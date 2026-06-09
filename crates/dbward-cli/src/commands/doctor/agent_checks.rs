use super::*;

pub(super) async fn run_agent_mode(ctx: &mut DoctorContext, path: &std::path::Path) {
    if !ctx.json_output {
        eprintln!("dbward doctor — Agent configuration\n");
    }

    // A1: config_parse
    let raw_content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            ctx.record(CheckResult {
                id: "config_parse",
                status: Status::Fail,
                message: format!("{}: {e}", path.display()),
                hint: None,
            });
            return;
        }
    };

    // A2: env_vars_audit — scan raw content for ${VAR} and check env
    let env_issues = audit_agent_env_vars(&raw_content);
    if env_issues.is_empty() {
        ctx.record(CheckResult {
            id: "env_vars_audit",
            status: Status::Pass,
            message: "all resolved".into(),
            hint: None,
        });
    } else {
        let has_undefined = env_issues.iter().any(|(_, defined, _)| !defined);
        let status = if has_undefined {
            Status::Fail
        } else {
            Status::Warn
        };
        let msgs: Vec<String> = env_issues
            .iter()
            .map(|(name, defined, _)| {
                if !defined {
                    format!("{name} is undefined")
                } else {
                    format!("{name} is empty")
                }
            })
            .collect();
        ctx.record(CheckResult {
            id: "env_vars_audit",
            status,
            message: msgs.join("; "),
            hint: Some("Set these environment variables before starting the agent".into()),
        });
    }

    // Try to parse config (strict: undefined env vars = error)
    let cfg = match dbward_config::AgentConfig::from_str(&raw_content, &path.display().to_string())
    {
        Ok(c) => {
            ctx.record(CheckResult {
                id: "config_parse",
                status: Status::Pass,
                message: path.display().to_string(),
                hint: None,
            });
            c
        }
        Err(e) => {
            ctx.record(CheckResult {
                id: "config_parse",
                status: Status::Fail,
                message: e.to_string(),
                hint: None,
            });
            return;
        }
    };

    // A3: server_reachable
    let server_url = redact_url(&cfg.server.url);
    let server_ok = match check_server_health(&cfg.server.url, ctx.timeout).await {
        Ok((version, _)) => {
            ctx.record(CheckResult {
                id: "server_reachable",
                status: Status::Pass,
                message: format!("{server_url} (v{version})"),
                hint: None,
            });
            true
        }
        Err(e) => {
            ctx.record(CheckResult {
                id: "server_reachable",
                status: Status::Fail,
                message: format!("{server_url} — {e}"),
                hint: Some("Is the server running?".into()),
            });
            false
        }
    };

    // A4: agent_token_valid
    if !server_ok {
        ctx.record(CheckResult {
            id: "agent_token_valid",
            status: Status::Skip,
            message: "skipped (server unreachable)".into(),
            hint: None,
        });
    } else {
        match check_agent_token(&cfg.server.url, &cfg.server.agent_token, ctx.timeout).await {
            Ok(()) => {
                ctx.record(CheckResult {
                    id: "agent_token_valid",
                    status: Status::Pass,
                    message: "valid agent token".into(),
                    hint: None,
                });
            }
            Err(e) => {
                ctx.record(CheckResult {
                    id: "agent_token_valid",
                    status: Status::Fail,
                    message: e,
                    hint: Some("Check server.agent_token in agent config".into()),
                });
            }
        }
    }

    // A5: db_url_scheme
    let mut all_valid = true;
    let mut invalid_urls = Vec::new();
    for (db_name, envs) in &cfg.databases {
        for (env_name, entry) in envs {
            if !entry.url.starts_with("postgres://")
                && !entry.url.starts_with("postgresql://")
                && !entry.url.starts_with("mysql://")
            {
                all_valid = false;
                invalid_urls.push(format!("{db_name}.{env_name}"));
            }
        }
    }
    if all_valid {
        let count = cfg.databases.values().map(|e| e.len()).sum::<usize>();
        ctx.record(CheckResult {
            id: "db_url_scheme",
            status: Status::Pass,
            message: format!("{count} valid"),
            hint: None,
        });
    } else {
        ctx.record(CheckResult {
            id: "db_url_scheme",
            status: Status::Fail,
            message: format!("unsupported scheme: {}", invalid_urls.join(", ")),
            hint: Some("URLs must start with postgres://, postgresql://, or mysql://".into()),
        });
    }
}

async fn check_agent_token(url: &str, token: &str, timeout: Duration) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout)
        .build()
        .map_err(|e| e.to_string())?;

    let resp = client
        .get(format!("{}/api/public-key", url.trim_end_matches('/')))
        .bearer_auth(token)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    match resp.status().as_u16() {
        200 => Ok(()),
        401 => Err("invalid token (401 Unauthorized)".into()),
        403 => Err("token is not an agent token (403 Forbidden — user tokens cannot access /api/public-key)".into()),
        s => Err(format!("unexpected HTTP {s}")),
    }
}

/// Scan raw TOML for `${VAR}` patterns and check if they're defined/non-empty.
/// Returns (var_name, is_defined, is_sensitive) tuples for problematic vars.
fn audit_agent_env_vars(raw: &str) -> Vec<(String, bool, bool)> {
    let re = regex::Regex::new(dbward_config::ENV_VAR_PATTERN).expect("BUG: invalid regex");
    let mut issues = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for caps in re.captures_iter(raw) {
        let name = caps[1].to_string();
        let has_default = caps.get(2).is_some();
        if has_default || !seen.insert(name.clone()) {
            continue;
        }
        let is_sensitive = name.to_lowercase().contains("token")
            || name.to_lowercase().contains("password")
            || name.to_lowercase().contains("secret");

        match std::env::var(&name) {
            Err(_) => issues.push((name, false, is_sensitive)),
            Ok(v) if v.is_empty() && is_sensitive => issues.push((name, true, is_sensitive)),
            _ => {}
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_agent_env_vars_detects_undefined() {
        unsafe { std::env::remove_var("DOCTOR_TEST_MISSING") };
        let raw = r#"agent_token = "${DOCTOR_TEST_MISSING}""#;
        let issues = audit_agent_env_vars(raw);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].0, "DOCTOR_TEST_MISSING");
        assert!(!issues[0].1); // not defined
    }

    #[test]
    fn audit_agent_env_vars_warns_empty_sensitive() {
        unsafe { std::env::set_var("DOCTOR_TEST_EMPTY_TOKEN", "") };
        let raw = r#"agent_token = "${DOCTOR_TEST_EMPTY_TOKEN}""#;
        let issues = audit_agent_env_vars(raw);
        assert_eq!(issues.len(), 1);
        assert!(issues[0].1); // defined but empty
        assert!(issues[0].2); // sensitive
        unsafe { std::env::remove_var("DOCTOR_TEST_EMPTY_TOKEN") };
    }

    #[test]
    fn audit_agent_env_vars_ok_when_set() {
        unsafe { std::env::set_var("DOCTOR_TEST_GOOD", "value") };
        let raw = r#"url = "${DOCTOR_TEST_GOOD}""#;
        let issues = audit_agent_env_vars(raw);
        assert!(issues.is_empty());
        unsafe { std::env::remove_var("DOCTOR_TEST_GOOD") };
    }
}
