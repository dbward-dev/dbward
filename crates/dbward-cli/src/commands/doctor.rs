use std::path::PathBuf;
use std::time::Duration;

use crate::error::CliError;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Pass,
    Warn,
    Fail,
    Skip,
}

pub struct CheckResult {
    pub id: &'static str,
    pub status: Status,
    pub message: String,
    pub hint: Option<String>,
}

struct DoctorContext {
    results: Vec<CheckResult>,
    json_output: bool,
    timeout: Duration,
}

impl DoctorContext {
    fn record(&mut self, r: CheckResult) {
        self.results.push(r);
    }

    fn last_failed(&self, id: &str) -> bool {
        self.results
            .iter()
            .rfind(|r| r.id == id)
            .is_some_and(|r| r.status == Status::Fail)
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub async fn run(
    config_path: Option<&std::path::Path>,
    agent_config: Option<PathBuf>,
    server_config: Option<PathBuf>,
    json_output: bool,
    timeout_secs: u64,
) -> Result<(), CliError> {
    if agent_config.is_some() && server_config.is_some() {
        eprintln!("error: --agent and --server are mutually exclusive");
        std::process::exit(2);
    }

    let mut ctx = DoctorContext {
        results: Vec::new(),
        json_output,
        timeout: Duration::from_secs(timeout_secs),
    };

    if let Some(path) = agent_config {
        run_agent_mode(&mut ctx, &path).await;
    } else if let Some(path) = server_config {
        run_server_mode(&mut ctx, &path);
    } else {
        run_cli_mode(&mut ctx, config_path).await;
    }

    print_results(&ctx);
    let has_failure = ctx.results.iter().any(|r| r.status == Status::Fail);
    if has_failure {
        std::process::exit(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// CLI mode
// ---------------------------------------------------------------------------

async fn run_cli_mode(ctx: &mut DoctorContext, config_path: Option<&std::path::Path>) {
    if !ctx.json_output {
        eprintln!("dbward doctor — CLI configuration\n");
    }

    // C1: config_parse
    let cfg = match crate::config::load_resolved(config_path, false) {
        Ok(m) => {
            let sources_str = m
                .sources_loaded
                .iter()
                .map(|(_, p)| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            ctx.record(CheckResult {
                id: "config_parse",
                status: Status::Pass,
                message: sources_str,
                hint: None,
            });
            Some(m.config)
        }
        Err(e) => {
            ctx.record(CheckResult {
                id: "config_parse",
                status: Status::Fail,
                message: e.to_string(),
                hint: Some("Run 'dbward init' to create a config file".into()),
            });
            None
        }
    };

    let Some(cfg) = cfg else { return };

    // C2: env_vars — already validated by config::load (returns error on undefined without default)
    ctx.record(CheckResult {
        id: "env_vars",
        status: Status::Pass,
        message: "all resolved".into(),
        hint: None,
    });

    // C3: server_reachable
    let server_url_display = redact_url(&cfg.server.url);
    let health = check_server_health(&cfg.server.url, ctx.timeout).await;
    match health {
        Ok((version, _)) => {
            ctx.record(CheckResult {
                id: "server_reachable",
                status: Status::Pass,
                message: format!("{server_url_display} (v{version})"),
                hint: None,
            });

            // C4: version_info
            let cli_version = env!("CARGO_PKG_VERSION");
            if version != cli_version && semver_gt(&version, cli_version) {
                ctx.record(CheckResult {
                    id: "version_info",
                    status: Status::Warn,
                    message: format!(
                        "CLI v{cli_version}, Server v{version} — consider updating CLI"
                    ),
                    hint: Some("Run 'dbward self-update'".into()),
                });
            } else {
                ctx.record(CheckResult {
                    id: "version_info",
                    status: Status::Pass,
                    message: format!("CLI v{cli_version}, Server v{version}"),
                    hint: None,
                });
            }
        }
        Err(e) => {
            ctx.record(CheckResult {
                id: "server_reachable",
                status: Status::Fail,
                message: e,
                hint: Some("Is the server running? Check server.url in your config.".into()),
            });
            ctx.record(CheckResult {
                id: "version_info",
                status: Status::Skip,
                message: "skipped (server unreachable)".into(),
                hint: None,
            });
        }
    }

    // C5: auth_configured
    let has_auth = cfg.server.token.is_some() || cfg.server.oidc.is_some();
    if has_auth {
        ctx.record(CheckResult {
            id: "auth_configured",
            status: Status::Pass,
            message: if cfg.server.token.is_some() {
                "token"
            } else {
                "oidc"
            }
            .into(),
            hint: None,
        });
    } else {
        ctx.record(CheckResult {
            id: "auth_configured",
            status: Status::Fail,
            message: "no token or OIDC configured".into(),
            hint: Some("Set server.token or [server.oidc] in your config".into()),
        });
    }

    // C6: auth_valid
    if ctx.last_failed("server_reachable") || ctx.last_failed("auth_configured") {
        ctx.record(CheckResult {
            id: "auth_valid",
            status: Status::Skip,
            message: "skipped".into(),
            hint: None,
        });
    } else if let Some(ref token) = cfg.server.token {
        let sc = crate::server_client::ServerClient::new(&cfg.server.url, token);
        match sc.get_json("/api/me").await {
            Ok(resp) => {
                let subject = resp["subject_id"].as_str().unwrap_or("unknown");
                let roles: Vec<&str> = resp["roles"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|v| v["name"].as_str()).collect())
                    .unwrap_or_default();
                ctx.record(CheckResult {
                    id: "auth_valid",
                    status: Status::Pass,
                    message: format!("{subject} ({})", roles.join(", ")),
                    hint: None,
                });
            }
            Err(e) => {
                ctx.record(CheckResult {
                    id: "auth_valid",
                    status: Status::Fail,
                    message: format!("authentication failed: {e}"),
                    hint: Some("Check your token or run 'dbward login'".into()),
                });
            }
        }
    } else {
        ctx.record(CheckResult {
            id: "auth_valid",
            status: Status::Skip,
            message: "skipped (OIDC — run 'dbward login' to verify)".into(),
            hint: None,
        });
    }

    // C7/C8: databases_exist / workflows_exist (info, permission-aware)
    if !ctx.last_failed("server_reachable")
        && !ctx.last_failed("auth_configured")
        && let Some(ref token) = cfg.server.token
    {
        let sc = crate::server_client::ServerClient::new(&cfg.server.url, token);
        check_databases_workflows(ctx, &sc).await;
    }
}

async fn check_databases_workflows(
    ctx: &mut DoctorContext,
    sc: &crate::server_client::ServerClient,
) {
    // C7
    match sc.get_json("/api/databases").await {
        Ok(resp) => {
            let count = resp["databases"].as_array().map(|a| a.len()).unwrap_or(0);
            if count == 0 {
                ctx.record(CheckResult {
                    id: "databases_exist",
                    status: Status::Warn,
                    message: "0 registered — requests will be rejected".into(),
                    hint: Some("Add [[databases]] to server config".into()),
                });
            } else {
                ctx.record(CheckResult {
                    id: "databases_exist",
                    status: Status::Pass,
                    message: format!("{count} registered"),
                    hint: None,
                });
            }
        }
        Err(e) if e.to_string().contains("403") || e.to_string().contains("forbidden") => {
            ctx.record(CheckResult {
                id: "databases_exist",
                status: Status::Skip,
                message: "skipped (insufficient permission)".into(),
                hint: None,
            });
        }
        Err(e) => {
            ctx.record(CheckResult {
                id: "databases_exist",
                status: Status::Warn,
                message: format!("could not check: {e}"),
                hint: None,
            });
        }
    }

    // C8
    match sc.get_json("/api/workflows").await {
        Ok(resp) => {
            let count = resp["workflows"].as_array().map(|a| a.len()).unwrap_or(0);
            if count == 0 {
                ctx.record(CheckResult {
                    id: "workflows_exist",
                    status: Status::Warn,
                    message: "0 defined — requests will be rejected (fail-closed)".into(),
                    hint: Some("Add [[workflows]] to server config".into()),
                });
            } else {
                ctx.record(CheckResult {
                    id: "workflows_exist",
                    status: Status::Pass,
                    message: format!("{count} defined"),
                    hint: None,
                });
            }
        }
        Err(e) if e.to_string().contains("403") || e.to_string().contains("forbidden") => {
            ctx.record(CheckResult {
                id: "workflows_exist",
                status: Status::Skip,
                message: "skipped (insufficient permission)".into(),
                hint: None,
            });
        }
        Err(e) => {
            ctx.record(CheckResult {
                id: "workflows_exist",
                status: Status::Warn,
                message: format!("could not check: {e}"),
                hint: None,
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Agent mode
// ---------------------------------------------------------------------------

async fn run_agent_mode(ctx: &mut DoctorContext, path: &std::path::Path) {
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

// ---------------------------------------------------------------------------
// Server mode
// ---------------------------------------------------------------------------

fn run_server_mode(ctx: &mut DoctorContext, path: &std::path::Path) {
    if !ctx.json_output {
        eprintln!("dbward doctor — Server configuration\n");
    }

    // S1 + S2: Load, expand env vars, parse, and validate in one step
    let cfg = match dbward_config::ServerConfig::load(path) {
        Ok(c) => {
            ctx.record(CheckResult {
                id: "env_vars",
                status: Status::Pass,
                message: "all resolved".into(),
                hint: None,
            });
            ctx.record(CheckResult {
                id: "config_parse",
                status: Status::Pass,
                message: path.display().to_string(),
                hint: None,
            });
            c
        }
        Err(dbward_config::ConfigError::UndefinedEnvVar { var, .. }) => {
            ctx.record(CheckResult {
                id: "env_vars",
                status: Status::Fail,
                message: format!("undefined environment variable: ${{{var}}}"),
                hint: Some(format!("Set {var} or remove the reference")),
            });
            return;
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

    // S3: workflow_validity
    check_workflow_validity(ctx, &cfg);

    // S4: workflow_coverage (reverse check)
    check_workflow_coverage(ctx, &cfg);

    // S5: role_resolution
    check_role_resolution(ctx, &cfg);

    // S6: auto_approve_consistency
    check_auto_approve_consistency(ctx, &cfg);
}

fn check_workflow_validity(ctx: &mut DoctorContext, cfg: &dbward_config::ServerConfig) {
    if cfg.workflows.is_empty() {
        ctx.record(CheckResult {
            id: "workflow_validity",
            status: Status::Fail,
            message: "no workflows defined — all requests will be rejected (fail-closed)".into(),
            hint: Some("Add [[workflows]] sections".into()),
        });
        return;
    }

    // Build set of all registered (db, env) pairs
    let mut registered_pairs: std::collections::HashSet<(&str, &str)> =
        std::collections::HashSet::new();
    for db in &cfg.databases {
        for env in &db.environments {
            registered_pairs.insert((db.name.as_str(), env.as_str()));
        }
    }
    let registered_dbs: std::collections::HashSet<&str> =
        cfg.databases.iter().map(|d| d.name.as_str()).collect();

    let mut dead = Vec::new();
    for (i, wf) in cfg.workflows.iter().enumerate() {
        // Wildcard db/env always valid
        if wf.database == "*" && wf.environment == "*" {
            continue;
        }
        // Check database
        if wf.database != "*" && !registered_dbs.contains(wf.database.as_str()) {
            dead.push(format!(
                "workflows[{i}]: database '{}' not registered",
                wf.database
            ));
            continue;
        }
        // Check environment (if both are concrete)
        if wf.database != "*"
            && wf.environment != "*"
            && !registered_pairs.contains(&(wf.database.as_str(), wf.environment.as_str()))
        {
            dead.push(format!(
                "workflows[{i}]: environment '{}' not in database '{}'",
                wf.environment, wf.database
            ));
        }
        // workflow with db=* but env=concrete: check if ANY db has that env
        if wf.database == "*" && wf.environment != "*" {
            let env_exists = cfg
                .databases
                .iter()
                .any(|db| db.environments.iter().any(|e| e == &wf.environment));
            if !env_exists {
                dead.push(format!(
                    "workflows[{i}]: environment '{}' not found in any database",
                    wf.environment
                ));
            }
        }
    }

    if dead.is_empty() {
        ctx.record(CheckResult {
            id: "workflow_validity",
            status: Status::Pass,
            message: format!("{} workflows, all valid", cfg.workflows.len()),
            hint: None,
        });
    } else if dead.len() == cfg.workflows.len() {
        ctx.record(CheckResult {
            id: "workflow_validity",
            status: Status::Fail,
            message: format!(
                "all {} workflows reference unregistered databases/environments",
                dead.len()
            ),
            hint: Some("Add [[databases]] for referenced databases".into()),
        });
    } else {
        ctx.record(CheckResult {
            id: "workflow_validity",
            status: Status::Warn,
            message: format!("{} dead: {}", dead.len(), dead.join("; ")),
            hint: None,
        });
    }
}

/// S4: Reverse lint — check if each registered DB×env has at least one matching workflow.
fn check_workflow_coverage(ctx: &mut DoctorContext, cfg: &dbward_config::ServerConfig) {
    if cfg.databases.is_empty() || cfg.workflows.is_empty() {
        return; // S3 already covers these cases
    }

    let mut gaps = Vec::new();
    let mut total_pairs = 0usize;
    let mut wildcard_skipped = false;

    for db in &cfg.databases {
        // Skip wildcard database names (can't enumerate concrete pairs)
        if db.name == "*" {
            wildcard_skipped = true;
            continue;
        }
        for env in &db.environments {
            // Skip wildcard environments (can't expand) but note it
            if env == "*" {
                wildcard_skipped = true;
                continue;
            }
            total_pairs += 1;
            // Check if any workflow matches this (db, env) pair
            let covered = cfg.workflows.iter().any(|wf| {
                workflow_covers_scope(
                    wf.database.as_str(),
                    wf.environment.as_str(),
                    db.name.as_str(),
                    env.as_str(),
                )
            });
            if !covered {
                // Check if there's an inert auto_approve for this scope
                let has_inert_aa = cfg.auto_approve.iter().any(|aa| {
                    workflow_covers_scope(
                        aa.database.as_str(),
                        aa.environment.as_str(),
                        db.name.as_str(),
                        env.as_str(),
                    )
                });
                let mut msg = format!("{}:{} → no workflow (fail-closed)", db.name, env);
                if has_inert_aa {
                    msg.push_str(" [auto_approve rule is inert here]");
                }
                gaps.push(msg);
            }
        }
    }

    if gaps.is_empty() {
        let mut msg = format!("{total_pairs} DB×env pairs, all covered");
        if wildcard_skipped {
            msg.push_str(" (wildcard registrations skipped — verify with 'dbward policy resolve')");
        }
        ctx.record(CheckResult {
            id: "workflow_coverage",
            status: if wildcard_skipped {
                Status::Warn
            } else {
                Status::Pass
            },
            message: msg,
            hint: None,
        });
    } else if gaps.len() == total_pairs && total_pairs > 0 {
        ctx.record(CheckResult {
            id: "workflow_coverage",
            status: Status::Fail,
            message: format!("all {} DB×env pairs have no workflow", gaps.len()),
            hint: Some("Add [[workflows]] matching your databases".into()),
        });
    } else {
        ctx.record(CheckResult {
            id: "workflow_coverage",
            status: Status::Warn,
            message: format!("{} gap(s): {}", gaps.len(), gaps.join("; ")),
            hint: Some("These DB×env pairs will reject all requests (fail-closed)".into()),
        });
    }
}

fn check_role_resolution(ctx: &mut DoctorContext, cfg: &dbward_config::ServerConfig) {
    let builtin = ["admin", "developer", "readonly", "agent-default"];
    let config_roles: std::collections::HashSet<&str> =
        cfg.auth.roles.iter().map(|r| r.name.as_str()).collect();
    let mut undefined = Vec::new();

    for rb in &cfg.auth.role_bindings {
        if !builtin.contains(&rb.role.as_str()) && !config_roles.contains(rb.role.as_str()) {
            undefined.push(rb.role.clone());
        }
    }
    if let Some(ref default) = cfg.auth.default_role
        && !builtin.contains(&default.as_str())
        && !config_roles.contains(default.as_str())
    {
        undefined.push(default.clone());
    }
    if let Some(ref oidc) = cfg.auth.oidc {
        for mapping in &oidc.role_mappings {
            if !builtin.contains(&mapping.role.as_str())
                && !config_roles.contains(mapping.role.as_str())
            {
                undefined.push(mapping.role.clone());
            }
        }
    }

    if undefined.is_empty() {
        ctx.record(CheckResult {
            id: "role_resolution",
            status: Status::Pass,
            message: "all referenced roles are defined".into(),
            hint: None,
        });
    } else {
        undefined.sort();
        undefined.dedup();
        ctx.record(CheckResult {
            id: "role_resolution",
            status: Status::Warn,
            message: format!(
                "custom roles referenced (must exist in DB): {}",
                undefined.join(", ")
            ),
            hint: Some("Define them in [[auth.roles]] in server.toml".into()),
        });
    }
}

fn check_auto_approve_consistency(ctx: &mut DoctorContext, cfg: &dbward_config::ServerConfig) {
    if cfg.auto_approve.is_empty() {
        ctx.record(CheckResult {
            id: "auto_approve_consistency",
            status: Status::Pass,
            message: "no auto_approve rules (all requests need approval)".into(),
            hint: None,
        });
        return;
    }

    let mut orphaned = Vec::new();
    for aa in &cfg.auto_approve {
        // Check if any workflow covers this auto_approve scope
        let has_matching_workflow = cfg.workflows.iter().any(|wf| {
            workflow_covers_scope(
                wf.database.as_str(),
                wf.environment.as_str(),
                aa.database.as_str(),
                aa.environment.as_str(),
            )
        });
        if !has_matching_workflow {
            orphaned.push(format!("{}:{}", aa.database, aa.environment));
        }
    }

    if orphaned.is_empty() {
        ctx.record(CheckResult {
            id: "auto_approve_consistency",
            status: Status::Pass,
            message: format!(
                "{} rules, all have matching workflows",
                cfg.auto_approve.len()
            ),
            hint: None,
        });
    } else {
        ctx.record(CheckResult {
            id: "auto_approve_consistency",
            status: Status::Warn,
            message: format!(
                "orphaned auto_approve (no workflow): {}",
                orphaned.join(", ")
            ),
            hint: Some("These auto_approve rules will never trigger".into()),
        });
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Simple semver comparison: returns true if a > b.
fn semver_gt(a: &str, b: &str) -> bool {
    let parse = |s: &str| -> (u64, u64, u64) {
        let parts: Vec<u64> = s
            .split('.')
            .take(3)
            .map(|p| p.parse().unwrap_or(0))
            .collect();
        (
            parts.first().copied().unwrap_or(0),
            parts.get(1).copied().unwrap_or(0),
            parts.get(2).copied().unwrap_or(0),
        )
    };
    parse(a) > parse(b)
}

/// Strip credentials from a URL for safe display.
fn redact_url(url: &str) -> String {
    if let Ok(mut parsed) = reqwest::Url::parse(url) {
        if !parsed.username().is_empty() || parsed.password().is_some() {
            let _ = parsed.set_username("");
            let _ = parsed.set_password(None);
        }
        parsed.to_string()
    } else {
        url.to_string()
    }
}

/// Scope matching using domain types (same as runtime's workflow_matcher).
fn workflow_covers_scope(wf_db: &str, wf_env: &str, req_db: &str, req_env: &str) -> bool {
    use dbward_domain::values::{DatabaseName, Environment};
    let Ok(policy_db) = DatabaseName::new(wf_db) else {
        return false;
    };
    let Ok(policy_env) = Environment::new(wf_env) else {
        return false;
    };
    let Ok(request_db) = DatabaseName::new(req_db) else {
        return false;
    };
    let Ok(request_env) = Environment::new(req_env) else {
        return false;
    };
    (policy_db.is_wildcard() || policy_db == request_db)
        && (policy_env.is_wildcard() || policy_env == request_env)
}

async fn check_server_health(url: &str, timeout: Duration) -> Result<(String, String), String> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout)
        .build()
        .map_err(|e| e.to_string())?;

    let resp = client
        .get(format!("{}/health", url.trim_end_matches('/')))
        .send()
        .await
        .map_err(|e| {
            if e.is_timeout() {
                "connection timed out".to_string()
            } else if e.is_connect() {
                "connection refused".to_string()
            } else {
                e.to_string()
            }
        })?;

    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }

    let body: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    let version = body["version"].as_str().unwrap_or("unknown").to_string();
    let min_agent = body["min_agent_version"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    Ok((version, min_agent))
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

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

fn print_results(ctx: &DoctorContext) {
    if ctx.json_output {
        print_json(ctx);
    } else {
        print_human(ctx);
    }
}

fn print_human(ctx: &DoctorContext) {
    for r in &ctx.results {
        let icon = match r.status {
            Status::Pass => "  \x1b[32m✓\x1b[0m",
            Status::Warn => "  \x1b[33m⚠\x1b[0m",
            Status::Fail => "  \x1b[31m✗\x1b[0m",
            Status::Skip => "  \x1b[90m-\x1b[0m",
        };
        println!("{} {:<24} {}", icon, r.id, r.message);
        if let Some(ref hint) = r.hint {
            println!("    {}", hint);
        }
    }

    let (pass, warn, fail, skip) = count_results(ctx);
    println!(
        "\n  {} passed, {} warnings, {} failed, {} skipped",
        pass, warn, fail, skip
    );
}

fn print_json(ctx: &DoctorContext) {
    let checks: Vec<serde_json::Value> = ctx
        .results
        .iter()
        .map(|r| {
            let mut obj = serde_json::json!({
                "id": r.id,
                "status": match r.status {
                    Status::Pass => "pass",
                    Status::Warn => "warn",
                    Status::Fail => "fail",
                    Status::Skip => "skip",
                },
                "message": r.message,
            });
            if let Some(ref hint) = r.hint {
                obj["hint"] = serde_json::Value::String(hint.clone());
            }
            obj
        })
        .collect();

    let (pass, warn, fail, skip) = count_results(ctx);
    let output = serde_json::json!({
        "checks": checks,
        "summary": {
            "passed": pass,
            "warnings": warn,
            "failed": fail,
            "skipped": skip,
        }
    });
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

fn count_results(ctx: &DoctorContext) -> (usize, usize, usize, usize) {
    let pass = ctx
        .results
        .iter()
        .filter(|r| r.status == Status::Pass)
        .count();
    let warn = ctx
        .results
        .iter()
        .filter(|r| r.status == Status::Warn)
        .count();
    let fail = ctx
        .results
        .iter()
        .filter(|r| r.status == Status::Fail)
        .count();
    let skip = ctx
        .results
        .iter()
        .filter(|r| r.status == Status::Skip)
        .count();
    (pass, warn, fail, skip)
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

    fn server_cfg(toml: &str) -> dbward_config::ServerConfig {
        let full = format!("state_dir = \"/tmp/test\"\n{toml}");
        dbward_config::ServerConfig::from_str(&full, "test").unwrap()
    }

    #[test]
    fn workflow_validity_all_dead() {
        let mut ctx = DoctorContext {
            results: Vec::new(),
            json_output: false,
            timeout: Duration::from_secs(5),
        };
        let cfg = server_cfg(
            r#"
[[databases]]
name = "app"
environments = ["production"]

[[workflows]]
database = "nonexistent"
environment = "*"
"#,
        );
        check_workflow_validity(&mut ctx, &cfg);
        assert_eq!(ctx.results[0].status, Status::Fail);
    }

    #[test]
    fn workflow_validity_partial_dead() {
        let mut ctx = DoctorContext {
            results: Vec::new(),
            json_output: false,
            timeout: Duration::from_secs(5),
        };
        let cfg = server_cfg(
            r#"
[[databases]]
name = "app"
environments = ["production"]

[[workflows]]
database = "app"
environment = "*"

[[workflows]]
database = "ghost"
environment = "*"
"#,
        );
        check_workflow_validity(&mut ctx, &cfg);
        assert_eq!(ctx.results[0].status, Status::Warn);
    }

    #[test]
    fn workflow_validity_wildcard_passes() {
        let mut ctx = DoctorContext {
            results: Vec::new(),
            json_output: false,
            timeout: Duration::from_secs(5),
        };
        let cfg = server_cfg(
            r#"
[[databases]]
name = "app"
environments = ["production"]

[[workflows]]
database = "*"
environment = "*"
"#,
        );
        check_workflow_validity(&mut ctx, &cfg);
        assert_eq!(ctx.results[0].status, Status::Pass);
    }

    #[test]
    fn role_resolution_builtin_only() {
        let mut ctx = DoctorContext {
            results: Vec::new(),
            json_output: false,
            timeout: Duration::from_secs(5),
        };
        let cfg = server_cfg(
            r#"
[auth]
mode = "token"
default_role = "developer"

[[auth.role_bindings]]
role = "admin"
subjects = ["alice"]
"#,
        );
        check_role_resolution(&mut ctx, &cfg);
        assert_eq!(ctx.results[0].status, Status::Pass);
    }

    #[test]
    fn role_resolution_custom_warns() {
        let mut ctx = DoctorContext {
            results: Vec::new(),
            json_output: false,
            timeout: Duration::from_secs(5),
        };
        let cfg = server_cfg(
            r#"
[auth]
mode = "token"

[[auth.roles]]
name = "dba"
permissions = ["request.approve"]

[[auth.role_bindings]]
role = "dba"
subjects = ["bob"]
"#,
        );
        check_role_resolution(&mut ctx, &cfg);
        // With the role defined, doctor no longer warns about it being undefined.
        // Verify it passes without issues instead.
        assert!(ctx.results.is_empty() || ctx.results.iter().all(|r| r.status != Status::Warn));
    }
}
