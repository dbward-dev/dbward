use super::*;

pub(super) async fn run_cli_mode(ctx: &mut DoctorContext, config_path: Option<&std::path::Path>) {
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

    // C2.5: server_url_scheme — TLS transport safety
    let has_oidc = cfg.server.oidc.is_some();
    let allow_insecure = cfg.server.allow_insecure.unwrap_or(false);
    match dbward_config::transport::check_transport_security(
        &cfg.server.url,
        allow_insecure,
        has_oidc,
    ) {
        Ok(()) => {
            let label = if cfg.server.url.to_ascii_lowercase().starts_with("https") {
                "HTTPS"
            } else {
                "HTTP (local/internal)"
            };
            ctx.record(CheckResult {
                id: "server_url_scheme",
                status: Status::Pass,
                message: label.into(),
                hint: None,
            });
        }
        Err(e) => {
            ctx.record(CheckResult {
                id: "server_url_scheme",
                status: Status::Fail,
                message: e.to_string(),
                hint: Some("Production requires HTTPS. See docs/deployment/tls.md".into()),
            });
        }
    }

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
                hint: Some("Is the server running? Verify server.url in your config and check that the process is up.".into()),
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
                    hint: Some("Check your token or run 'dbward login'. On first server start, tokens are in /data/admin-token and /data/developer-token.".into()),
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
