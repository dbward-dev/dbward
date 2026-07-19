use super::*;

pub(super) async fn run_server_mode(ctx: &mut DoctorContext, path: &std::path::Path) {
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
                details: vec![],
            });
            ctx.record(CheckResult {
                id: "config_parse",
                status: Status::Pass,
                message: path.display().to_string(),
                hint: None,
                details: vec![],
            });
            c
        }
        Err(dbward_config::ConfigError::UndefinedEnvVar { var, .. }) => {
            ctx.record(CheckResult {
                id: "env_vars",
                status: Status::Fail,
                message: format!("undefined environment variable: ${{{var}}}"),
                hint: Some(format!("Set {var} or remove the reference")),
                details: vec![],
            });
            return;
        }
        Err(e) => {
            ctx.record(CheckResult {
                id: "config_parse",
                status: Status::Fail,
                message: e.to_string(),
                hint: None,
                details: vec![],
            });
            return;
        }
    };

    // S3: workflow_validity
    check_workflow_validity(ctx, &cfg);

    // S3b: workflow_step_validity (approver logic checks)
    check_workflow_step_validity(ctx, &cfg);

    // S4: workflow_coverage (reverse check)
    check_workflow_coverage(ctx, &cfg);

    // S5: role_resolution
    check_role_resolution(ctx, &cfg);

    // S7: built_in_role_collision
    check_built_in_role_collision(ctx, &cfg);

    // S9: notification_webhook_refs
    check_notification_webhook_refs(ctx, &cfg);

    // S11: slack connectivity
    check_slack(ctx, &cfg).await;
}

fn check_workflow_validity(ctx: &mut DoctorContext, cfg: &dbward_config::ServerConfig) {
    if cfg.workflows.is_empty() {
        ctx.record(CheckResult {
            id: "workflow_validity",
            status: Status::Fail,
            message: "no workflows defined — all requests will be rejected (fail-closed)".into(),
            hint: Some("Add [[workflows]] sections".into()),
            details: vec![],
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
            details: vec![],
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
            details: vec![],
        });
    } else {
        ctx.record(CheckResult {
            id: "workflow_validity",
            status: Status::Warn,
            message: format!("{} dead: {}", dead.len(), dead.join("; ")),
            hint: None,
            details: vec![],
        });
    }
}

/// S3b: Validate workflow step logic (approver selectors, deadlock detection).
fn check_workflow_step_validity(ctx: &mut DoctorContext, cfg: &dbward_config::ServerConfig) {
    use dbward_domain::policies::workflow::{ApproverGroup, WorkflowStep, WorkflowStepMode};
    use dbward_domain::services::workflow_validator;
    use dbward_domain::values::Selector;

    for (wf_idx, wf) in cfg.workflows.iter().enumerate() {
        if wf.steps.is_empty() {
            continue; // auto-approve workflow, nothing to validate
        }

        // Parse steps from serde_json::Value → WorkflowStep
        let mut steps = Vec::new();
        let mut parse_error = false;
        for (step_idx, step_val) in wf.steps.iter().enumerate() {
            let mode = match step_val
                .get("mode")
                .and_then(|m| m.as_str())
                .unwrap_or("all")
            {
                "any" => WorkflowStepMode::Any,
                "all" => WorkflowStepMode::All,
                other => {
                    ctx.record(CheckResult {
                        id: "workflow_step_validity",
                        status: Status::Fail,
                        message: format!(
                            "workflows[{wf_idx}].steps[{step_idx}]: unknown mode '{other}'"
                        ),
                        hint: None,
                        details: vec![],
                    });
                    parse_error = true;
                    continue;
                }
            };
            let approvers: Vec<ApproverGroup> = step_val
                .get("approvers")
                .and_then(|a| a.as_array())
                .map(|arr| {
                    let mut parsed = Vec::new();
                    for (a_idx, a) in arr.iter().enumerate() {
                        let raw_min = a.get("min").and_then(|m| m.as_u64()).unwrap_or(1);
                        if raw_min > u32::MAX as u64 {
                            ctx.record(CheckResult {
                                id: "workflow_step_validity",
                                status: Status::Fail,
                                message: format!(
                                    "workflows[{wf_idx}].steps[{step_idx}].approvers[{a_idx}]: min={raw_min} exceeds maximum ({})",
                                    u32::MAX
                                ),
                                hint: None,
                                details: vec![],
                            });
                            parse_error = true;
                            continue;
                        }
                        let min = raw_min as u32;
                        let selector = if let Some(r) = a.get("role").and_then(|v| v.as_str()) {
                            Selector::Role(r.to_string())
                        } else if let Some(g) = a.get("group").and_then(|v| v.as_str()) {
                            Selector::Group(g.to_string())
                        } else if let Some(u) = a.get("user").and_then(|v| v.as_str()) {
                            Selector::User(u.to_string())
                        } else {
                            ctx.record(CheckResult {
                                id: "workflow_step_validity",
                                status: Status::Fail,
                                message: format!(
                                    "workflows[{wf_idx}].steps[{step_idx}].approvers[{a_idx}]: no valid selector"
                                ),
                                hint: Some(
                                    "Each approver must have 'role', 'group', or 'user' key".into(),
                                ),
                                details: vec![],
                            });
                            parse_error = true;
                            continue;
                        };
                        parsed.push(ApproverGroup { selector, min });
                    }
                    parsed
                })
                .unwrap_or_default();
            steps.push(WorkflowStep { approvers, mode });
        }

        if parse_error && steps.is_empty() {
            continue;
        }

        // Skip logical validation if any parse error occurred for this workflow
        if parse_error {
            continue;
        }

        let issues =
            workflow_validator::validate_steps(&steps, wf.allow_same_approver_across_steps);
        for issue in issues {
            let status = match issue.severity {
                workflow_validator::Severity::Error => Status::Fail,
                workflow_validator::Severity::Warning => Status::Warn,
            };
            ctx.record(CheckResult {
                id: "workflow_step_validity",
                status,
                message: format!("workflows[{wf_idx}]: {}", issue.message),
                hint: None,
                details: vec![],
            });
        }
    }

    // Emit pass if no workflow_step_validity results were recorded
    if !ctx.results.iter().any(|r| r.id == "workflow_step_validity") {
        let non_auto = cfg.workflows.iter().filter(|w| !w.steps.is_empty()).count();
        if non_auto > 0 {
            ctx.record(CheckResult {
                id: "workflow_step_validity",
                status: Status::Pass,
                message: format!("{non_auto} workflows with steps, all valid"),
                hint: None,
                details: vec![],
            });
        }
    }
}

/// S4: Reverse lint — check if each registered DB×env has at least one matching workflow.
/// Produces a coverage table showing which workflow covers each (db, env) pair.
fn check_workflow_coverage(ctx: &mut DoctorContext, cfg: &dbward_config::ServerConfig) {
    use crate::display::{display_width, sanitize_table_cell, truncate_table_cell};

    if cfg.databases.is_empty() || cfg.workflows.is_empty() {
        return; // S3 already covers these cases
    }

    const COL_MAX: usize = 20;

    struct CoverageRow {
        database: String,
        environment: String,
        workflow: String,
        auto_approve: String,
    }

    let mut rows: Vec<CoverageRow> = Vec::new();
    let mut gap_count = 0usize;
    let mut total_pairs = 0usize;
    let mut wildcard_skipped = false;

    for db in &cfg.databases {
        if db.name == "*" {
            wildcard_skipped = true;
            continue;
        }
        for env in &db.environments {
            if env == "*" {
                wildcard_skipped = true;
                continue;
            }
            total_pairs += 1;

            // Find best matching workflow using specificity score (same as runtime).
            // Higher specificity wins: exact env = +4, exact db = +2.
            // Note: operations axis is intentionally ignored (see S4 design doc).
            let matched = cfg
                .workflows
                .iter()
                .filter(|wf| {
                    workflow_covers_scope(
                        wf.database.as_str(),
                        wf.environment.as_str(),
                        db.name.as_str(),
                        env.as_str(),
                    )
                })
                .max_by_key(|wf| {
                    let mut score = 0u8;
                    if wf.environment != "*" && wf.environment == *env {
                        score += 4;
                    }
                    if wf.database != "*" && wf.database == db.name {
                        score += 2;
                    }
                    score
                });

            let (workflow_label, auto_approve_label) = match matched {
                Some(wf) => {
                    let wf_label = format!("({},{})", wf.database, wf.environment);
                    let aa_label = match &wf.auto_approve {
                        Some(dbward_config::server::AutoApproveDef::Always) => "always".to_string(),
                        Some(dbward_config::server::AutoApproveDef::RiskBased { risk, .. }) => {
                            format!("risk_based({risk})")
                        }
                        None => "—".to_string(),
                    };
                    (wf_label, aa_label)
                }
                None => {
                    gap_count += 1;
                    ("✗ NO COVERAGE".to_string(), "—".to_string())
                }
            };

            rows.push(CoverageRow {
                database: sanitize_table_cell(&db.name),
                environment: sanitize_table_cell(env),
                workflow: workflow_label,
                auto_approve: auto_approve_label,
            });
        }
    }

    // Build table lines
    let details = if !rows.is_empty() {
        let headers = ["Database", "Environment", "Workflow", "Auto-Approve"];

        // Compute column widths (capped at COL_MAX)
        let mut widths: [usize; 4] = [
            display_width(headers[0]),
            display_width(headers[1]),
            display_width(headers[2]),
            display_width(headers[3]),
        ];
        for r in &rows {
            widths[0] = widths[0].max(display_width(&r.database)).min(COL_MAX);
            widths[1] = widths[1].max(display_width(&r.environment)).min(COL_MAX);
            widths[2] = widths[2].max(display_width(&r.workflow)).min(COL_MAX);
            widths[3] = widths[3].max(display_width(&r.auto_approve)).min(COL_MAX);
        }

        let mut lines = Vec::new();
        // Header
        lines.push(format!(
            "{}  {}  {}  {}",
            pad_col(headers[0], widths[0]),
            pad_col(headers[1], widths[1]),
            pad_col(headers[2], widths[2]),
            pad_col(headers[3], widths[3]),
        ));
        // Separator
        lines.push(format!(
            "{}  {}  {}  {}",
            "-".repeat(widths[0]),
            "-".repeat(widths[1]),
            "-".repeat(widths[2]),
            "-".repeat(widths[3]),
        ));
        // Data rows
        for r in &rows {
            lines.push(format!(
                "{}  {}  {}  {}",
                pad_col(&truncate_table_cell(&r.database, COL_MAX), widths[0]),
                pad_col(&truncate_table_cell(&r.environment, COL_MAX), widths[1]),
                pad_col(&truncate_table_cell(&r.workflow, COL_MAX), widths[2]),
                pad_col(&truncate_table_cell(&r.auto_approve, COL_MAX), widths[3]),
            ));
        }
        lines
    } else {
        vec![]
    };

    // Record result
    if gap_count == 0 {
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
            details,
        });
    } else if gap_count == total_pairs && total_pairs > 0 {
        ctx.record(CheckResult {
            id: "workflow_coverage",
            status: Status::Fail,
            message: format!("all {} DB×env pairs have no workflow", gap_count),
            hint: Some("Add [[workflows]] matching your databases".into()),
            details,
        });
    } else {
        ctx.record(CheckResult {
            id: "workflow_coverage",
            status: Status::Warn,
            message: format!("{gap_count} of {total_pairs} DB×env pairs have no workflow"),
            hint: Some("Uncovered pairs will reject all requests (fail-closed)".into()),
            details,
        });
    }
}

/// Pad a string to the given width (left-aligned).
fn pad_col(value: &str, width: usize) -> String {
    use crate::display::display_width;
    let padding = width.saturating_sub(display_width(value));
    format!("{value}{}", " ".repeat(padding))
}

fn check_role_resolution(ctx: &mut DoctorContext, cfg: &dbward_config::ServerConfig) {
    let builtin = [
        "admin",
        "requester",
        "approver",
        "operator",
        "agent-default",
    ];
    let config_roles: std::collections::HashSet<&str> =
        cfg.auth.roles.iter().map(|r| r.name.as_str()).collect();
    let mut undefined = Vec::new();

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
            details: vec![],
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
            details: vec![],
        });
    }
}

fn check_built_in_role_collision(ctx: &mut DoctorContext, cfg: &dbward_config::ServerConfig) {
    let builtin = [
        "admin",
        "requester",
        "approver",
        "operator",
        "agent-default",
    ];
    let mut collisions = Vec::new();
    for r in &cfg.auth.roles {
        if builtin.contains(&r.name.as_str()) {
            collisions.push(r.name.clone());
        }
    }
    if collisions.is_empty() {
        ctx.record(CheckResult {
            id: "built_in_role_collision",
            status: Status::Pass,
            message: "no collisions with built-in roles".into(),
            hint: None,
            details: vec![],
        });
    } else {
        ctx.record(CheckResult {
            id: "built_in_role_collision",
            status: Status::Fail,
            message: format!("collides with built-in: {}", collisions.join(", ")),
            hint: Some("Choose different names for custom roles".into()),
            details: vec![],
        });
    }
}

fn check_notification_webhook_refs(ctx: &mut DoctorContext, cfg: &dbward_config::ServerConfig) {
    let webhook_ids: std::collections::HashSet<&str> =
        cfg.webhooks.iter().map(|w| w.id.as_str()).collect();
    let mut missing = Vec::new();
    for (i, np) in cfg.notification_policies.iter().enumerate() {
        for wh_id in &np.webhooks {
            if !webhook_ids.contains(wh_id.as_str()) {
                missing.push(format!("notification_policies[{i}].webhooks: '{wh_id}'"));
            }
        }
    }
    if missing.is_empty() {
        ctx.record(CheckResult {
            id: "notification_webhook_refs",
            status: Status::Pass,
            message: "all webhook references valid".into(),
            hint: None,
            details: vec![],
        });
    } else {
        ctx.record(CheckResult {
            id: "notification_webhook_refs",
            status: Status::Fail,
            message: format!("{} undefined: {}", missing.len(), missing.join("; ")),
            hint: Some("Define referenced webhooks in [[webhooks]]".into()),
            details: vec![],
        });
    }
}

async fn check_slack(ctx: &mut DoctorContext, cfg: &dbward_config::ServerConfig) {
    let Some(ref slack) = cfg.slack else {
        return;
    };

    // S-slack1: config fields non-empty
    if slack.bot_token.is_empty() || slack.signing_secret.is_empty() {
        let missing = if slack.bot_token.is_empty() && slack.signing_secret.is_empty() {
            "bot_token and signing_secret are empty"
        } else if slack.bot_token.is_empty() {
            "bot_token is empty"
        } else {
            "signing_secret is empty"
        };
        ctx.record(CheckResult {
            id: "slack_config",
            status: Status::Fail,
            message: missing.into(),
            hint: Some("Set values in [slack] section of server.toml".into()),
            details: vec![],
        });
        return;
    }
    ctx.record(CheckResult {
        id: "slack_config",
        status: Status::Pass,
        message: "bot_token + signing_secret present".into(),
        hint: None,
        details: vec![],
    });

    // S-slack2: bot_token format
    if !slack.bot_token.starts_with("xoxb-") || slack.bot_token.len() < 10 {
        ctx.record(CheckResult {
            id: "slack_bot_token",
            status: Status::Fail,
            message: "invalid prefix (expected xoxb-)".into(),
            hint: Some("Copy the Bot User OAuth Token from Slack App settings".into()),
            details: vec![],
        });
        return;
    }
    ctx.record(CheckResult {
        id: "slack_bot_token",
        status: Status::Pass,
        message: "xoxb-... (valid prefix)".into(),
        hint: None,
        details: vec![],
    });

    // S-slack3: signing_secret format (32 lowercase alphanumeric chars)
    let valid_secret = slack.signing_secret.len() == 32
        && slack
            .signing_secret
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    if !valid_secret {
        ctx.record(CheckResult {
            id: "slack_signing_secret",
            status: Status::Fail,
            message: "invalid format (expected 32 alphanumeric chars)".into(),
            hint: Some("Copy from Basic Information → App Credentials → Signing Secret".into()),
            details: vec![],
        });
        return;
    }
    ctx.record(CheckResult {
        id: "slack_signing_secret",
        status: Status::Pass,
        message: "32-char alphanumeric".into(),
        hint: None,
        details: vec![],
    });

    // S-slack4: auth.test API call
    let client = match reqwest::Client::builder()
        .timeout(ctx.timeout)
        .connect_timeout(ctx.timeout)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            ctx.record(CheckResult {
                id: "slack_auth_test",
                status: Status::Fail,
                message: format!("failed to create HTTP client: {e}"),
                hint: None,
                details: vec![],
            });
            return;
        }
    };

    let auth_resp = client
        .post("https://slack.com/api/auth.test")
        .bearer_auth(&slack.bot_token)
        .send()
        .await;

    match auth_resp {
        Err(e) => {
            let msg = if e.is_timeout() {
                "connection timed out".to_string()
            } else if e.is_connect() {
                "connection refused".to_string()
            } else {
                e.to_string()
            };
            ctx.record(CheckResult {
                id: "slack_auth_test",
                status: Status::Fail,
                message: format!("connection failed ({msg})"),
                hint: Some("Check network/firewall settings".into()),
                details: vec![],
            });
            return;
        }
        Ok(resp) => match resp.json::<serde_json::Value>().await {
            Err(e) => {
                ctx.record(CheckResult {
                    id: "slack_auth_test",
                    status: Status::Fail,
                    message: format!("invalid response: {e}"),
                    hint: None,
                    details: vec![],
                });
                return;
            }
            Ok(body) => {
                if body["ok"].as_bool() != Some(true) {
                    let error = body["error"].as_str().unwrap_or("unknown");
                    ctx.record(CheckResult {
                        id: "slack_auth_test",
                        status: Status::Fail,
                        message: format!("Slack API returned: {error}"),
                        hint: Some("Verify bot_token is correct and app is installed".into()),
                        details: vec![],
                    });
                    return;
                }
                let team = body["team"].as_str().unwrap_or("?");
                let team_id = body["team_id"].as_str().unwrap_or("?");
                let bot = body["user"].as_str().unwrap_or("?");
                let bot_id = body["user_id"].as_str().unwrap_or("?");
                ctx.record(CheckResult {
                    id: "slack_auth_test",
                    status: Status::Pass,
                    message: format!("team={team} ({team_id}), bot={bot} ({bot_id})"),
                    hint: None,
                    details: vec![],
                });
            }
        },
    }

    // S-slack5: channel existence + bot membership
    let channel_id = slack.channel.as_str();

    if channel_id.is_empty() {
        ctx.record(CheckResult {
            id: "slack_channel",
            status: Status::Skip,
            message: "not configured".into(),
            hint: None,
            details: vec![],
        });
    } else if channel_id.starts_with('#') {
        ctx.record(CheckResult {
            id: "slack_channel",
            status: Status::Skip,
            message: format!("{channel_id}: use channel ID (C.../G...) for full validation"),
            hint: None,
            details: vec![],
        });
    } else if !(channel_id.starts_with('C') || channel_id.starts_with('G'))
        || channel_id.len() < 2
        || !channel_id[1..].chars().all(|c| c.is_ascii_alphanumeric())
    {
        ctx.record(CheckResult {
            id: "slack_channel",
            status: Status::Fail,
            message: format!("{channel_id}: invalid channel ID format"),
            hint: Some(
                "Channel IDs start with C (public) or G (private) followed by alphanumeric".into(),
            ),
            details: vec![],
        });
    } else {
        let conv_resp = client
            .get("https://slack.com/api/conversations.info")
            .bearer_auth(&slack.bot_token)
            .query(&[("channel", channel_id)])
            .send()
            .await;

        match conv_resp {
            Err(_) => {
                ctx.record(CheckResult {
                    id: "slack_channel",
                    status: Status::Fail,
                    message: format!("{channel_id}: connection failed"),
                    hint: None,
                    details: vec![],
                });
            }
            Ok(resp) => match resp.json::<serde_json::Value>().await {
                Err(_) => {
                    ctx.record(CheckResult {
                        id: "slack_channel",
                        status: Status::Fail,
                        message: format!("{channel_id}: invalid response"),
                        hint: None,
                        details: vec![],
                    });
                }
                Ok(body) => {
                    if body["ok"].as_bool() != Some(true) {
                        let error = body["error"].as_str().unwrap_or("unknown");
                        ctx.record(CheckResult {
                            id: "slack_channel",
                            status: Status::Fail,
                            message: format!("{channel_id}: {error}"),
                            hint: Some("Verify the channel ID exists".into()),
                            details: vec![],
                        });
                    } else {
                        let is_member = body["channel"]["is_member"].as_bool().unwrap_or(false);
                        if is_member {
                            ctx.record(CheckResult {
                                id: "slack_channel",
                                status: Status::Pass,
                                message: format!("{channel_id} — bot is member"),
                                hint: None,
                                details: vec![],
                            });
                        } else {
                            ctx.record(CheckResult {
                                id: "slack_channel",
                                status: Status::Warn,
                                message: format!("{channel_id} — bot not a member"),
                                hint: Some("Run: /invite @dbward in the channel".into()),
                                details: vec![],
                            });
                        }
                    }
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

[workflows.auto_approve]
mode = "always"
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

[workflows.auto_approve]
mode = "always"

[[workflows]]
database = "ghost"
environment = "*"

[workflows.auto_approve]
mode = "always"
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

[workflows.auto_approve]
mode = "always"
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
default_role = "requester"

[[auth.groups]]
name = "admins"
roles = ["admin"]
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

[[auth.roles]]
name = "dba"
permissions = ["request.view"]

[[auth.groups]]
name = "dba-team"
roles = ["dba"]
"#,
        );
        check_role_resolution(&mut ctx, &cfg);
        // With the role defined, doctor no longer warns about it being undefined.
        assert!(ctx.results.is_empty() || ctx.results.iter().all(|r| r.status != Status::Warn));
    }

    #[tokio::test]
    async fn slack_checks_skip_when_unconfigured() {
        let mut ctx = DoctorContext {
            results: Vec::new(),
            json_output: false,
            timeout: Duration::from_secs(5),
        };
        let cfg = server_cfg("");
        check_slack(&mut ctx, &cfg).await;
        // No results when [slack] is absent
        assert!(ctx.results.is_empty());
    }

    #[tokio::test]
    async fn slack_bot_token_format_validation() {
        let mut ctx = DoctorContext {
            results: Vec::new(),
            json_output: false,
            timeout: Duration::from_secs(5),
        };
        let cfg = server_cfg(
            r#"
[slack]
bot_token = "invalid-token"
signing_secret = "abcdef1234567890abcdef1234567890"
"#,
        );
        check_slack(&mut ctx, &cfg).await;
        assert!(
            ctx.results
                .iter()
                .any(|r| r.id == "slack_bot_token" && r.status == Status::Fail)
        );
    }

    #[tokio::test]
    async fn slack_signing_secret_format_validation() {
        let mut ctx = DoctorContext {
            results: Vec::new(),
            json_output: false,
            timeout: Duration::from_secs(5),
        };
        let cfg = server_cfg(
            r#"
[slack]
bot_token = "xoxb-1234567890-abcdefgh"
signing_secret = "too_short"
"#,
        );
        check_slack(&mut ctx, &cfg).await;
        assert!(
            ctx.results
                .iter()
                .any(|r| r.id == "slack_signing_secret" && r.status == Status::Fail)
        );
    }

    #[tokio::test]
    async fn slack_format_checks_pass_with_valid_config() {
        let mut ctx = DoctorContext {
            results: Vec::new(),
            json_output: false,
            timeout: Duration::from_secs(5),
        };
        let cfg = server_cfg(
            r##"
[slack]
bot_token = "xoxb-1234567890-abcdefgh"
signing_secret = "abcdef1234567890abcdef1234567890"
channel = "#general"
"##,
        );
        check_slack(&mut ctx, &cfg).await;
        // signing_secret passes (auth_test will fail due to no network)
        assert!(
            ctx.results
                .iter()
                .any(|r| r.id == "slack_signing_secret" && r.status == Status::Pass)
        );
    }

    #[tokio::test]
    async fn slack_signing_secret_rejects_uppercase() {
        let mut ctx = DoctorContext {
            results: Vec::new(),
            json_output: false,
            timeout: Duration::from_secs(5),
        };
        let cfg = server_cfg(
            r#"
[slack]
bot_token = "xoxb-1234567890-abcdefgh"
signing_secret = "ABCDEF1234567890abcdef1234567890"
"#,
        );
        check_slack(&mut ctx, &cfg).await;
        assert!(
            ctx.results
                .iter()
                .any(|r| r.id == "slack_signing_secret" && r.status == Status::Fail)
        );
    }

    /// Verifies that #name channels produce Status::Skip. Requires network (auth.test must pass first).
    #[tokio::test]
    #[ignore]
    async fn slack_channel_name_produces_skip() {
        let mut ctx = DoctorContext {
            results: Vec::new(),
            json_output: false,
            timeout: Duration::from_secs(5),
        };
        // This test requires a real bot_token + signing_secret to pass auth.test
        let cfg = server_cfg(
            r##"
[slack]
bot_token = "xoxb-REAL-TOKEN-HERE"
signing_secret = "real32charsigningsecretgoeshere00"
channel = "#nonexistent"
"##,
        );
        check_slack(&mut ctx, &cfg).await;
        assert!(
            ctx.results
                .iter()
                .any(|r| r.id == "slack_channel" && r.status == Status::Skip)
        );
    }

    // --- DOC-W2: workflow coverage table tests ---

    #[test]
    fn workflow_coverage_all_covered_wildcard() {
        let mut ctx = DoctorContext {
            results: Vec::new(),
            json_output: false,
            timeout: Duration::from_secs(5),
        };
        let cfg = server_cfg(
            r#"
[[databases]]
name = "app"
environments = ["production", "staging"]

[[workflows]]
database = "*"
environment = "*"

[workflows.auto_approve]
mode = "always"
"#,
        );
        check_workflow_coverage(&mut ctx, &cfg);
        let r = ctx
            .results
            .iter()
            .find(|r| r.id == "workflow_coverage")
            .unwrap();
        assert_eq!(r.status, Status::Pass);
        assert!(r.message.contains("2 DB×env pairs, all covered"));
        // Table should have header + separator + 2 data rows = 4 lines
        assert_eq!(r.details.len(), 4);
        assert!(r.details[2].contains("app"));
        assert!(r.details[2].contains("production"));
        assert!(r.details[2].contains("always"));
    }

    #[test]
    fn workflow_coverage_partial_gap() {
        let mut ctx = DoctorContext {
            results: Vec::new(),
            json_output: false,
            timeout: Duration::from_secs(5),
        };
        let cfg = server_cfg(
            r#"
[[databases]]
name = "app"
environments = ["production", "staging"]

[[workflows]]
database = "*"
environment = "production"

[workflows.auto_approve]
mode = "risk_based"
risk = "low"

[[workflows.steps]]
type = "approval"
[[workflows.steps.approvers]]
role = "dba"
min = 1
"#,
        );
        check_workflow_coverage(&mut ctx, &cfg);
        let r = ctx
            .results
            .iter()
            .find(|r| r.id == "workflow_coverage")
            .unwrap();
        assert_eq!(r.status, Status::Warn);
        assert!(r.message.contains("1 of 2"));
        // Table should show one covered, one gap
        assert_eq!(r.details.len(), 4); // header + sep + 2 rows
        let prod_row = &r.details[2];
        assert!(prod_row.contains("production"));
        assert!(prod_row.contains("risk_based(low)"));
        let staging_row = &r.details[3];
        assert!(staging_row.contains("staging"));
        assert!(staging_row.contains("NO COVERAGE"));
    }

    #[test]
    fn workflow_coverage_all_gaps() {
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
database = "other"
environment = "*"

[workflows.auto_approve]
mode = "always"
"#,
        );
        check_workflow_coverage(&mut ctx, &cfg);
        let r = ctx
            .results
            .iter()
            .find(|r| r.id == "workflow_coverage")
            .unwrap();
        assert_eq!(r.status, Status::Fail);
        assert!(r.message.contains("all 1 DB×env pairs have no workflow"));
        assert!(r.details[2].contains("NO COVERAGE"));
    }

    #[test]
    fn workflow_coverage_most_specific_wins() {
        let mut ctx = DoctorContext {
            results: Vec::new(),
            json_output: false,
            timeout: Duration::from_secs(5),
        };
        // More specific workflow (app,production) should be picked over wildcard (*,*)
        let cfg = server_cfg(
            r#"
[[databases]]
name = "app"
environments = ["production"]

[[workflows]]
database = "app"
environment = "production"

[[workflows.steps]]
type = "approval"
[[workflows.steps.approvers]]
role = "dba"
min = 1

[[workflows]]
database = "*"
environment = "*"

[workflows.auto_approve]
mode = "always"
"#,
        );
        check_workflow_coverage(&mut ctx, &cfg);
        let r = ctx
            .results
            .iter()
            .find(|r| r.id == "workflow_coverage")
            .unwrap();
        assert_eq!(r.status, Status::Pass);
        // Should match the more specific (app,production) not wildcard (*,*)
        let data_row = &r.details[2];
        assert!(data_row.contains("(app,production)"));
        // No auto_approve in first workflow
        assert!(data_row.contains("—"));
    }

    #[test]
    fn workflow_coverage_specificity_beats_definition_order() {
        let mut ctx = DoctorContext {
            results: Vec::new(),
            json_output: false,
            timeout: Duration::from_secs(5),
        };
        // Wildcard workflow is defined FIRST, but specific should still win
        let cfg = server_cfg(
            r#"
[[databases]]
name = "app"
environments = ["production"]

[[workflows]]
database = "*"
environment = "*"

[workflows.auto_approve]
mode = "always"

[[workflows]]
database = "app"
environment = "production"

[[workflows.steps]]
type = "approval"
[[workflows.steps.approvers]]
role = "dba"
min = 1
"#,
        );
        check_workflow_coverage(&mut ctx, &cfg);
        let r = ctx
            .results
            .iter()
            .find(|r| r.id == "workflow_coverage")
            .unwrap();
        assert_eq!(r.status, Status::Pass);
        // Specificity wins: (app,production) score=6 beats (*,*) score=0
        let data_row = &r.details[2];
        assert!(data_row.contains("(app,production)"));
        // The specific workflow has no auto_approve (needs approval)
        assert!(data_row.contains("—"));
    }

    #[test]
    fn workflow_coverage_wildcard_env_skipped() {
        let mut ctx = DoctorContext {
            results: Vec::new(),
            json_output: false,
            timeout: Duration::from_secs(5),
        };
        let cfg = server_cfg(
            r#"
[[databases]]
name = "app"
environments = ["production", "*"]

[[workflows]]
database = "*"
environment = "*"

[workflows.auto_approve]
mode = "always"
"#,
        );
        check_workflow_coverage(&mut ctx, &cfg);
        let r = ctx
            .results
            .iter()
            .find(|r| r.id == "workflow_coverage")
            .unwrap();
        // wildcard env skipped → status is Warn
        assert_eq!(r.status, Status::Warn);
        assert!(r.message.contains("wildcard"));
        // Only 1 concrete pair (production), wildcard skipped
        assert!(r.message.contains("1 DB×env pairs, all covered"));
    }
}
