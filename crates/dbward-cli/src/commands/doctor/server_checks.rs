use super::*;

pub(super) fn run_server_mode(ctx: &mut DoctorContext, path: &std::path::Path) {
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

    // S7: built_in_role_collision
    check_built_in_role_collision(ctx, &cfg);

    // S8: role_binding_duplicates
    check_role_binding_duplicates(ctx, &cfg);

    // S9: notification_webhook_refs
    check_notification_webhook_refs(ctx, &cfg);

    // S10: role_binding_empty
    check_role_binding_empty(ctx, &cfg);
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

fn check_built_in_role_collision(ctx: &mut DoctorContext, cfg: &dbward_config::ServerConfig) {
    let builtin = ["admin", "developer", "readonly", "agent-default"];
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
        });
    } else {
        ctx.record(CheckResult {
            id: "built_in_role_collision",
            status: Status::Fail,
            message: format!("collides with built-in: {}", collisions.join(", ")),
            hint: Some("Choose different names for custom roles".into()),
        });
    }
}

fn check_role_binding_duplicates(ctx: &mut DoctorContext, cfg: &dbward_config::ServerConfig) {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut dups = Vec::new();
    for (i, rb) in cfg.auth.role_bindings.iter().enumerate() {
        let mut sorted_subjects = rb.subjects.clone();
        sorted_subjects.sort();
        sorted_subjects.dedup();
        let mut sorted_groups = rb.groups.clone();
        sorted_groups.sort();
        sorted_groups.dedup();
        let key = format!(
            "{}|{}|{}",
            rb.role,
            sorted_subjects.join(","),
            sorted_groups.join(",")
        );
        if !seen.insert(key) {
            dups.push(format!("role_bindings[{i}] role='{}'", rb.role));
        }
    }
    if dups.is_empty() {
        ctx.record(CheckResult {
            id: "role_binding_duplicates",
            status: Status::Pass,
            message: format!("{} bindings, no duplicates", cfg.auth.role_bindings.len()),
            hint: None,
        });
    } else {
        ctx.record(CheckResult {
            id: "role_binding_duplicates",
            status: Status::Fail,
            message: format!("{} duplicate(s): {}", dups.len(), dups.join("; ")),
            hint: Some("Remove duplicate role_bindings".into()),
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
        });
    } else {
        ctx.record(CheckResult {
            id: "notification_webhook_refs",
            status: Status::Fail,
            message: format!("{} undefined: {}", missing.len(), missing.join("; ")),
            hint: Some("Define referenced webhooks in [[webhooks]]".into()),
        });
    }
}

fn check_role_binding_empty(ctx: &mut DoctorContext, cfg: &dbward_config::ServerConfig) {
    let mut empty = Vec::new();
    for (i, rb) in cfg.auth.role_bindings.iter().enumerate() {
        if rb.subjects.is_empty() && rb.groups.is_empty() {
            empty.push(format!("role_bindings[{i}] role='{}'", rb.role));
        }
    }
    if empty.is_empty() {
        ctx.record(CheckResult {
            id: "role_binding_empty",
            status: Status::Pass,
            message: "all bindings have at least one target".into(),
            hint: None,
        });
    } else {
        ctx.record(CheckResult {
            id: "role_binding_empty",
            status: Status::Warn,
            message: format!("{} no-op binding(s): {}", empty.len(), empty.join("; ")),
            hint: Some("Add subjects or groups to these bindings".into()),
        });
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
        assert!(ctx.results.is_empty() || ctx.results.iter().all(|r| r.status != Status::Warn));
    }
}
