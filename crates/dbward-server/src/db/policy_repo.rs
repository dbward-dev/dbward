use rusqlite::Connection;

// --- Approval policy evaluation ---

/// Unified approval policy decision.
pub struct ApprovalDecision {
    pub needs_approval: bool,
    pub workflow_id: Option<String>,
    pub workflow_snapshot_json: Option<String>,
    pub require_reason: bool,
}

/// Single entry point for approval policy evaluation.
/// Checks workflows table first, falls back to static PolicyConfig.
pub fn evaluate_approval_policy(
    conn: &Connection,
    policy: &crate::policy::PolicyConfig,
    database: &str,
    environment: &str,
    operation: &str,
    role: &str,
) -> ApprovalDecision {
    if let Some((wf_id, steps, require_reason)) =
        evaluate_workflow(conn, database, environment, operation)
    {
        let needs_approval = !steps.is_empty();
        let snapshot = serde_json::to_string(&steps).unwrap_or_else(|_| "[]".into());
        ApprovalDecision {
            needs_approval,
            workflow_id: Some(wf_id),
            workflow_snapshot_json: Some(snapshot),
            require_reason,
        }
    } else {
        let action = policy.evaluate(environment, operation, role);
        ApprovalDecision {
            needs_approval: action == "require_approval",
            workflow_id: None,
            workflow_snapshot_json: None,
            require_reason: false,
        }
    }
}

/// Evaluate workflow for a request.
pub fn evaluate_workflow(
    conn: &Connection,
    database: &str,
    environment: &str,
    operation: &str,
) -> Option<(String, Vec<crate::server_config::WorkflowStep>, bool)> {
    let candidates = [
        (database, environment),
        ("*", environment),
        (database, "*"),
        ("*", "*"),
    ];

    for (db_name, env_name) in candidates {
        let mut stmt = conn
            .prepare("SELECT id, operations_json, steps_json, require_reason FROM workflows WHERE database_name = ?1 AND environment = ?2 ORDER BY id ASC")
            .ok()?;
        let rows: Vec<(String, String, String, bool)> = stmt
            .query_map(rusqlite::params![db_name, env_name], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .ok()?
            .filter_map(|r| r.ok())
            .collect();

        let mut exact_match: Option<(String, Vec<crate::server_config::WorkflowStep>, bool)> = None;
        let mut catchall_match: Option<(String, Vec<crate::server_config::WorkflowStep>, bool)> =
            None;

        for (id, operations_json, steps_json, require_reason) in &rows {
            let operations: Vec<String> = serde_json::from_str(operations_json).unwrap_or_default();
            let steps: Vec<crate::server_config::WorkflowStep> =
                serde_json::from_str(steps_json).unwrap_or_default();
            if operations.is_empty() {
                if catchall_match.is_none() {
                    catchall_match = Some((id.clone(), steps, *require_reason));
                }
            } else if operations.iter().any(|op| op == operation) {
                if exact_match.is_none() {
                    exact_match = Some((id.clone(), steps, *require_reason));
                }
            }
        }

        if let Some(m) = exact_match.or(catchall_match) {
            return Some(m);
        }
    }

    None
}

// --- TOML sync ---

fn delete_stale_toml_records(
    conn: &Connection,
    table: &str,
    keep_ids: &[String],
) -> Result<(), rusqlite::Error> {
    if keep_ids.is_empty() {
        conn.execute(&format!("DELETE FROM {table} WHERE source = 'toml'"), [])?;
    } else {
        let placeholders: Vec<String> = (1..=keep_ids.len()).map(|i| format!("?{i}")).collect();
        let sql = format!(
            "DELETE FROM {table} WHERE source = 'toml' AND id NOT IN ({})",
            placeholders.join(",")
        );
        let params: Vec<&dyn rusqlite::types::ToSql> = keep_ids
            .iter()
            .map(|id| id as &dyn rusqlite::types::ToSql)
            .collect();
        conn.execute(&sql, params.as_slice())?;
    }
    Ok(())
}

pub fn sync_workflows(
    conn: &Connection,
    workflows: &[crate::server_config::WorkflowDef],
) -> Result<(), rusqlite::Error> {
    let now = chrono::Utc::now().to_rfc3339();
    let mut toml_ids: Vec<String> = Vec::new();
    for w in workflows {
        let mut sorted_ops = w.operations.clone();
        sorted_ops.sort();
        let ops_json = serde_json::to_string(&sorted_ops).unwrap_or_else(|_| "[]".into());
        let ops_tag = if sorted_ops.is_empty() {
            "*".to_string()
        } else {
            sorted_ops.join(",")
        };
        let id = format!("{}:{}:{}", w.database, w.environment, ops_tag);
        let steps_json = serde_json::to_string(&w.steps).unwrap_or_else(|_| "[]".into());
        conn.execute(
            "INSERT INTO workflows (id, database_name, environment, operations_json, steps_json, require_reason, source, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'toml', ?7, ?7)
             ON CONFLICT(database_name, environment, operations_json) DO UPDATE SET
               id = ?1, steps_json = ?5, require_reason = ?6, updated_at = ?7
             WHERE source = 'toml'",
            rusqlite::params![id, w.database, w.environment, ops_json, steps_json, w.require_reason, now],
        )?;
        toml_ids.push(id);
    }
    delete_stale_toml_records(conn, "workflows", &toml_ids)?;
    Ok(())
}

pub fn sync_execution_policies(
    conn: &Connection,
    policies: &[crate::server_config::ExecutionPolicyDef],
) -> Result<(), rusqlite::Error> {
    let now = chrono::Utc::now().to_rfc3339();
    let mut toml_ids: Vec<String> = Vec::new();
    for p in policies {
        let id = format!("{}:{}", p.database, p.environment);
        conn.execute(
            "INSERT INTO execution_policies (id, database_name, environment, max_executions, execution_window_secs, retry_on_failure, source, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'toml', ?7, ?7)
             ON CONFLICT(database_name, environment) DO UPDATE SET
               max_executions = ?4, execution_window_secs = ?5, retry_on_failure = ?6, updated_at = ?7
             WHERE source = 'toml'",
            rusqlite::params![id, p.database, p.environment, p.max_executions, p.execution_window_secs, p.retry_on_failure, now],
        )?;
        toml_ids.push(id);
    }
    delete_stale_toml_records(conn, "execution_policies", &toml_ids)?;
    Ok(())
}

pub fn sync_result_policies(
    conn: &Connection,
    policies: &[crate::server_config::ResultPolicyDef],
) -> Result<(), rusqlite::Error> {
    let now = chrono::Utc::now().to_rfc3339();
    let mut toml_ids: Vec<String> = Vec::new();
    for p in policies {
        let id = format!("{}:{}", p.database, p.environment);
        let config_json = p
            .storage_config
            .as_ref()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "{}".into());
        let access_json = serde_json::to_string(&p.access).unwrap_or_else(|_| "[]".into());
        conn.execute(
            "INSERT INTO result_policies (id, database_name, environment, delivery_mode, storage_config_json, access_json, source, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'toml', ?7, ?7)
             ON CONFLICT(database_name, environment) DO UPDATE SET
               delivery_mode = ?4, storage_config_json = ?5, access_json = ?6, updated_at = ?7
             WHERE source = 'toml'",
            rusqlite::params![id, p.database, p.environment, p.delivery_mode, config_json, access_json, now],
        )?;
        toml_ids.push(id);
    }
    delete_stale_toml_records(conn, "result_policies", &toml_ids)?;
    Ok(())
}

pub fn sync_notification_policies(
    conn: &Connection,
    policies: &[crate::server_config::NotificationPolicyDef],
) -> Result<(), rusqlite::Error> {
    let now = chrono::Utc::now().to_rfc3339();
    let mut toml_ids: Vec<String> = Vec::new();
    for p in policies {
        let id = format!("{}:{}", p.database, p.environment);
        let webhooks_json = serde_json::to_string(&p.webhooks).unwrap_or_else(|_| "[]".into());
        conn.execute(
            "INSERT INTO notification_policies (id, database_name, environment, webhooks_json, source, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, 'toml', ?5, ?5)
             ON CONFLICT(database_name, environment) DO UPDATE SET
               webhooks_json = ?4, updated_at = ?5
             WHERE source = 'toml'",
            rusqlite::params![id, p.database, p.environment, webhooks_json, now],
        )?;
        toml_ids.push(id);
    }
    delete_stale_toml_records(conn, "notification_policies", &toml_ids)?;
    Ok(())
}

// --- Policy lookups ---

pub fn get_execution_policy(
    conn: &Connection,
    database: &str,
    environment: &str,
) -> (u32, u64, bool) {
    let query = |db: &str, env: &str| -> Option<(u32, u64, bool)> {
        conn.query_row(
            "SELECT max_executions, execution_window_secs, retry_on_failure FROM execution_policies WHERE database_name = ?1 AND environment = ?2",
            rusqlite::params![db, env],
            |row| Ok((row.get(0)?, row.get(1)?, row.get::<_, bool>(2)?)),
        ).ok()
    };
    query(database, environment)
        .or_else(|| query("*", environment))
        .or_else(|| query(database, "*"))
        .or_else(|| query("*", "*"))
        .unwrap_or((1, 86400, false))
}

pub fn get_result_policy(
    conn: &Connection,
    database: &str,
    environment: &str,
) -> (String, Vec<String>) {
    let query = |db: &str, env: &str| -> Option<(String, String)> {
        conn.query_row(
            "SELECT delivery_mode, access_json FROM result_policies WHERE database_name = ?1 AND environment = ?2",
            rusqlite::params![db, env],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).ok()
    };
    let (mode, access_json) = query(database, environment)
        .or_else(|| query("*", environment))
        .or_else(|| query(database, "*"))
        .or_else(|| query("*", "*"))
        .unwrap_or(("direct".into(), r#"["requester","admin"]"#.into()));
    let access: Vec<String> = serde_json::from_str(&access_json).unwrap_or_default();
    (mode, access)
}

pub fn get_notification_webhooks(
    conn: &Connection,
    database: &str,
    environment: &str,
) -> Vec<crate::webhook::WebhookConfig> {
    let query = |db: &str, env: &str| -> Option<String> {
        conn.query_row(
            "SELECT webhooks_json FROM notification_policies WHERE database_name = ?1 AND environment = ?2",
            rusqlite::params![db, env],
            |row| row.get(0),
        ).ok()
    };
    let json = query(database, environment)
        .or_else(|| query("*", environment))
        .or_else(|| query(database, "*"))
        .or_else(|| query("*", "*"));
    match json {
        Some(j) => serde_json::from_str(&j).unwrap_or_default(),
        None => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    #[test]
    fn sync_workflows_only_deletes_toml_rows() {
        let conn = Connection::open_in_memory().unwrap();
        db::init(&conn).unwrap();

        conn.execute(
            "INSERT INTO workflows (id, database_name, environment, operations_json, steps_json, require_reason, source, created_at, updated_at)
             VALUES ('api-row', 'app', 'development', '[\"execute_query\"]', '[]', 0, 'api', 't1', 't1')",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO workflows (id, database_name, environment, operations_json, steps_json, require_reason, source, created_at, updated_at)
             VALUES ('stale-toml', 'legacy', 'development', '[\"execute_query\"]', '[]', 0, 'toml', 't1', 't1')",
            [],
        ).unwrap();

        sync_workflows(&conn, &[]).unwrap();

        let api_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM workflows WHERE id = 'api-row' AND source = 'api'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let stale_toml_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM workflows WHERE id = 'stale-toml'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(api_count, 1);
        assert_eq!(stale_toml_count, 0);
    }

    #[test]
    fn evaluate_workflow_prefers_more_specific_scope_before_wildcards() {
        let conn = Connection::open_in_memory().unwrap();
        db::init(&conn).unwrap();

        conn.execute(
            "INSERT INTO workflows (id, database_name, environment, operations_json, steps_json, require_reason, source, created_at, updated_at)
             VALUES ('app:production:*', 'app', 'production', '[]', '[]', 0, 'api', 't1', 't1')",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO workflows (id, database_name, environment, operations_json, steps_json, require_reason, source, created_at, updated_at)
             VALUES ('*:production:execute_query', '*', 'production', '[\"execute_query\"]', '[{\"type\":\"approval\",\"mode\":\"all\",\"approvers\":[{\"role\":\"admin\",\"min\":1}],\"require_distinct_actors\":true}]', 0, 'api', 't1', 't1')",
            [],
        ).unwrap();

        let (workflow_id, steps, require_reason) =
            evaluate_workflow(&conn, "app", "production", "execute_query").unwrap();
        assert_eq!(workflow_id, "app:production:*");
        assert!(steps.is_empty());
        assert!(!require_reason);
    }

    #[test]
    fn evaluate_approval_policy_falls_back_to_static_policy_without_workflow() {
        let conn = Connection::open_in_memory().unwrap();
        db::init(&conn).unwrap();

        let decision = evaluate_approval_policy(
            &conn,
            &crate::policy::PolicyConfig::default(),
            "app",
            "production",
            "execute_query",
            "developer",
        );

        assert!(decision.needs_approval);
        assert!(decision.workflow_id.is_none());
        assert!(decision.workflow_snapshot_json.is_none());
        assert!(!decision.require_reason);
    }
}
