use rusqlite::Connection;

// --- Approval policy evaluation ---

/// Unified approval policy decision.
#[derive(Debug)]
pub struct ApprovalDecision {
    pub needs_approval: bool,
    pub workflow_id: Option<String>,
    pub workflow_snapshot_json: Option<String>,
    pub require_reason: bool,
}

#[derive(Debug)]
pub enum PolicyEvalError {
    Database(rusqlite::Error),
    CorruptedConfig(String),
}

impl std::fmt::Display for PolicyEvalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Database(e) => write!(f, "database error while evaluating workflow: {e}"),
            Self::CorruptedConfig(msg) => write!(f, "corrupted workflow configuration: {msg}"),
        }
    }
}

impl std::error::Error for PolicyEvalError {}

impl From<rusqlite::Error> for PolicyEvalError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Database(e)
    }
}

/// Single entry point for approval policy evaluation.
/// Checks workflows table; if no workflow matches, auto-approves.
/// Returns Err on any infrastructure failure (fail-closed).
pub fn evaluate_approval_policy(
    conn: &Connection,
    database: &str,
    environment: &str,
    operation: &str,
) -> Result<ApprovalDecision, PolicyEvalError> {
    match evaluate_workflow(conn, database, environment, operation)? {
        Some((wf_id, steps, require_reason)) => {
            let needs_approval = !steps.is_empty();
            let snapshot = serde_json::to_string(&steps).map_err(|e| {
                PolicyEvalError::CorruptedConfig(format!(
                    "failed to serialize workflow steps for {wf_id}: {e}"
                ))
            })?;
            Ok(ApprovalDecision {
                needs_approval,
                workflow_id: Some(wf_id),
                workflow_snapshot_json: Some(snapshot),
                require_reason,
            })
        }
        None => Ok(ApprovalDecision {
            needs_approval: false,
            workflow_id: None,
            workflow_snapshot_json: None,
            require_reason: false,
        }),
    }
}

/// Evaluate workflow for a request.
pub fn evaluate_workflow(
    conn: &Connection,
    database: &str,
    environment: &str,
    operation: &str,
) -> Result<Option<(String, Vec<crate::server_config::WorkflowStep>, bool)>, PolicyEvalError> {
    let candidates = [
        (database, environment),
        ("*", environment),
        (database, "*"),
        ("*", "*"),
    ];

    for (db_name, env_name) in candidates {
        let mut stmt = conn
            .prepare("SELECT id, operations_json, steps_json, require_reason FROM workflows WHERE database_name = ?1 AND environment = ?2 ORDER BY id ASC")?;
        let rows = stmt.query_map(rusqlite::params![db_name, env_name], |row| {
            Ok(WorkflowRow {
                id: row.get(0)?,
                operations_json: row.get(1)?,
                steps_json: row.get(2)?,
                require_reason: row.get(3)?,
            })
        })?;
        let rows: Vec<WorkflowRow> = rows.collect::<Result<Vec<_>, _>>()?;

        if let Some(m) = match_workflow(&rows, operation)? {
            return Ok(Some(m));
        }
    }

    Ok(None)
}

/// A row from the workflows table (used for matching).
pub struct WorkflowRow {
    pub id: String,
    pub operations_json: String,
    pub steps_json: String,
    pub require_reason: bool,
}

/// Pure matching logic: given a list of workflow rows, find the best match for an operation.
/// Prefers exact operation match over catchall (empty operations list).
pub fn match_workflow(
    rows: &[WorkflowRow],
    operation: &str,
) -> Result<Option<(String, Vec<crate::server_config::WorkflowStep>, bool)>, PolicyEvalError> {
    let mut exact_match: Option<(String, Vec<crate::server_config::WorkflowStep>, bool)> = None;
    let mut catchall_match: Option<(String, Vec<crate::server_config::WorkflowStep>, bool)> = None;

    for row in rows {
        let operations: Vec<String> = serde_json::from_str(&row.operations_json).map_err(|e| {
            PolicyEvalError::CorruptedConfig(format!(
                "invalid operations_json in workflow '{}': {e}", row.id
            ))
        })?;
        let steps: Vec<crate::server_config::WorkflowStep> =
            serde_json::from_str(&row.steps_json).map_err(|e| {
                PolicyEvalError::CorruptedConfig(format!(
                    "invalid steps_json in workflow '{}': {e}", row.id
                ))
            })?;
        if operations.is_empty() {
            if catchall_match.is_none() {
                catchall_match = Some((row.id.clone(), steps, row.require_reason));
            }
        } else if operations.iter().any(|op| op == operation) && exact_match.is_none() {
            exact_match = Some((row.id.clone(), steps, row.require_reason));
        }
    }

    Ok(exact_match.or(catchall_match))
}

// --- TOML sync ---

// --- TOML sync ---

/// Validate all workflow JSON integrity on startup. Fails if any are corrupted.
pub fn validate_workflows(conn: &Connection) -> Result<(), PolicyEvalError> {
    let mut stmt = conn.prepare("SELECT id, operations_json, steps_json FROM workflows")?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    for row in rows {
        let (id, ops_json, steps_json) = row?;
        let _: Vec<String> = serde_json::from_str(&ops_json).map_err(|e| {
            PolicyEvalError::CorruptedConfig(format!(
                "invalid operations_json in workflow '{id}': {e}"
            ))
        })?;
        let _: Vec<crate::server_config::WorkflowStep> = serde_json::from_str(&steps_json)
            .map_err(|e| {
                PolicyEvalError::CorruptedConfig(format!(
                    "invalid steps_json in workflow '{id}': {e}"
                ))
            })?;
    }
    Ok(())
}

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
        let steps_json = serde_json::to_string(&w.steps)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        conn.execute(
            "INSERT INTO workflows (id, database_name, environment, operations_json, steps_json, require_reason, allow_same_approver_across_steps, allow_self_approve, source, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'toml', ?9, ?9)
             ON CONFLICT(database_name, environment, operations_json) DO UPDATE SET
               id = ?1, steps_json = ?5, require_reason = ?6, allow_same_approver_across_steps = ?7, allow_self_approve = ?8, updated_at = ?9
             WHERE source = 'toml'",
            rusqlite::params![id, w.database, w.environment, ops_json, steps_json, w.require_reason, w.allow_same_approver_across_steps, w.allow_self_approve, now],
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

pub fn sync_access_policies(
    conn: &Connection,
    policies: &[crate::server_config::AccessPolicyDef],
) -> Result<(), rusqlite::Error> {
    let now = chrono::Utc::now().to_rfc3339();
    let mut toml_ids: Vec<String> = Vec::new();
    for p in policies {
        let id = format!("{}:{}", p.database, p.environment);
        let roles_json = serde_json::to_string(&p.allowed_roles).unwrap_or_else(|_| "[]".into());
        let groups_json = serde_json::to_string(&p.allowed_groups).unwrap_or_else(|_| "[]".into());
        conn.execute(
            "INSERT INTO access_policies (id, database_name, environment, allowed_roles_json, allowed_groups_json, source, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'toml', ?6, ?6)
             ON CONFLICT(database_name, environment) DO UPDATE SET
               allowed_roles_json = ?4, allowed_groups_json = ?5, updated_at = ?6
             WHERE source = 'toml'",
            rusqlite::params![id, p.database, p.environment, roles_json, groups_json, now],
        )?;
        toml_ids.push(id);
    }
    delete_stale_toml_records(conn, "access_policies", &toml_ids)?;
    Ok(())
}

/// Check if a user is allowed to create requests for the given database×environment.
/// Returns Ok(()) if allowed, Err(403) if denied.
/// Open by default: no matching policy = allow.
pub fn check_access_policy(
    conn: &Connection,
    database: &str,
    environment: &str,
    user: &crate::state::AuthUser,
    license: &crate::license::License,
) -> Result<(), crate::api_error::ApiError> {
    if user.effective_permission() == "admin" {
        return Ok(());
    }

    let lookup = |db: &str, env: &str| -> Option<(String, String)> {
        conn.query_row(
            "SELECT allowed_roles_json, allowed_groups_json FROM access_policies WHERE database_name = ?1 AND environment = ?2",
            rusqlite::params![db, env],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).ok()
    };

    let policy = lookup(database, environment)
        .or_else(|| lookup("*", environment))
        .or_else(|| lookup(database, "*"))
        .or_else(|| lookup("*", "*"));

    let Some((roles_json, groups_json)) = policy else {
        return Ok(());
    };

    crate::limits::require_pro("Access policies", license)?;

    let allowed_roles: Vec<String> = serde_json::from_str(&roles_json).unwrap_or_default();
    let allowed_groups: Vec<String> = serde_json::from_str(&groups_json).unwrap_or_default();

    if allowed_roles.is_empty() && allowed_groups.is_empty() {
        return Ok(());
    }

    let role_match = allowed_roles.iter().any(|r| user.roles.iter().any(|ur| ur == r));
    let group_match = allowed_groups.iter().any(|g| user.groups.iter().any(|ug| ug == g));

    if role_match || group_match {
        Ok(())
    } else {
        Err(crate::api_error::ApiError::forbidden(format!(
            "access denied: you are not authorized to access database '{database}' in '{environment}'"
        )).with_code("access_policy_denied"))
    }
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
    fn match_workflow_prefers_exact_operation() {
        let rows = vec![
            WorkflowRow {
                id: "catchall".into(),
                operations_json: "[]".into(),
                steps_json: "[]".into(),
                require_reason: false,
            },
            WorkflowRow {
                id: "exact".into(),
                operations_json: r#"["execute_query"]"#.into(),
                steps_json: r#"[{"type":"approval","mode":"all","approvers":[]}]"#.into(),
                require_reason: true,
            },
        ];
        let result = match_workflow(&rows, "execute_query").unwrap().unwrap();
        assert_eq!(result.0, "exact");
        assert!(result.2); // require_reason
    }

    #[test]
    fn match_workflow_falls_back_to_catchall() {
        let rows = vec![WorkflowRow {
            id: "catchall".into(),
            operations_json: "[]".into(),
            steps_json: "[]".into(),
            require_reason: false,
        }];
        let result = match_workflow(&rows, "migrate_up").unwrap().unwrap();
        assert_eq!(result.0, "catchall");
    }

    #[test]
    fn match_workflow_returns_none_when_empty() {
        let result = match_workflow(&[], "execute_query").unwrap();
        assert!(result.is_none());
    }

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
            evaluate_workflow(&conn, "app", "production", "execute_query")
                .unwrap()
                .unwrap();
        assert_eq!(workflow_id, "app:production:*");
        assert!(steps.is_empty());
        assert!(!require_reason);
    }

    #[test]
    fn evaluate_workflow_propagates_db_errors() {
        let conn = Connection::open_in_memory().unwrap();

        let err = evaluate_workflow(&conn, "app", "production", "execute_query").unwrap_err();
        assert!(matches!(err, PolicyEvalError::Database(_)));
    }

    #[test]
    fn evaluate_approval_policy_auto_approves_without_workflow() {
        let conn = Connection::open_in_memory().unwrap();
        db::init(&conn).unwrap();

        let decision =
            evaluate_approval_policy(&conn, "app", "production", "execute_query").unwrap();

        assert!(!decision.needs_approval);
        assert!(decision.workflow_id.is_none());
        assert!(decision.workflow_snapshot_json.is_none());
        assert!(!decision.require_reason);
    }

    #[test]
    fn evaluate_fails_on_corrupted_steps_json() {
        let conn = Connection::open_in_memory().unwrap();
        db::init(&conn).unwrap();

        conn.execute(
            "INSERT INTO workflows (id, database_name, environment, operations_json, steps_json, require_reason, source, created_at, updated_at)
             VALUES ('bad', 'app', 'production', '[\"execute_query\"]', 'NOT VALID JSON', 0, 'api', 't1', 't1')",
            [],
        ).unwrap();

        let err =
            evaluate_approval_policy(&conn, "app", "production", "execute_query").unwrap_err();
        assert!(matches!(err, PolicyEvalError::CorruptedConfig(_)));
    }

    #[test]
    fn evaluate_fails_on_corrupted_operations_json() {
        let conn = Connection::open_in_memory().unwrap();
        db::init(&conn).unwrap();

        conn.execute(
            "INSERT INTO workflows (id, database_name, environment, operations_json, steps_json, require_reason, source, created_at, updated_at)
             VALUES ('bad', 'app', 'production', 'BROKEN', '[]', 0, 'api', 't1', 't1')",
            [],
        ).unwrap();

        let err =
            evaluate_approval_policy(&conn, "app", "production", "execute_query").unwrap_err();
        assert!(matches!(err, PolicyEvalError::CorruptedConfig(_)));
    }

    #[test]
    fn validate_workflows_catches_corruption() {
        let conn = Connection::open_in_memory().unwrap();
        db::init(&conn).unwrap();

        conn.execute(
            "INSERT INTO workflows (id, database_name, environment, operations_json, steps_json, require_reason, source, created_at, updated_at)
             VALUES ('ok', 'app', 'dev', '[\"execute_query\"]', '[]', 0, 'api', 't1', 't1')",
            [],
        ).unwrap();
        assert!(validate_workflows(&conn).is_ok());

        conn.execute(
            "INSERT INTO workflows (id, database_name, environment, operations_json, steps_json, require_reason, source, created_at, updated_at)
             VALUES ('bad', 'app', 'prod', '[\"execute_query\"]', '{corrupt', 0, 'api', 't1', 't1')",
            [],
        ).unwrap();
        assert!(validate_workflows(&conn).is_err());
    }
}
