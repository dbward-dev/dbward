use rusqlite::Connection;

/// Initialize SQLite database with WAL mode and schema.
pub fn init(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.pragma_update(None, "journal_mode", "WAL")?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS tokens (
            id TEXT PRIMARY KEY,
            subject_type TEXT NOT NULL DEFAULT 'user',
            subject_id TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            token_prefix TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'developer',
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL,
            revoked_at TEXT
        );

        CREATE TABLE IF NOT EXISTS requests (
            id TEXT PRIMARY KEY,
            created_by TEXT NOT NULL,
            operation TEXT NOT NULL,
            environment TEXT NOT NULL,
            database_name TEXT NOT NULL DEFAULT 'default',
            status TEXT NOT NULL DEFAULT 'pending',
            detail TEXT NOT NULL,
            emergency INTEGER NOT NULL DEFAULT 0,
            reason TEXT,
            workflow_id TEXT,
            workflow_snapshot_json TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            resolved_at TEXT
        );

        CREATE TABLE IF NOT EXISTS approvals (
            id TEXT PRIMARY KEY,
            request_id TEXT NOT NULL,
            action TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            comment TEXT,
            step_index INTEGER NOT NULL DEFAULT 0,
            actor_role TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY (request_id) REFERENCES requests(id)
        );

        CREATE TABLE IF NOT EXISTS agents (
            id TEXT PRIMARY KEY,
            display_name TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            token_id TEXT NOT NULL,
            capabilities_json TEXT NOT NULL DEFAULT '{}',
            last_seen_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (token_id) REFERENCES tokens(id)
        );

        CREATE TABLE IF NOT EXISTS agent_executions (
            id TEXT PRIMARY KEY,
            request_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'claimed',
            execution_token_json TEXT NOT NULL,
            lease_expires_at TEXT NOT NULL,
            started_at TEXT,
            finished_at TEXT,
            error_message TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (request_id) REFERENCES requests(id)
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id TEXT PRIMARY KEY,
            request_id TEXT,
            execution_id TEXT,
            actor_id TEXT NOT NULL,
            operation TEXT NOT NULL,
            environment TEXT NOT NULL,
            database_name TEXT NOT NULL DEFAULT 'default',
            detail TEXT NOT NULL,
            status TEXT NOT NULL,
            result_summary TEXT,
            error_message TEXT,
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_requests_status ON requests(status, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_approvals_request ON approvals(request_id);
        CREATE INDEX IF NOT EXISTS idx_approvals_step ON approvals(request_id, step_index, actor_id);
        CREATE INDEX IF NOT EXISTS idx_agent_exec_request ON agent_executions(request_id);
        CREATE INDEX IF NOT EXISTS idx_agent_exec_agent ON agent_executions(agent_id, status);
        CREATE INDEX IF NOT EXISTS idx_audit_request ON audit_log(request_id);

        CREATE TABLE IF NOT EXISTS workflows (
            id TEXT PRIMARY KEY,
            database_name TEXT NOT NULL,
            environment TEXT NOT NULL,
            operations_json TEXT NOT NULL DEFAULT '[]',
            steps_json TEXT NOT NULL DEFAULT '[]',
            require_reason INTEGER NOT NULL DEFAULT 0,
            source TEXT NOT NULL DEFAULT 'api',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(database_name, environment, operations_json)
        );

        CREATE TABLE IF NOT EXISTS execution_policies (
            id TEXT PRIMARY KEY,
            database_name TEXT NOT NULL,
            environment TEXT NOT NULL,
            max_executions INTEGER NOT NULL DEFAULT 1,
            execution_window_secs INTEGER NOT NULL DEFAULT 86400,
            retry_on_failure INTEGER NOT NULL DEFAULT 0,
            source TEXT NOT NULL DEFAULT 'api',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(database_name, environment)
        );

        CREATE TABLE IF NOT EXISTS result_policies (
            id TEXT PRIMARY KEY,
            database_name TEXT NOT NULL,
            environment TEXT NOT NULL,
            delivery_mode TEXT NOT NULL DEFAULT 'direct',
            storage_config_json TEXT NOT NULL DEFAULT '{}',
            access_json TEXT NOT NULL DEFAULT '[\"requester\", \"admin\"]',
            source TEXT NOT NULL DEFAULT 'api',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(database_name, environment)
        );

        CREATE TABLE IF NOT EXISTS notification_policies (
            id TEXT PRIMARY KEY,
            database_name TEXT NOT NULL,
            environment TEXT NOT NULL,
            webhooks_json TEXT NOT NULL DEFAULT '[]',
            source TEXT NOT NULL DEFAULT 'api',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(database_name, environment)
        );
        ",
    )?;

    recover_in_flight_requests(conn)?;

    Ok(())
}

fn recover_in_flight_requests(conn: &Connection) -> Result<(), rusqlite::Error> {
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute_batch("BEGIN")?;
    conn.execute(
        "UPDATE requests
         SET status = 'approved', updated_at = ?1
         WHERE status IN ('dispatched', 'running')",
        rusqlite::params![now],
    )?;
    conn.execute(
        "UPDATE agent_executions
         SET status = 'failed', finished_at = ?1, error_message = COALESCE(error_message, 'server restarted before result relay completed')
         WHERE status = 'claimed'",
        rusqlite::params![now],
    )?;
    conn.execute_batch("COMMIT")?;
    Ok(())
}

/// Purge old completed requests and audit logs based on TTL.
pub fn purge_old_records(
    conn: &Connection,
    request_ttl_days: u32,
    audit_ttl_days: u32,
) -> Result<(usize, usize), rusqlite::Error> {
    let req_cutoff =
        (chrono::Utc::now() - chrono::Duration::days(request_ttl_days as i64)).to_rfc3339();
    let audit_cutoff =
        (chrono::Utc::now() - chrono::Duration::days(audit_ttl_days as i64)).to_rfc3339();

    // Delete child rows first to satisfy FK constraints
    conn.execute(
        "DELETE FROM approvals WHERE request_id IN (SELECT id FROM requests WHERE created_at < ?1 AND status IN ('executed', 'failed', 'rejected'))",
        rusqlite::params![req_cutoff],
    )?;
    conn.execute(
        "DELETE FROM agent_executions WHERE request_id IN (SELECT id FROM requests WHERE created_at < ?1 AND status IN ('executed', 'failed', 'rejected'))",
        rusqlite::params![req_cutoff],
    )?;
    let req_deleted = conn.execute(
        "DELETE FROM requests WHERE created_at < ?1 AND status IN ('executed', 'failed', 'rejected')",
        rusqlite::params![req_cutoff],
    )?;
    let audit_deleted = conn.execute(
        "DELETE FROM audit_log WHERE created_at < ?1",
        rusqlite::params![audit_cutoff],
    )?;
    Ok((req_deleted, audit_deleted))
}

/// Reclaim expired leases: reset running→approved so client can re-dispatch.
pub fn reclaim_expired_leases(conn: &Connection) -> Result<usize, rusqlite::Error> {
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute_batch("BEGIN")?;
    let count = conn.execute(
        "UPDATE requests SET status = 'approved', updated_at = ?1
         WHERE status = 'running' AND id IN (
           SELECT request_id FROM agent_executions
           WHERE status = 'claimed' AND lease_expires_at < ?1
         )",
        rusqlite::params![now],
    )?;
    conn.execute(
        "UPDATE agent_executions SET status = 'failed', finished_at = ?1,
         error_message = 'lease expired'
         WHERE status = 'claimed' AND lease_expires_at < ?1",
        rusqlite::params![now],
    )?;
    conn.execute_batch("COMMIT")?;
    Ok(count)
}

/// Sync workflows from TOML config into SQLite. Only touches source='toml' rows.
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
    // Remove TOML-sourced workflows that no longer exist in config
    delete_stale_toml_records(conn, "workflows", &toml_ids)?;
    Ok(())
}

/// Evaluate workflow for a request. Returns Some((workflow_id, steps, require_reason)) when a workflow matches.
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

        // Priority: exact operations match first, then catch-all (empty operations)
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

/// Sync execution policies from TOML config into SQLite.
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

/// Sync result policies from TOML config into SQLite.
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

/// Lookup execution policy for a request. Returns (max_executions, window_secs, retry_on_failure).
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
        .unwrap_or((1, 86400, false)) // safe defaults
}

/// Lookup result policy for a request. Returns (delivery_mode, access_roles).
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

/// Sync notification policies from TOML config into SQLite.
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

/// Lookup notification webhooks for a database×environment.
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

    #[test]
    fn init_creates_tables() {
        let conn = Connection::open_in_memory().unwrap();
        init(&conn).unwrap();

        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        assert!(tables.contains(&"tokens".to_string()));
        assert!(tables.contains(&"requests".to_string()));
        assert!(tables.contains(&"approvals".to_string()));
        assert!(tables.contains(&"agents".to_string()));
        assert!(tables.contains(&"agent_executions".to_string()));
        assert!(tables.contains(&"audit_log".to_string()));
    }

    #[test]
    fn init_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        init(&conn).unwrap();
        init(&conn).unwrap();
    }

    #[test]
    fn init_recovers_in_flight_requests() {
        let conn = Connection::open_in_memory().unwrap();
        init(&conn).unwrap();

        conn.execute(
            "INSERT INTO requests (id, created_by, operation, environment, database_name, status, detail, created_at, updated_at)
             VALUES ('req-1', 'alice', 'execute_query', 'development', 'app', 'dispatched', 'SELECT 1', 't1', 't1')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO requests (id, created_by, operation, environment, database_name, status, detail, created_at, updated_at)
             VALUES ('req-2', 'alice', 'execute_query', 'development', 'app', 'running', 'SELECT 1', 't1', 't1')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO agent_executions (id, request_id, agent_id, status, execution_token_json, lease_expires_at, started_at, created_at)
             VALUES ('exec-1', 'req-2', 'agent-1', 'claimed', '{}', 't2', 't1', 't1')",
            [],
        )
        .unwrap();

        init(&conn).unwrap();

        let req1: String = conn
            .query_row(
                "SELECT status FROM requests WHERE id = 'req-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let req2: String = conn
            .query_row(
                "SELECT status FROM requests WHERE id = 'req-2'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let exec1: (String, Option<String>) = conn
            .query_row(
                "SELECT status, error_message FROM agent_executions WHERE id = 'exec-1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();

        assert_eq!(req1, "approved");
        assert_eq!(req2, "approved");
        assert_eq!(exec1.0, "failed");
        assert!(exec1.1.unwrap().contains("server restarted"));
    }

    #[test]
    fn purge_old_records_deletes_expired() {
        let conn = Connection::open_in_memory().unwrap();
        init(&conn).unwrap();

        let old = "2020-01-01T00:00:00+00:00";
        let recent = chrono::Utc::now().to_rfc3339();

        // Old executed request (should be purged)
        conn.execute(
            "INSERT INTO requests (id, created_by, operation, environment, database_name, status, detail, created_at, updated_at)
             VALUES ('old-1', 'alice', 'execute_query', 'dev', 'app', 'executed', 'SELECT 1', ?1, ?1)",
            rusqlite::params![old],
        ).unwrap();
        conn.execute(
            "INSERT INTO approvals (id, request_id, action, actor_id, created_at)
             VALUES ('apr-1', 'old-1', 'approve', 'bob', ?1)",
            rusqlite::params![old],
        )
        .unwrap();

        // Recent executed request (should NOT be purged)
        conn.execute(
            "INSERT INTO requests (id, created_by, operation, environment, database_name, status, detail, created_at, updated_at)
             VALUES ('new-1', 'alice', 'execute_query', 'dev', 'app', 'executed', 'SELECT 1', ?1, ?1)",
            rusqlite::params![recent],
        ).unwrap();

        // Old pending request (should NOT be purged — still active)
        conn.execute(
            "INSERT INTO requests (id, created_by, operation, environment, database_name, status, detail, created_at, updated_at)
             VALUES ('old-2', 'alice', 'execute_query', 'dev', 'app', 'pending', 'SELECT 1', ?1, ?1)",
            rusqlite::params![old],
        ).unwrap();

        // Old audit log
        conn.execute(
            "INSERT INTO audit_log (id, actor_id, operation, environment, database_name, detail, status, created_at)
             VALUES ('aud-1', 'alice', 'execute_query', 'dev', 'app', 'SELECT 1', 'ok', ?1)",
            rusqlite::params![old],
        ).unwrap();

        // Recent audit log
        conn.execute(
            "INSERT INTO audit_log (id, actor_id, operation, environment, database_name, detail, status, created_at)
             VALUES ('aud-2', 'alice', 'execute_query', 'dev', 'app', 'SELECT 1', 'ok', ?1)",
            rusqlite::params![recent],
        ).unwrap();

        let (req_del, audit_del) = purge_old_records(&conn, 90, 365).unwrap();
        assert_eq!(req_del, 1); // old-1 purged
        assert_eq!(audit_del, 1); // aud-1 purged

        // Verify remaining
        let req_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM requests", [], |r| r.get(0))
            .unwrap();
        assert_eq!(req_count, 2); // new-1 + old-2

        let apr_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM approvals", [], |r| r.get(0))
            .unwrap();
        assert_eq!(apr_count, 0); // orphaned approval cleaned up

        let aud_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM audit_log", [], |r| r.get(0))
            .unwrap();
        assert_eq!(aud_count, 1); // aud-2 remains
    }

    #[test]
    fn sync_workflows_only_deletes_toml_rows() {
        let conn = Connection::open_in_memory().unwrap();
        init(&conn).unwrap();

        conn.execute(
            "INSERT INTO workflows (id, database_name, environment, operations_json, steps_json, require_reason, source, created_at, updated_at)
             VALUES ('api-row', 'app', 'development', '[\"execute_query\"]', '[]', 0, 'api', 't1', 't1')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO workflows (id, database_name, environment, operations_json, steps_json, require_reason, source, created_at, updated_at)
             VALUES ('stale-toml', 'legacy', 'development', '[\"execute_query\"]', '[]', 0, 'toml', 't1', 't1')",
            [],
        )
        .unwrap();

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
        init(&conn).unwrap();

        conn.execute(
            "INSERT INTO workflows (id, database_name, environment, operations_json, steps_json, require_reason, source, created_at, updated_at)
             VALUES ('app:production:*', 'app', 'production', '[]', '[]', 0, 'api', 't1', 't1')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO workflows (id, database_name, environment, operations_json, steps_json, require_reason, source, created_at, updated_at)
             VALUES ('*:production:execute_query', '*', 'production', '[\"execute_query\"]', '[{\"type\":\"approval\",\"mode\":\"all\",\"approvers\":[{\"role\":\"admin\",\"min\":1}],\"require_distinct_actors\":true}]', 0, 'api', 't1', 't1')",
            [],
        )
        .unwrap();

        let (workflow_id, steps, require_reason) =
            evaluate_workflow(&conn, "app", "production", "execute_query").unwrap();
        assert_eq!(workflow_id, "app:production:*");
        assert!(steps.is_empty());
        assert!(!require_reason);
    }

    #[test]
    fn evaluate_approval_policy_falls_back_to_static_policy_without_workflow() {
        let conn = Connection::open_in_memory().unwrap();
        init(&conn).unwrap();

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
