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
        CREATE INDEX IF NOT EXISTS idx_agent_exec_request ON agent_executions(request_id);
        CREATE INDEX IF NOT EXISTS idx_agent_exec_agent ON agent_executions(agent_id, status);
        CREATE INDEX IF NOT EXISTS idx_audit_request ON audit_log(request_id);

        CREATE TABLE IF NOT EXISTS workflows (
            id TEXT PRIMARY KEY,
            database_name TEXT NOT NULL,
            environment TEXT NOT NULL,
            operations_json TEXT NOT NULL DEFAULT '[]',
            steps_json TEXT NOT NULL DEFAULT '[]',
            source TEXT NOT NULL DEFAULT 'api',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(database_name, environment)
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
pub fn sync_workflows(
    conn: &Connection,
    workflows: &[crate::server_config::WorkflowDef],
) -> Result<(), rusqlite::Error> {
    let now = chrono::Utc::now().to_rfc3339();
    for w in workflows {
        let id = format!("{}:{}", w.database, w.environment);
        let ops_json = serde_json::to_string(&w.operations).unwrap_or_else(|_| "[]".into());
        let steps_json = serde_json::to_string(&w.steps).unwrap_or_else(|_| "[]".into());
        conn.execute(
            "INSERT INTO workflows (id, database_name, environment, operations_json, steps_json, source, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'toml', ?6, ?6)
             ON CONFLICT(database_name, environment) DO UPDATE SET
               operations_json = ?4, steps_json = ?5, updated_at = ?6
             WHERE source = 'toml'",
            rusqlite::params![id, w.database, w.environment, ops_json, steps_json, now],
        )?;
    }
    Ok(())
}

fn workflow_action_for_operation(
    operations_json: &str,
    steps_json: &str,
    operation: &str,
) -> Option<String> {
    let operations: Vec<String> = serde_json::from_str(operations_json).unwrap_or_default();
    if !operations.is_empty() && !operations.iter().any(|op| op == operation) {
        return None;
    }

    let steps: Vec<serde_json::Value> = serde_json::from_str(steps_json).unwrap_or_default();
    Some(if steps.is_empty() {
        "auto_approve".into()
    } else {
        "require_approval".into()
    })
}

/// Evaluate workflow for a request. Returns Some(action) when a workflow matches.
pub fn evaluate_workflow(
    conn: &Connection,
    database: &str,
    environment: &str,
    operation: &str,
) -> Option<String> {
    let candidates = [
        (database, environment),
        ("*", environment),
        (database, "*"),
        ("*", "*"),
    ];

    for (db_name, env_name) in candidates {
        let row: Option<(String, String)> = conn
            .query_row(
                "SELECT operations_json, steps_json FROM workflows WHERE database_name = ?1 AND environment = ?2",
                rusqlite::params![db_name, env_name],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .ok();

        if let Some((operations_json, steps_json)) = row {
            if let Some(action) =
                workflow_action_for_operation(&operations_json, &steps_json, operation)
            {
                return Some(action);
            }
        }
    }

    None
}

/// Sync execution policies from TOML config into SQLite.
pub fn sync_execution_policies(
    conn: &Connection,
    policies: &[crate::server_config::ExecutionPolicyDef],
) -> Result<(), rusqlite::Error> {
    let now = chrono::Utc::now().to_rfc3339();
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
    }
    Ok(())
}

/// Sync result policies from TOML config into SQLite.
pub fn sync_result_policies(
    conn: &Connection,
    policies: &[crate::server_config::ResultPolicyDef],
) -> Result<(), rusqlite::Error> {
    let now = chrono::Utc::now().to_rfc3339();
    for p in policies {
        let id = format!("{}:{}", p.database, p.environment);
        let config_json = p.storage_config.as_ref()
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
    }
    Ok(())
}

/// Lookup execution policy for a request. Returns (max_executions, window_secs, retry_on_failure).
pub fn get_execution_policy(conn: &Connection, database: &str, environment: &str) -> (u32, u64, bool) {
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
pub fn get_result_policy(conn: &Connection, database: &str, environment: &str) -> (String, Vec<String>) {
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
    }
    Ok(())
}

/// Lookup notification webhooks for a database×environment.
pub fn get_notification_webhooks(conn: &Connection, database: &str, environment: &str) -> Vec<crate::webhook::WebhookConfig> {
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
}
