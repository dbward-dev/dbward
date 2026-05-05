pub mod agent_repo;
pub mod audit_repo;
pub(crate) mod maintenance;
pub mod policy_repo;
pub mod request_repo;
pub(crate) mod token_repo;

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

        CREATE TABLE IF NOT EXISTS token_groups (
            token_id TEXT NOT NULL,
            group_name TEXT NOT NULL,
            FOREIGN KEY (token_id) REFERENCES tokens(id)
        );
        CREATE INDEX IF NOT EXISTS idx_token_groups_token ON token_groups(token_id);

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
            share_with_json TEXT,
            workflow_id TEXT,
            workflow_snapshot_json TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            resolved_at TEXT,
            cancelled_by TEXT,
            cancelled_at TEXT,
            cancel_reason TEXT
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

        CREATE TABLE IF NOT EXISTS request_results (
            request_id TEXT PRIMARY KEY,
            storage_backend TEXT NOT NULL,
            storage_key TEXT NOT NULL,
            content_length INTEGER NOT NULL,
            checksum_sha256 TEXT NOT NULL,
            retention_days INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'stored',
            stored_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY (request_id) REFERENCES requests(id)
        );
        CREATE INDEX IF NOT EXISTS idx_request_results_expires ON request_results(expires_at);

        CREATE TABLE IF NOT EXISTS result_access (
            request_id TEXT NOT NULL,
            selector_type TEXT NOT NULL,
            selector_value TEXT NOT NULL,
            FOREIGN KEY (request_id) REFERENCES requests(id)
        );
        CREATE INDEX IF NOT EXISTS idx_result_access_request
            ON result_access(request_id);
        CREATE INDEX IF NOT EXISTS idx_result_access_lookup
            ON result_access(selector_type, selector_value);
        ",
    )?;

    for sql in [
        "ALTER TABLE requests ADD COLUMN cancelled_by TEXT",
        "ALTER TABLE requests ADD COLUMN cancelled_at TEXT",
        "ALTER TABLE requests ADD COLUMN cancel_reason TEXT",
    ] {
        let _ = conn.execute(sql, []);
    }

    maintenance::recover_in_flight_requests(conn)?;

    Ok(())
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
