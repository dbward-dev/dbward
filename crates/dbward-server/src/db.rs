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
            execution_result TEXT,
            execution_error TEXT,
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
            result_json TEXT,
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
        ",
    )?;

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
}
