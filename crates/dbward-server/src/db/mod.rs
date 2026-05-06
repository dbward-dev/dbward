pub(crate) mod agent_repo;
pub(crate) mod audit_event_repo;
pub(crate) mod audit_repo;
pub mod maintenance;
pub mod policy_repo;
pub(crate) mod request_repo;
pub(crate) mod token_repo;

use rusqlite::Connection;

/// Latest schema version. Increment when adding migrations.
pub const LATEST_SCHEMA_VERSION: i64 = 4;

/// Initialize SQLite database with WAL mode and versioned schema.
pub fn init(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.pragma_update(None, "journal_mode", "WAL")?;

    let current_version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;

    if current_version > LATEST_SCHEMA_VERSION {
        return Err(rusqlite::Error::QueryReturnedNoRows); // caller should map to a clear message
    }

    if current_version == 0 {
        // Check if tables already exist (unsupported legacy DB)
        let has_tables = has_user_tables(conn)?;
        if has_tables {
            return Err(rusqlite::Error::QueryReturnedNoRows); // unversioned DB with existing tables
        }

        // Fresh DB: create base schema then apply all migrations
        create_schema_v1(conn)?;
        for v in 2..=LATEST_SCHEMA_VERSION {
            apply_migration(conn, v)?;
        }
        conn.pragma_update(None, "user_version", LATEST_SCHEMA_VERSION)?;
    } else if current_version < LATEST_SCHEMA_VERSION {
        // Apply migrations sequentially
        for v in (current_version + 1)..=LATEST_SCHEMA_VERSION {
            apply_migration(conn, v)?;
        }
        conn.pragma_update(None, "user_version", LATEST_SCHEMA_VERSION)?;
    }

    maintenance::recover_in_flight_requests(conn)?;

    Ok(())
}

/// Initialize schema only (without recovering in-flight requests).
/// Use this for CLI tools that open the DB file directly (e.g. token create).
pub fn init_schema_only(conn: &Connection) -> Result<(), rusqlite::Error> {
    let current_version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;

    if current_version == 0 {
        if has_user_tables(conn)? {
            return Err(rusqlite::Error::QueryReturnedNoRows);
        }
        create_schema_v1(conn)?;
        for v in 2..=LATEST_SCHEMA_VERSION {
            apply_migration(conn, v)?;
        }
        conn.pragma_update(None, "user_version", LATEST_SCHEMA_VERSION)?;
    } else if current_version < LATEST_SCHEMA_VERSION {
        for v in (current_version + 1)..=LATEST_SCHEMA_VERSION {
            apply_migration(conn, v)?;
        }
        conn.pragma_update(None, "user_version", LATEST_SCHEMA_VERSION)?;
    }

    Ok(())
}

fn has_user_tables(conn: &Connection) -> Result<bool, rusqlite::Error> {
    conn.query_row(
        "SELECT EXISTS(
            SELECT 1
            FROM sqlite_master
            WHERE type = 'table'
              AND name NOT LIKE 'sqlite_%'
        )",
        [],
        |row| row.get(0),
    )
}

fn has_column(conn: &Connection, table: &str, column: &str) -> Result<bool, rusqlite::Error> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for row in rows {
        if row? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Apply a single migration step. Add new versions here.
fn apply_migration(conn: &Connection, version: i64) -> Result<(), rusqlite::Error> {
    match version {
        2 => {
            if !has_column(conn, "workflows", "allow_same_approver_across_steps")? {
                conn.execute_batch(
                    "ALTER TABLE workflows
                     ADD COLUMN allow_same_approver_across_steps INTEGER NOT NULL DEFAULT 0",
                )?;
            }
            Ok(())
        }
        3 => {
            if !has_column(conn, "requests", "idempotency_key")? {
                conn.execute_batch(
                    "ALTER TABLE requests
                     ADD COLUMN idempotency_key TEXT",
                )?;
            }
            if !has_column(conn, "requests", "metadata_json")? {
                conn.execute_batch(
                    "ALTER TABLE requests
                     ADD COLUMN metadata_json TEXT NOT NULL DEFAULT '{}'",
                )?;
            }
            conn.execute_batch(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_requests_idempotency_key
                 ON requests(idempotency_key)
                 WHERE idempotency_key IS NOT NULL",
            )?;
            Ok(())
        }
        4 => {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS audit_events (
                    id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    event_category TEXT NOT NULL,
                    event_version INTEGER NOT NULL DEFAULT 1,
                    outcome TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    actor_type TEXT NOT NULL,
                    resource_type TEXT,
                    resource_id TEXT,
                    peer_ip TEXT,
                    client_ip TEXT,
                    client_ip_source TEXT,
                    request_id TEXT,
                    operation TEXT,
                    environment TEXT,
                    database_name TEXT,
                    detail_fingerprint TEXT,
                    detail_raw TEXT,
                    reason TEXT,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    prev_hash TEXT CHECK (prev_hash IS NULL OR length(prev_hash) = 64),
                    event_hash TEXT NOT NULL CHECK (length(event_hash) = 64),
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_audit_events_type ON audit_events(event_type, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_audit_events_actor ON audit_events(actor_id, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_audit_events_category ON audit_events(event_category, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_audit_events_request ON audit_events(request_id);
                CREATE INDEX IF NOT EXISTS idx_audit_events_resource ON audit_events(resource_type, resource_id);
                CREATE INDEX IF NOT EXISTS idx_audit_events_created ON audit_events(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_audit_events_outcome ON audit_events(outcome, created_at DESC);",
            )?;
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Create the full v1 schema (used for fresh installs).
fn create_schema_v1(conn: &Connection) -> Result<(), rusqlite::Error> {
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
            metadata_json TEXT NOT NULL DEFAULT '{}',
            idempotency_key TEXT,
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
        CREATE UNIQUE INDEX IF NOT EXISTS idx_requests_idempotency_key
            ON requests(idempotency_key)
            WHERE idempotency_key IS NOT NULL;
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
            allow_same_approver_across_steps INTEGER NOT NULL DEFAULT 0,
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
    )
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

        // Verify version is set
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, LATEST_SCHEMA_VERSION);
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

        // Second init should NOT change request/execution statuses (no-op recovery)
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
        let exec1: String = conn
            .query_row(
                "SELECT status FROM agent_executions WHERE id = 'exec-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();

        // States are preserved — lease reclaim handles recovery, not init
        assert_eq!(req1, "dispatched");
        assert_eq!(req2, "running");
        assert_eq!(exec1, "claimed");
    }

    #[test]
    fn init_fails_on_newer_version() {
        let conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "user_version", LATEST_SCHEMA_VERSION + 1)
            .unwrap();
        assert!(init(&conn).is_err());
    }

    #[test]
    fn init_fails_on_unversioned_existing_db() {
        let conn = Connection::open_in_memory().unwrap();
        // Create a table without setting user_version
        conn.execute_batch("CREATE TABLE requests (id TEXT PRIMARY KEY)")
            .unwrap();
        assert!(init(&conn).is_err());
    }

    #[test]
    fn init_fails_on_unversioned_db_with_non_dbward_tables() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE external_data (id TEXT PRIMARY KEY)")
            .unwrap();
        assert!(init(&conn).is_err());
    }

    #[test]
    fn init_migrates_workflow_allow_same_approver_column() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE requests (
                id TEXT PRIMARY KEY,
                created_by TEXT NOT NULL,
                operation TEXT NOT NULL,
                environment TEXT NOT NULL,
                database_name TEXT NOT NULL DEFAULT 'default',
                status TEXT NOT NULL DEFAULT 'pending',
                detail TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE agent_executions (
                id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'claimed',
                execution_token_json TEXT NOT NULL,
                lease_expires_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                error_message TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE workflows (
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
            );",
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 1).unwrap();

        init(&conn).unwrap();

        assert!(has_column(&conn, "workflows", "allow_same_approver_across_steps").unwrap());

        let version: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, LATEST_SCHEMA_VERSION);
    }

    #[test]
    fn init_migrates_request_metadata_and_idempotency() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE requests (
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
            CREATE TABLE agent_executions (
                id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'claimed',
                execution_token_json TEXT NOT NULL,
                lease_expires_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                error_message TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE workflows (
                id TEXT PRIMARY KEY,
                database_name TEXT NOT NULL,
                environment TEXT NOT NULL,
                operations_json TEXT NOT NULL DEFAULT '[]',
                steps_json TEXT NOT NULL DEFAULT '[]',
                require_reason INTEGER NOT NULL DEFAULT 0,
                allow_same_approver_across_steps INTEGER NOT NULL DEFAULT 0,
                source TEXT NOT NULL DEFAULT 'api',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(database_name, environment, operations_json)
            );",
        )
        .unwrap();
        conn.pragma_update(None, "user_version", 2).unwrap();

        init(&conn).unwrap();

        assert!(has_column(&conn, "requests", "metadata_json").unwrap());
        assert!(has_column(&conn, "requests", "idempotency_key").unwrap());

        conn.execute(
            "INSERT INTO requests (id, created_by, operation, environment, database_name, status, detail, created_at, updated_at, metadata_json, idempotency_key)
             VALUES ('req-1', 'alice', 'execute_query', 'development', 'app', 'pending', 'SELECT 1', 't1', 't1', '{\"ticket\":\"ABC-1\"}', 'idem-1')",
            [],
        )
        .unwrap();

        let metadata_json: String = conn
            .query_row(
                "SELECT metadata_json FROM requests WHERE id = 'req-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(metadata_json, "{\"ticket\":\"ABC-1\"}");

        let duplicate = conn.execute(
            "INSERT INTO requests (id, created_by, operation, environment, database_name, status, detail, created_at, updated_at, metadata_json, idempotency_key)
             VALUES ('req-2', 'alice', 'execute_query', 'development', 'app', 'pending', 'SELECT 1', 't1', 't1', '{}', 'idem-1')",
            [],
        );
        assert!(duplicate.is_err());

        let version: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, LATEST_SCHEMA_VERSION);
    }
}
