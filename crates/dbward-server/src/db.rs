use rusqlite::Connection;

/// Initialize SQLite database with WAL mode and schema.
pub fn init(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.pragma_update(None, "journal_mode", "WAL")?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS tokens (
            id TEXT PRIMARY KEY,
            user TEXT NOT NULL,
            role TEXT NOT NULL,
            hash TEXT NOT NULL,
            prefix TEXT NOT NULL,
            created_at TEXT NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS requests (
            id TEXT PRIMARY KEY,
            user TEXT NOT NULL,
            operation TEXT NOT NULL,
            environment TEXT NOT NULL,
            database TEXT NOT NULL DEFAULT 'default',
            detail TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            approved_by TEXT,
            created_at TEXT NOT NULL,
            resolved_at TEXT,
            emergency INTEGER NOT NULL DEFAULT 0,
            reason TEXT
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            user TEXT NOT NULL,
            role TEXT NOT NULL,
            operation TEXT NOT NULL,
            environment TEXT NOT NULL,
            database TEXT NOT NULL DEFAULT 'default',
            detail TEXT NOT NULL,
            success INTEGER NOT NULL,
            error_message TEXT,
            request_id TEXT,
            emergency INTEGER NOT NULL DEFAULT 0
        );",
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
        assert!(tables.contains(&"audit_log".to_string()));
    }

    #[test]
    fn init_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        init(&conn).unwrap();
        init(&conn).unwrap();
    }
}
