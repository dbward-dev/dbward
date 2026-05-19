use rusqlite::params;

use dbward_app::error::AppError;
use dbward_app::ports::repos::{SchemaRepo, SchemaSnapshotRecord};

use crate::sqlite::DbConn;

pub struct SqliteSchemaRepo {
    conn: DbConn,
}

impl SqliteSchemaRepo {
    pub fn new(conn: DbConn) -> Self {
        Self { conn }
    }
}

impl SchemaRepo for SqliteSchemaRepo {
    fn upsert_snapshot(&self, record: &SchemaSnapshotRecord) -> Result<(), AppError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO schema_snapshots \
             (database_name, environment, status, snapshot_json, error_message, dialect, collected_at, agent_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                record.database_name,
                record.environment,
                record.status,
                record.snapshot_json,
                record.error_message,
                record.dialect,
                record.collected_at,
                record.agent_id,
            ],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
        conn.execute(
            "UPDATE databases SET dialect = ?1 WHERE name = ?2 AND environment = ?3 AND dialect IS NULL",
            params![record.dialect, record.database_name, record.environment],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(())
    }

    fn get_snapshot(&self, db: &str, env: &str) -> Result<Option<SchemaSnapshotRecord>, AppError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT database_name, environment, status, snapshot_json, error_message, dialect, collected_at, agent_id \
             FROM schema_snapshots WHERE database_name = ?1 AND environment = ?2",
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
        let result = stmt.query_row(params![db, env], |row| {
            Ok(SchemaSnapshotRecord {
                database_name: row.get(0)?,
                environment: row.get(1)?,
                status: row.get(2)?,
                snapshot_json: row.get(3)?,
                error_message: row.get(4)?,
                dialect: row.get(5)?,
                collected_at: row.get(6)?,
                agent_id: row.get(7)?,
            })
        });
        match result {
            Ok(r) => Ok(Some(r)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(AppError::Internal(e.to_string())),
        }
    }

    fn get_dialect(&self, db: &str, env: &str) -> Result<Option<String>, AppError> {
        let conn = self.conn.lock().unwrap();
        let result: Result<Option<String>, _> = conn.query_row(
            "SELECT dialect FROM databases WHERE name = ?1 AND environment = ?2",
            params![db, env],
            |row| row.get(0),
        );
        match result {
            Ok(d) => Ok(d),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(AppError::Internal(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::open_memory;
    use crate::sqlite::schema::initialize;

    fn setup() -> DbConn {
        let conn = open_memory().unwrap();
        {
            let c = conn.lock().unwrap();
            initialize(&c).unwrap();
        }
        conn
    }

    #[test]
    fn upsert_and_get_snapshot() {
        let conn = setup();
        let repo = SqliteSchemaRepo::new(conn);
        let record = SchemaSnapshotRecord {
            database_name: "app".into(),
            environment: "production".into(),
            status: "ready".into(),
            snapshot_json: Some(r#"{"tables":[]}"#.into()),
            error_message: None,
            dialect: "postgresql".into(),
            collected_at: "2026-05-19T12:00:00Z".into(),
            agent_id: "agent-1".into(),
        };
        repo.upsert_snapshot(&record).unwrap();
        let got = repo.get_snapshot("app", "production").unwrap().unwrap();
        assert_eq!(got.status, "ready");
        assert_eq!(got.dialect, "postgresql");
    }

    #[test]
    fn get_snapshot_not_found() {
        let conn = setup();
        let repo = SqliteSchemaRepo::new(conn);
        assert!(repo.get_snapshot("nope", "nope").unwrap().is_none());
    }

    #[test]
    fn upsert_replaces_existing() {
        let conn = setup();
        let repo = SqliteSchemaRepo::new(conn);
        let record = SchemaSnapshotRecord {
            database_name: "app".into(),
            environment: "production".into(),
            status: "ready".into(),
            snapshot_json: Some("v1".into()),
            error_message: None,
            dialect: "postgresql".into(),
            collected_at: "2026-05-19T12:00:00Z".into(),
            agent_id: "agent-1".into(),
        };
        repo.upsert_snapshot(&record).unwrap();
        let updated = SchemaSnapshotRecord {
            status: "failed".into(),
            snapshot_json: None,
            error_message: Some("timeout".into()),
            collected_at: "2026-05-19T13:00:00Z".into(),
            ..record
        };
        repo.upsert_snapshot(&updated).unwrap();
        let got = repo.get_snapshot("app", "production").unwrap().unwrap();
        assert_eq!(got.status, "failed");
        assert_eq!(got.error_message.as_deref(), Some("timeout"));
    }
}
