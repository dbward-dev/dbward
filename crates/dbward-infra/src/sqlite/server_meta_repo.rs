use dbward_app::error::AppError;
use dbward_app::ports::ServerMetaRepo;

use super::DbConn;

pub struct SqliteServerMetaRepo {
    conn: DbConn,
}

impl SqliteServerMetaRepo {
    pub fn new(conn: DbConn) -> Self {
        Self { conn }
    }
}

impl ServerMetaRepo for SqliteServerMetaRepo {
    fn get(&self, key: &str) -> Result<Option<String>, AppError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare_cached("SELECT value FROM server_meta WHERE key = ?1")
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let result = stmt
            .query_row([key], |row| row.get::<_, String>(0))
            .optional()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(result)
    }

    fn set(&self, key: &str, value: &str) -> Result<(), AppError> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO server_meta (key, value, updated_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![key, value, chrono::Utc::now().to_rfc3339()],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(())
    }
}

use rusqlite::OptionalExtension;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::open_memory;

    #[test]
    fn get_returns_none_for_missing_key() {
        let conn = open_memory().unwrap();
        let repo = SqliteServerMetaRepo::new(conn);
        assert_eq!(repo.get("nonexistent").unwrap(), None);
    }

    #[test]
    fn set_and_get_roundtrip() {
        let conn = open_memory().unwrap();
        let repo = SqliteServerMetaRepo::new(conn);
        repo.set("license_validated_until", "2026-06-16T10:00:00Z")
            .unwrap();
        assert_eq!(
            repo.get("license_validated_until").unwrap(),
            Some("2026-06-16T10:00:00Z".to_string())
        );
    }

    #[test]
    fn set_overwrites_existing_value() {
        let conn = open_memory().unwrap();
        let repo = SqliteServerMetaRepo::new(conn);
        repo.set("key", "v1").unwrap();
        repo.set("key", "v2").unwrap();
        assert_eq!(repo.get("key").unwrap(), Some("v2".to_string()));
    }
}
