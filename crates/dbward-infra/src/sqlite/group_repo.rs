use crate::sqlite::DbConn;
use dbward_app::error::AppError;
use dbward_app::ports::GroupRepo;

pub struct SqliteGroupRepo {
    conn: DbConn,
}

impl SqliteGroupRepo {
    pub fn new(conn: DbConn) -> Self {
        Self { conn }
    }
}

impl GroupRepo for SqliteGroupRepo {
    fn delete_by_source(&self, source: &str) -> Result<u64, AppError> {
        let conn = self.conn.lock();
        let n = conn
            .execute("DELETE FROM groups WHERE source = ?1", [source])
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(n as u64)
    }

    fn create(&self, name: &str, members: &[String], source: &str) -> Result<(), AppError> {
        let conn = self.conn.lock();
        let members_json =
            serde_json::to_string(members).map_err(|e| AppError::Internal(e.to_string()))?;
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO groups (name, members_json, source, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![name, members_json, source, now, now],
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(())
    }

    fn list(&self) -> Result<Vec<(String, Vec<String>)>, AppError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT name, members_json FROM groups")
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                let name: String = row.get(0)?;
                let members_json: String = row.get(1)?;
                Ok((name, members_json))
            })
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let mut results = Vec::new();
        for row in rows {
            let (name, json) = row.map_err(|e| AppError::Internal(e.to_string()))?;
            let members: Vec<String> = serde_json::from_str(&json).unwrap_or_default();
            results.push((name, members));
        }
        Ok(results)
    }
}
