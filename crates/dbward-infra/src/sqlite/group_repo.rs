use crate::sqlite::DbConn;
use crate::sqlite::error::{db_err, json_err};
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
            .map_err(db_err("group: delete_by_source"))?;
        Ok(n as u64)
    }

    fn create(&self, name: &str, members: &[String], source: &str) -> Result<(), AppError> {
        let conn = self.conn.lock();
        let members_json = serde_json::to_string(members).map_err(json_err("group: create"))?;
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO groups (name, members_json, source, lifecycle_state, created_at, updated_at) VALUES (?1, ?2, ?3, 'active', ?4, ?5) ON CONFLICT(name) DO UPDATE SET members_json=excluded.members_json, lifecycle_state='active', updated_at=excluded.updated_at",
            rusqlite::params![name, members_json, source, now, now],
        )
        .map_err(db_err("group: create"))?;
        Ok(())
    }

    fn list(&self) -> Result<Vec<(String, Vec<String>)>, AppError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT name, members_json FROM groups")
            .map_err(db_err("group: list"))?;
        let rows = stmt
            .query_map([], |row| {
                let name: String = row.get(0)?;
                let members_json: String = row.get(1)?;
                Ok((name, members_json))
            })
            .map_err(db_err("group: list"))?;

        let mut results = Vec::new();
        for row in rows {
            let (name, json) = row.map_err(db_err("group: list"))?;
            let members: Vec<String> =
                serde_json::from_str(&json).map_err(json_err("group: members"))?;
            results.push((name, members));
        }
        Ok(results)
    }

    fn delete_stale_config(&self, active_names: &[String]) -> Result<u64, AppError> {
        let conn = self.conn.lock();
        if active_names.is_empty() {
            let n = conn
                .execute("DELETE FROM groups WHERE source = 'config'", [])
                .map_err(db_err("group: delete_stale"))?;
            return Ok(n as u64);
        }
        let placeholders: String = (1..=active_names.len())
            .map(|i| format!("?{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let sql =
            format!("DELETE FROM groups WHERE source = 'config' AND name NOT IN ({placeholders})");
        let params: Vec<&dyn rusqlite::types::ToSql> = active_names
            .iter()
            .map(|s| s as &dyn rusqlite::types::ToSql)
            .collect();
        let n = conn
            .execute(&sql, params.as_slice())
            .map_err(db_err("group: delete_stale"))?;
        Ok(n as u64)
    }
}
