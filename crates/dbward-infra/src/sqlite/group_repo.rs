use crate::sqlite::DbConn;
use crate::sqlite::error::db_err;
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
    fn upsert(&self, name: &str) -> Result<(), AppError> {
        let conn = self.conn.lock();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO groups (name, created_at) VALUES (?1, ?2) ON CONFLICT(name) DO NOTHING",
            rusqlite::params![name, now],
        )
        .map_err(db_err("group: upsert"))?;
        Ok(())
    }

    fn list_names(&self) -> Result<Vec<String>, AppError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT name FROM groups ORDER BY name")
            .map_err(db_err("group: list_names"))?;
        let rows = stmt
            .query_map([], |row| row.get(0))
            .map_err(db_err("group: list_names"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(db_err("group: list_names"))
    }

    fn exists(&self, name: &str) -> Result<bool, AppError> {
        let conn = self.conn.lock();
        let count: u32 = conn
            .query_row(
                "SELECT COUNT(*) FROM groups WHERE name = ?1",
                rusqlite::params![name],
                |row| row.get(0),
            )
            .map_err(db_err("group: exists"))?;
        Ok(count > 0)
    }

    fn delete_stale(&self, active_names: &[String]) -> Result<u64, AppError> {
        let conn = self.conn.lock();
        if active_names.is_empty() {
            let n = conn
                .execute("DELETE FROM groups", [])
                .map_err(db_err("group: delete_stale"))?;
            return Ok(n as u64);
        }
        let placeholders: String = (1..=active_names.len())
            .map(|i| format!("?{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!("DELETE FROM groups WHERE name NOT IN ({placeholders})");
        let params: Vec<&dyn rusqlite::types::ToSql> = active_names
            .iter()
            .map(|s| s as &dyn rusqlite::types::ToSql)
            .collect();
        let n = conn
            .execute(&sql, params.as_slice())
            .map_err(db_err("group: delete_stale"))?;
        Ok(n as u64)
    }

    fn add_member(
        &self,
        group_name: &str,
        user_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AppError> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR IGNORE INTO group_members (group_name, user_id, added_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![group_name, user_id, now.to_rfc3339()],
        )
        .map_err(db_err("group: add_member"))?;
        Ok(())
    }

    fn remove_member(&self, group_name: &str, user_id: &str) -> Result<bool, AppError> {
        let conn = self.conn.lock();
        let n = conn
            .execute(
                "DELETE FROM group_members WHERE group_name = ?1 AND user_id = ?2",
                rusqlite::params![group_name, user_id],
            )
            .map_err(db_err("group: remove_member"))?;
        Ok(n > 0)
    }

    fn list_members(&self, group_name: &str) -> Result<Vec<String>, AppError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT user_id FROM group_members WHERE group_name = ?1 ORDER BY added_at")
            .map_err(db_err("group: list_members"))?;
        let rows = stmt
            .query_map(rusqlite::params![group_name], |row| row.get(0))
            .map_err(db_err("group: list_members"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(db_err("group: list_members"))
    }

    fn list_groups_for_user(&self, user_id: &str) -> Result<Vec<String>, AppError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT group_name FROM group_members WHERE user_id = ?1 ORDER BY group_name")
            .map_err(db_err("group: list_groups_for_user"))?;
        let rows = stmt
            .query_map(rusqlite::params![user_id], |row| row.get(0))
            .map_err(db_err("group: list_groups_for_user"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(db_err("group: list_groups_for_user"))
    }

    fn remove_all_memberships(&self, user_id: &str) -> Result<u64, AppError> {
        let conn = self.conn.lock();
        let n = conn
            .execute(
                "DELETE FROM group_members WHERE user_id = ?1",
                rusqlite::params![user_id],
            )
            .map_err(db_err("group: remove_all_memberships"))?;
        Ok(n as u64)
    }
}
