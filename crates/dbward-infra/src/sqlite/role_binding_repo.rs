use crate::sqlite::DbConn;
use crate::sqlite::error::{db_err, json_err};
use dbward_app::error::AppError;
use dbward_app::ports::RoleBindingRepo;

pub struct SqliteRoleBindingRepo {
    conn: DbConn,
}

impl SqliteRoleBindingRepo {
    pub fn new(conn: DbConn) -> Self {
        Self { conn }
    }
}

impl RoleBindingRepo for SqliteRoleBindingRepo {
    fn delete_by_source(&self, source: &str) -> Result<u64, AppError> {
        let conn = self.conn.lock();
        let n = conn
            .execute("DELETE FROM role_bindings WHERE source = ?1", [source])
            .map_err(db_err("role_binding: delete_by_source"))?;
        Ok(n as u64)
    }

    fn create(
        &self,
        id: &str,
        role: &str,
        subjects: &[String],
        groups: &[String],
        source: &str,
    ) -> Result<(), AppError> {
        let conn = self.conn.lock();
        let subjects_json =
            serde_json::to_string(subjects).map_err(json_err("role_binding: create"))?;
        let groups_json =
            serde_json::to_string(groups).map_err(json_err("role_binding: create"))?;
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO role_bindings (id, role, subjects_json, groups_json, source, lifecycle_state, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, 'active', ?6, ?7) ON CONFLICT(id) DO UPDATE SET role=excluded.role, subjects_json=excluded.subjects_json, groups_json=excluded.groups_json, lifecycle_state='active', updated_at=excluded.updated_at",
            rusqlite::params![id, role, subjects_json, groups_json, source, now, now],
        )
        .map_err(db_err("role_binding: create"))?;
        Ok(())
    }

    fn list(&self) -> Result<Vec<dbward_app::ports::RoleBindingEntry>, AppError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT id, role, subjects_json, groups_json FROM role_bindings")
            .map_err(db_err("role_binding: list"))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(db_err("role_binding: list"))?;

        let mut results = Vec::new();
        for row in rows {
            let (id, role, subj_json, grp_json) = row.map_err(db_err("role_binding: list"))?;
            let subjects: Vec<String> =
                serde_json::from_str(&subj_json).map_err(json_err("role_binding: subjects"))?;
            let groups: Vec<String> =
                serde_json::from_str(&grp_json).map_err(json_err("role_binding: groups"))?;
            results.push((id, role, subjects, groups));
        }
        Ok(results)
    }

    fn delete_stale_config(&self, active_ids: &[String]) -> Result<u64, AppError> {
        let conn = self.conn.lock();
        if active_ids.is_empty() {
            let n = conn
                .execute("DELETE FROM role_bindings WHERE source = 'config'", [])
                .map_err(db_err("role_binding: delete_stale"))?;
            return Ok(n as u64);
        }
        let placeholders: String = (1..=active_ids.len())
            .map(|i| format!("?{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "DELETE FROM role_bindings WHERE source = 'config' AND id NOT IN ({placeholders})"
        );
        let params: Vec<&dyn rusqlite::types::ToSql> = active_ids
            .iter()
            .map(|s| s as &dyn rusqlite::types::ToSql)
            .collect();
        let n = conn
            .execute(&sql, params.as_slice())
            .map_err(db_err("role_binding: delete_stale"))?;
        Ok(n as u64)
    }
}
