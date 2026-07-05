use crate::sqlite::DbConn;
use crate::sqlite::error::db_err;
use chrono::{DateTime, Utc};
use dbward_app::error::AppError;
use dbward_app::ports::UserRepo;
use dbward_domain::entities::{User, UserStatus};
use rusqlite::OptionalExtension;

pub struct SqliteUserRepo {
    conn: DbConn,
}

impl SqliteUserRepo {
    pub fn new(conn: DbConn) -> Self {
        Self { conn }
    }
}

impl UserRepo for SqliteUserRepo {
    fn get(&self, user_id: &str) -> Result<Option<User>, AppError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT id, display_name, email, roles_json, status, last_seen_at, created_at, updated_at FROM users WHERE id = ?1").map_err(db_err("user: get"))?;
        let result = stmt.query_row(rusqlite::params![user_id], |row| {
            Ok(User {
                id: row.get(0)?,
                display_name: row.get(1)?,
                email: row.get(2)?,
                groups: vec![],
                roles: serde_json::from_str::<Vec<String>>(&row.get::<_, String>(3)?)
                    .unwrap_or_default(),
                status: parse_user_status(&row.get::<_, String>(4)?),
                last_seen_at: row.get::<_, Option<String>>(5)?.and_then(|s| {
                    DateTime::parse_from_rfc3339(&s)
                        .ok()
                        .map(|d| d.with_timezone(&Utc))
                }),
                created_at: super::parse_datetime(&row.get::<_, String>(6)?)?,
                updated_at: super::parse_datetime(&row.get::<_, String>(7)?)?,
            })
        });
        match result {
            Ok(u) => Ok(Some(u)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(db_err("user: get")(e)),
        }
    }

    fn upsert(&self, user: &User) -> Result<(), AppError> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO users (id, display_name, email, roles_json, status, last_seen_at, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(id) DO UPDATE SET display_name=excluded.display_name, email=excluded.email, roles_json=excluded.roles_json, last_seen_at=excluded.last_seen_at, updated_at=excluded.updated_at",
            rusqlite::params![
                user.id, user.display_name, user.email,
                serde_json::to_string(&user.roles).unwrap(),
                status_to_str(user.status),
                user.last_seen_at.map(|d| d.to_rfc3339()),
                user.created_at.to_rfc3339(),
                user.updated_at.to_rfc3339(),
            ],
        ).map_err(db_err("user: upsert"))?;
        Ok(())
    }

    fn list(&self) -> Result<Vec<User>, AppError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT id, display_name, email, roles_json, status, last_seen_at, created_at, updated_at FROM users WHERE lifecycle_state = 'active' ORDER BY created_at DESC").map_err(db_err("user: list"))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(User {
                    id: row.get(0)?,
                    display_name: row.get(1)?,
                    email: row.get(2)?,
                    groups: vec![],
                    roles: serde_json::from_str::<Vec<String>>(&row.get::<_, String>(3)?)
                        .unwrap_or_default(),
                    status: parse_user_status(&row.get::<_, String>(4)?),
                    last_seen_at: row.get::<_, Option<String>>(5)?.and_then(|s| {
                        DateTime::parse_from_rfc3339(&s)
                            .ok()
                            .map(|d| d.with_timezone(&Utc))
                    }),
                    created_at: super::parse_datetime(&row.get::<_, String>(6)?)?,
                    updated_at: super::parse_datetime(&row.get::<_, String>(7)?)?,
                })
            })
            .map_err(db_err("user: list"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(db_err("user: list"))
    }

    fn suspend(&self, user_id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        let conn = self.conn.lock();
        let n = conn.execute("UPDATE users SET status = 'suspended', updated_at = ?1 WHERE id = ?2 AND status != 'suspended' AND lifecycle_state = 'active'", rusqlite::params![now.to_rfc3339(), user_id]).map_err(db_err("user: suspend"))?;
        Ok(n > 0)
    }

    fn activate(&self, user_id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        let conn = self.conn.lock();
        let n = conn.execute("UPDATE users SET status = 'active', updated_at = ?1 WHERE id = ?2 AND status != 'active' AND lifecycle_state = 'active'", rusqlite::params![now.to_rfc3339(), user_id]).map_err(db_err("user: activate"))?;
        Ok(n > 0)
    }

    fn is_suspended(&self, user_id: &str) -> Result<bool, AppError> {
        let conn = self.conn.lock();
        match conn.query_row(
            "SELECT status FROM users WHERE id = ?1",
            rusqlite::params![user_id],
            |r| r.get::<_, String>(0),
        ) {
            Ok(status) => Ok(status != "active"),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
            Err(e) => Err(db_err("user: is_suspended")(e)),
        }
    }

    fn ensure_exists(&self, subject_id: &str) -> Result<(), AppError> {
        let conn = self.conn.lock();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT OR IGNORE INTO users (id, roles_json, status, created_at, updated_at) VALUES (?1, '[]', 'active', ?2, ?2)",
            rusqlite::params![subject_id, now],
        ).map_err(db_err("user: ensure_exists"))?;
        Ok(())
    }

    fn update_slack_user_id(
        &self,
        subject_id: &str,
        slack_user_id: Option<&str>,
    ) -> Result<(), AppError> {
        let conn = self.conn.lock();
        let now = chrono::Utc::now().to_rfc3339();
        let result = conn.execute(
            "UPDATE users SET slack_user_id = ?1, updated_at = ?2 WHERE id = ?3",
            rusqlite::params![slack_user_id, now, subject_id],
        );
        match result {
            Ok(0) => Err(AppError::NotFound("user not found".into())),
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ffi::ErrorCode::ConstraintViolation =>
            {
                Err(AppError::Conflict(
                    "slack_user_id already linked to another user".into(),
                ))
            }
            Err(e) => Err(db_err("user: update_slack_user_id")(e)),
        }
    }

    fn get_slack_user_id(&self, subject_id: &str) -> Result<Option<String>, AppError> {
        let conn = self.conn.lock();
        conn.prepare("SELECT slack_user_id FROM users WHERE id = ?1")
            .map_err(db_err("user: get_slack_user_id"))?
            .query_row(rusqlite::params![subject_id], |row| row.get(0))
            .optional()
            .map_err(db_err("user: get_slack_user_id"))
    }

    fn find_by_slack_user_id(&self, slack_user_id: &str) -> Result<Option<String>, AppError> {
        let conn = self.conn.lock();
        let result = conn
            .prepare("SELECT id FROM users WHERE slack_user_id = ?1")
            .map_err(db_err("user: find_by_slack_user_id"))?
            .query_row(rusqlite::params![slack_user_id], |row| row.get(0))
            .optional()
            .map_err(db_err("user: find_by_slack_user_id"))?;
        Ok(result)
    }

    fn delete_by_source(&self, source: &str) -> Result<u64, AppError> {
        let conn = self.conn.lock();
        let n = conn
            .execute("DELETE FROM users WHERE source = ?1", [source])
            .map_err(db_err("user: delete_by_source"))?;
        Ok(n as u64)
    }

    fn delete_stale_config(&self, active_ids: &[String]) -> Result<u64, AppError> {
        let conn = self.conn.lock();
        if active_ids.is_empty() {
            let n = conn
                .execute("DELETE FROM users WHERE source = 'config'", [])
                .map_err(db_err("user: delete_stale"))?;
            return Ok(n as u64);
        }
        let placeholders: String = (1..=active_ids.len())
            .map(|i| format!("?{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let sql =
            format!("DELETE FROM users WHERE source = 'config' AND id NOT IN ({placeholders})");
        let params: Vec<&dyn rusqlite::types::ToSql> = active_ids
            .iter()
            .map(|s| s as &dyn rusqlite::types::ToSql)
            .collect();
        let n = conn
            .execute(&sql, params.as_slice())
            .map_err(db_err("user: delete_stale"))?;
        Ok(n as u64)
    }

    fn set_source(&self, user_id: &str, source: &str) -> Result<(), AppError> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE users SET source = ?1 WHERE id = ?2",
            rusqlite::params![source, user_id],
        )
        .map_err(db_err("user: set_source"))?;
        Ok(())
    }

    fn get_source(&self, user_id: &str) -> Result<Option<String>, AppError> {
        let conn = self.conn.lock();
        let result = conn
            .query_row(
                "SELECT source FROM users WHERE id = ?1",
                rusqlite::params![user_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(db_err("user: get_source"))?;
        Ok(result)
    }

    fn list_stale_config_ids(&self, active_ids: &[String]) -> Result<Vec<String>, AppError> {
        let conn = self.conn.lock();
        if active_ids.is_empty() {
            let mut stmt = conn
                .prepare("SELECT id FROM users WHERE source = 'config'")
                .map_err(db_err("user: list_stale_config_ids"))?;
            let rows = stmt
                .query_map([], |row| row.get(0))
                .map_err(db_err("user: list_stale_config_ids"))?;
            return rows
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_err("user: list_stale_config_ids"));
        }
        let placeholders: String = (1..=active_ids.len())
            .map(|i| format!("?{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let sql =
            format!("SELECT id FROM users WHERE source = 'config' AND id NOT IN ({placeholders})");
        let params: Vec<&dyn rusqlite::types::ToSql> = active_ids
            .iter()
            .map(|s| s as &dyn rusqlite::types::ToSql)
            .collect();
        let mut stmt = conn
            .prepare(&sql)
            .map_err(db_err("user: list_stale_config_ids"))?;
        let rows = stmt
            .query_map(params.as_slice(), |row| row.get(0))
            .map_err(db_err("user: list_stale_config_ids"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(db_err("user: list_stale_config_ids"))
    }

    fn count_active(&self) -> Result<u32, AppError> {
        let conn = self.conn.lock();
        let count: u32 = conn
            .query_row(
                "SELECT COUNT(*) FROM users WHERE lifecycle_state = 'active'",
                [],
                |row| row.get(0),
            )
            .map_err(db_err("user: count_active"))?;
        Ok(count)
    }

    fn list_active_ids(&self) -> Result<Vec<String>, AppError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT id FROM users WHERE lifecycle_state = 'active'")
            .map_err(db_err("user: list_active_ids"))?;
        let rows = stmt
            .query_map([], |row| row.get(0))
            .map_err(db_err("user: list_active_ids"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(db_err("user: list_active_ids"))
    }

    fn get_roles(&self, user_id: &str) -> Result<Vec<String>, AppError> {
        let conn = self.conn.lock();
        let json: String = conn
            .query_row(
                "SELECT roles_json FROM users WHERE id = ?1",
                rusqlite::params![user_id],
                |row| row.get(0),
            )
            .map_err(db_err("user: get_roles"))?;
        Ok(serde_json::from_str(&json).unwrap_or_default())
    }

    fn set_roles(&self, user_id: &str, roles: &[String]) -> Result<(), AppError> {
        let conn = self.conn.lock();
        let json = serde_json::to_string(roles).unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE users SET roles_json = ?1, updated_at = ?2 WHERE id = ?3",
            rusqlite::params![json, now, user_id],
        )
        .map_err(db_err("user: set_roles"))?;
        Ok(())
    }

    fn soft_delete(
        &self,
        user_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, AppError> {
        let conn = self.conn.lock();
        let n = conn
            .execute(
                "UPDATE users SET lifecycle_state = 'deleted', status = 'suspended', updated_at = ?1 WHERE id = ?2 AND lifecycle_state = 'active'",
                rusqlite::params![now.to_rfc3339(), user_id],
            )
            .map_err(db_err("user: soft_delete"))?;
        Ok(n > 0)
    }

    fn is_deleted(&self, user_id: &str) -> Result<bool, AppError> {
        let conn = self.conn.lock();
        let state: Option<String> = conn
            .query_row(
                "SELECT lifecycle_state FROM users WHERE id = ?1",
                rusqlite::params![user_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(db_err("user: is_deleted"))?;
        Ok(state.as_deref() == Some("deleted"))
    }

    fn count_admins(&self) -> Result<u32, AppError> {
        let conn = self.conn.lock();
        let count: u32 = conn
            .query_row(
                "SELECT COUNT(*) FROM users WHERE roles_json LIKE '%\"admin\"%' AND lifecycle_state = 'active' AND status = 'active'",
                [],
                |row| row.get(0),
            )
            .map_err(db_err("user: count_admins"))?;
        Ok(count)
    }
}

fn parse_user_status(s: &str) -> UserStatus {
    match s {
        "active" => UserStatus::Active,
        "suspended" => UserStatus::Suspended,
        other => {
            tracing::warn!(
                status = other,
                "unknown user status in DB, treating as suspended (fail-closed)"
            );
            UserStatus::Suspended
        }
    }
}

fn status_to_str(s: UserStatus) -> &'static str {
    match s {
        UserStatus::Active => "active",
        UserStatus::Suspended => "suspended",
    }
}
