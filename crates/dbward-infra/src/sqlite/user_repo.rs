use crate::sqlite::DbConn;
use chrono::{DateTime, Utc};
use dbward_app::error::AppError;
use dbward_app::ports::UserRepo;
use dbward_domain::entities::{User, UserStatus};

pub struct SqliteUserRepo {
    conn: DbConn,
}

impl SqliteUserRepo {
    pub fn new(conn: DbConn) -> Self { Self { conn } }
}

impl UserRepo for SqliteUserRepo {
    fn get(&self, user_id: &str) -> Result<Option<User>, AppError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT id, display_name, email, groups_json, status, last_seen_at, created_at, updated_at FROM users WHERE id = ?1").map_err(|e| AppError::Internal(e.to_string()))?;
        let result = stmt.query_row(rusqlite::params![user_id], |row| {
            Ok(User {
                id: row.get(0)?,
                display_name: row.get(1)?,
                email: row.get(2)?,
                groups: serde_json::from_str::<Vec<String>>(&row.get::<_, String>(3)?).unwrap_or_default(),
                roles: vec![],
                status: parse_user_status(&row.get::<_, String>(4)?),
                last_seen_at: row.get::<_, Option<String>>(5)?.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
                created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(6)?).unwrap().with_timezone(&Utc),
                updated_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(7)?).unwrap().with_timezone(&Utc),
            })
        });
        match result {
            Ok(u) => Ok(Some(u)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(AppError::Internal(e.to_string())),
        }
    }

    fn upsert(&self, user: &User) -> Result<(), AppError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO users (id, display_name, email, groups_json, status, last_seen_at, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(id) DO UPDATE SET display_name=excluded.display_name, email=excluded.email, groups_json=excluded.groups_json, last_seen_at=excluded.last_seen_at, updated_at=excluded.updated_at",
            rusqlite::params![
                user.id, user.display_name, user.email,
                serde_json::to_string(&user.groups).unwrap(),
                status_to_str(user.status),
                user.last_seen_at.map(|d| d.to_rfc3339()),
                user.created_at.to_rfc3339(),
                user.updated_at.to_rfc3339(),
            ],
        ).map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(())
    }

    fn list(&self) -> Result<Vec<User>, AppError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT id, display_name, email, groups_json, status, last_seen_at, created_at, updated_at FROM users ORDER BY created_at DESC").map_err(|e| AppError::Internal(e.to_string()))?;
        let rows = stmt.query_map([], |row| {
            Ok(User {
                id: row.get(0)?,
                display_name: row.get(1)?,
                email: row.get(2)?,
                groups: serde_json::from_str::<Vec<String>>(&row.get::<_, String>(3)?).unwrap_or_default(),
                roles: vec![],
                status: parse_user_status(&row.get::<_, String>(4)?),
                last_seen_at: row.get::<_, Option<String>>(5)?.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
                created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(6)?).unwrap().with_timezone(&Utc),
                updated_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(7)?).unwrap().with_timezone(&Utc),
            })
        }).map_err(|e| AppError::Internal(e.to_string()))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|e| AppError::Internal(e.to_string()))
    }

    fn suspend(&self, user_id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute("UPDATE users SET status = 'suspended', updated_at = ?1 WHERE id = ?2 AND status = 'active'", rusqlite::params![now.to_rfc3339(), user_id]).map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(n > 0)
    }

    fn activate(&self, user_id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute("UPDATE users SET status = 'active', updated_at = ?1 WHERE id = ?2 AND status = 'suspended'", rusqlite::params![now.to_rfc3339(), user_id]).map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(n > 0)
    }

    fn is_suspended(&self, user_id: &str) -> Result<bool, AppError> {
        let conn = self.conn.lock().unwrap();
        let status: Option<String> = conn.query_row("SELECT status FROM users WHERE id = ?1", rusqlite::params![user_id], |r| r.get(0)).ok();
        Ok(status.as_deref() == Some("suspended"))
    }
}

fn parse_user_status(s: &str) -> UserStatus {
    match s {
        "suspended" => UserStatus::Suspended,
        _ => UserStatus::Active,
    }
}

fn status_to_str(s: UserStatus) -> &'static str {
    match s {
        UserStatus::Active => "active",
        UserStatus::Suspended => "suspended",
    }
}
