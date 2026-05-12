use crate::sqlite::DbConn;
use chrono::{DateTime, Utc};
use dbward_app::error::AppError;
use dbward_app::ports::TokenRepo;
use dbward_domain::auth::SubjectType;
use dbward_domain::entities::{Token, TokenStatus};

pub struct SqliteTokenRepo {
    conn: DbConn,
}

impl SqliteTokenRepo {
    pub fn new(conn: DbConn) -> Self {
        Self { conn }
    }
}

impl TokenRepo for SqliteTokenRepo {
    fn create(&self, token: &Token) -> Result<(), AppError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO tokens (id, subject_type, subject_id, token_hash, token_prefix, roles_json, groups_json, name, status, expires_at, created_at, revoked_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            rusqlite::params![
                token.id,
                subject_type_str(token.subject_type),
                token.subject_id,
                token.token_hash,
                token.token_prefix,
                serde_json::to_string(&token.roles).unwrap(),
                serde_json::to_string(&token.groups).unwrap(),
                token.name,
                token_status_str(token.status),
                token.expires_at.map(|t| t.to_rfc3339()),
                token.created_at.to_rfc3339(),
                token.revoked_at.map(|t| t.to_rfc3339()),
            ],
        ).map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(())
    }

    fn verify(&self, prefix: &str, hash: &str) -> Result<Option<Token>, AppError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, subject_type, subject_id, token_hash, token_prefix, roles_json, groups_json, name, status, expires_at, created_at, revoked_at FROM tokens WHERE token_prefix = ?1 AND token_hash = ?2 AND status = 'active'",
        ).map_err(|e| AppError::Internal(e.to_string()))?;
        let result = stmt.query_row(rusqlite::params![prefix, hash], row_to_token);
        match result {
            Ok(t) => Ok(Some(t)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(AppError::Internal(e.to_string())),
        }
    }

    fn list(&self) -> Result<Vec<Token>, AppError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, subject_type, subject_id, token_hash, token_prefix, roles_json, groups_json, name, status, expires_at, created_at, revoked_at FROM tokens",
        ).map_err(|e| AppError::Internal(e.to_string()))?;
        let rows = stmt.query_map([], row_to_token).map_err(|e| AppError::Internal(e.to_string()))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|e| AppError::Internal(e.to_string()))
    }

    fn get(&self, token_id: &str) -> Result<Option<Token>, AppError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, subject_type, subject_id, token_hash, token_prefix, roles_json, groups_json, name, status, expires_at, created_at, revoked_at FROM tokens WHERE id = ?1",
        ).map_err(|e| AppError::Internal(e.to_string()))?;
        let result = stmt.query_row(rusqlite::params![token_id], row_to_token);
        match result {
            Ok(t) => Ok(Some(t)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(AppError::Internal(e.to_string())),
        }
    }

    fn revoke(&self, token_id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "UPDATE tokens SET status = 'revoked', revoked_at = ?1 WHERE id = ?2 AND status = 'active'",
            rusqlite::params![now.to_rfc3339(), token_id],
        ).map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(n > 0)
    }

    fn revoke_all_for_user(&self, subject_id: &str, now: DateTime<Utc>) -> Result<u32, AppError> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "UPDATE tokens SET status = 'revoked', revoked_at = ?1 WHERE subject_id = ?2 AND status = 'active'",
            rusqlite::params![now.to_rfc3339(), subject_id],
        ).map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(n as u32)
    }

    fn count_active(&self) -> Result<u32, AppError> {
        let conn = self.conn.lock().unwrap();
        let count: u32 = conn.query_row("SELECT COUNT(*) FROM tokens WHERE status = 'active'", [], |row| row.get(0))
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(count)
    }

    fn purge_revoked(&self, before: &str) -> Result<u32, AppError> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "DELETE FROM tokens WHERE status = 'revoked' AND revoked_at < ?1",
            rusqlite::params![before],
        ).map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(n as u32)
    }
}

fn subject_type_str(s: SubjectType) -> &'static str {
    match s {
        SubjectType::User => "user",
        SubjectType::Agent => "agent",
    }
}

fn parse_subject_type(s: &str) -> SubjectType {
    match s {
        "agent" => SubjectType::Agent,
        _ => SubjectType::User,
    }
}

fn token_status_str(s: TokenStatus) -> &'static str {
    match s {
        TokenStatus::Active => "active",
        TokenStatus::Revoked => "revoked",
    }
}

fn parse_token_status(s: &str) -> TokenStatus {
    match s {
        "revoked" => TokenStatus::Revoked,
        _ => TokenStatus::Active,
    }
}

fn row_to_token(row: &rusqlite::Row) -> rusqlite::Result<Token> {
    let subject_type_s: String = row.get(1)?;
    let roles_json: String = row.get(5)?;
    let groups_json: String = row.get(6)?;
    let status_s: String = row.get(8)?;
    let expires_str: Option<String> = row.get(9)?;
    let created_str: String = row.get(10)?;
    let revoked_str: Option<String> = row.get(11)?;

    Ok(Token {
        id: row.get(0)?,
        subject_type: parse_subject_type(&subject_type_s),
        subject_id: row.get(2)?,
        token_hash: row.get(3)?,
        token_prefix: row.get(4)?,
        roles: serde_json::from_str(&roles_json).unwrap_or_default(),
        groups: serde_json::from_str(&groups_json).unwrap_or_default(),
        name: row.get(7)?,
        status: parse_token_status(&status_s),
        expires_at: expires_str.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
        created_at: DateTime::parse_from_rfc3339(&created_str).unwrap().with_timezone(&Utc),
        revoked_at: revoked_str.and_then(|s| DateTime::parse_from_rfc3339(&s).ok().map(|d| d.with_timezone(&Utc))),
    })
}
