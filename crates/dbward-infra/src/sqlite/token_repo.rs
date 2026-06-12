use crate::sqlite::DbConn;
use crate::sqlite::error::db_err;
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
        let conn = self.conn.lock();
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
        ).map_err(db_err("token: create"))?;
        Ok(())
    }

    fn verify(&self, prefix: &str, hash: &str) -> Result<Option<Token>, AppError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, subject_type, subject_id, token_hash, token_prefix, roles_json, groups_json, name, status, expires_at, created_at, revoked_at FROM tokens WHERE token_prefix = ?1 AND status = 'active'",
        ).map_err(db_err("token: verify"))?;
        let rows = stmt
            .query_map(rusqlite::params![prefix], row_to_token)
            .map_err(db_err("token: verify"))?;

        use subtle::ConstantTimeEq;
        for row in rows {
            let token = row.map_err(db_err("token: verify"))?;
            if token.token_hash.as_bytes().ct_eq(hash.as_bytes()).into() {
                return Ok(Some(token));
            }
        }
        Ok(None)
    }

    fn list(&self) -> Result<Vec<Token>, AppError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, subject_type, subject_id, token_hash, token_prefix, roles_json, groups_json, name, status, expires_at, created_at, revoked_at FROM tokens",
        ).map_err(db_err("token: list"))?;
        let rows = stmt
            .query_map([], row_to_token)
            .map_err(db_err("token: list"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(db_err("token: list"))
    }

    fn get(&self, token_id: &str) -> Result<Option<Token>, AppError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, subject_type, subject_id, token_hash, token_prefix, roles_json, groups_json, name, status, expires_at, created_at, revoked_at FROM tokens WHERE id = ?1",
        ).map_err(db_err("token: get"))?;
        let result = stmt.query_row(rusqlite::params![token_id], row_to_token);
        match result {
            Ok(t) => Ok(Some(t)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(db_err("token: get")(e)),
        }
    }

    fn revoke(&self, token_id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        let conn = self.conn.lock();
        let n = conn.execute(
            "UPDATE tokens SET status = 'revoked', revoked_at = ?1 WHERE id = ?2 AND status = 'active'",
            rusqlite::params![now.to_rfc3339(), token_id],
        ).map_err(db_err("token: revoke"))?;
        Ok(n > 0)
    }

    fn revoke_all_for_user(&self, subject_id: &str, now: DateTime<Utc>) -> Result<u32, AppError> {
        let conn = self.conn.lock();
        let n = conn.execute(
            "UPDATE tokens SET status = 'revoked', revoked_at = ?1 WHERE subject_id = ?2 AND status = 'active'",
            rusqlite::params![now.to_rfc3339(), subject_id],
        ).map_err(db_err("token: revoke_all_for_user"))?;
        Ok(n as u32)
    }

    fn count_active(&self) -> Result<u32, AppError> {
        let conn = self.conn.lock();
        let count: u32 = conn
            .query_row(
                "SELECT COUNT(*) FROM tokens WHERE status = 'active'",
                [],
                |row| row.get(0),
            )
            .map_err(db_err("token: count_active"))?;
        Ok(count)
    }

    fn purge_revoked(&self, before: &str) -> Result<u32, AppError> {
        let conn = self.conn.lock();
        let n = conn
            .execute(
                "DELETE FROM tokens WHERE status = 'revoked' AND revoked_at < ?1",
                rusqlite::params![before],
            )
            .map_err(db_err("token: purge_revoked"))?;
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
        roles: serde_json::from_str(&roles_json).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(5, rusqlite::types::Type::Text, Box::new(e))
        })?,
        groups: serde_json::from_str(&groups_json).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(6, rusqlite::types::Type::Text, Box::new(e))
        })?,
        name: row.get(7)?,
        status: parse_token_status(&status_s),
        expires_at: expires_str.and_then(|s| {
            DateTime::parse_from_rfc3339(&s)
                .ok()
                .map(|d| d.with_timezone(&Utc))
        }),
        created_at: super::parse_datetime(&created_str)?,
        revoked_at: revoked_str.and_then(|s| {
            DateTime::parse_from_rfc3339(&s)
                .ok()
                .map(|d| d.with_timezone(&Utc))
        }),
    })
}
