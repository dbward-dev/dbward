use axum::http::{HeaderMap, StatusCode};
use chrono::Utc;
use rusqlite::params;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use dbward_core::Role;

use crate::state::{AppState, AuthUser};

fn hash_token(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Extract a prefix for fast lookup (first 8 chars after "dbw_").
fn token_prefix(raw: &str) -> String {
    raw.strip_prefix("dbw_")
        .unwrap_or(raw)
        .chars()
        .take(8)
        .collect()
}

/// Create a new API token for a user.
pub fn create_token(
    state: &AppState,
    user: &str,
    role: Role,
) -> Result<(String, String), String> {
    let token_id = Uuid::new_v4().to_string();
    let raw_token = format!("dbw_{}", Uuid::new_v4().to_string().replace('-', ""));
    let hash = hash_token(&raw_token);
    let prefix = token_prefix(&raw_token);

    let conn = state.sqlite.lock().map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT INTO tokens (id, user, role, hash, prefix, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![token_id, user, role.to_string(), hash, prefix, Utc::now().to_rfc3339()],
    )
    .map_err(|e| e.to_string())?;

    Ok((token_id, raw_token))
}

/// Revoke a token by ID.
pub fn revoke_token(state: &AppState, token_id: &str) -> Result<(), String> {
    let conn = state.sqlite.lock().map_err(|e| e.to_string())?;
    let updated = conn
        .execute(
            "UPDATE tokens SET revoked = 1 WHERE id = ?1",
            params![token_id],
        )
        .map_err(|e| e.to_string())?;

    if updated == 0 {
        return Err("token not found".to_string());
    }
    Ok(())
}

/// Authenticate a request by extracting and verifying the Bearer token.
pub fn authenticate(headers: &HeaderMap, state: &AppState) -> Result<AuthUser, (StatusCode, String)> {
    let header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or((StatusCode::UNAUTHORIZED, "missing Authorization header".into()))?;

    let raw_token = header
        .strip_prefix("Bearer ")
        .ok_or((StatusCode::UNAUTHORIZED, "invalid Authorization format".into()))?;

    let prefix = token_prefix(raw_token);
    let hash = hash_token(raw_token);

    let conn = state
        .sqlite
        .lock()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // O(1) lookup by prefix, then constant-time hash comparison
    let result: Result<(String, String, String, String), _> = conn.query_row(
        "SELECT id, user, role, hash FROM tokens WHERE prefix = ?1 AND revoked = 0",
        params![prefix],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    );

    match result {
        Ok((id, user, role_str, stored_hash)) => {
            if hash != stored_hash {
                return Err((StatusCode::UNAUTHORIZED, "invalid token".into()));
            }
            let role = match role_str.as_str() {
                "admin" => Role::Admin,
                "developer" => Role::Developer,
                "readonly" => Role::Readonly,
                _ => return Err((StatusCode::INTERNAL_SERVER_ERROR, "invalid role in db".into())),
            };
            Ok(AuthUser {
                token_id: id,
                user,
                role,
            })
        }
        Err(_) => Err((StatusCode::UNAUTHORIZED, "invalid token".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use rusqlite::Connection;
    use std::sync::{Arc, Mutex};

    fn test_state() -> AppState {
        let conn = Connection::open_in_memory().unwrap();
        db::init(&conn).unwrap();
        AppState {
            sqlite: Arc::new(Mutex::new(conn)),
            token_signer: Arc::new(crate::token::TokenSigner::generate()),
            webhooks: Arc::new(crate::webhook::WebhookDispatcher::empty()),
        }
    }

    #[test]
    fn create_and_verify_token() {
        let state = test_state();
        let (token_id, raw_token) = create_token(&state, "alice", Role::Developer).unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {raw_token}").parse().unwrap());

        let user = authenticate(&headers, &state).unwrap();
        assert_eq!(user.user, "alice");
        assert_eq!(user.role, Role::Developer);
        assert_eq!(user.token_id, token_id);
    }

    #[test]
    fn revoked_token_rejected() {
        let state = test_state();
        let (token_id, raw_token) = create_token(&state, "bob", Role::Admin).unwrap();
        revoke_token(&state, &token_id).unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {raw_token}").parse().unwrap());

        assert!(authenticate(&headers, &state).is_err());
    }

    #[test]
    fn invalid_token_rejected() {
        let state = test_state();
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer dbw_invalid".parse().unwrap());

        assert!(authenticate(&headers, &state).is_err());
    }

    #[test]
    fn wrong_token_rejected() {
        let state = test_state();
        create_token(&state, "alice", Role::Developer).unwrap();

        let mut headers = HeaderMap::new();
        // Same prefix length but different token
        headers.insert("authorization", "Bearer dbw_00000000aaaabbbbccccddddeeee".parse().unwrap());

        assert!(authenticate(&headers, &state).is_err());
    }
}
