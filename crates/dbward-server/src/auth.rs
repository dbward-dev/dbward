use axum::http::{HeaderMap, StatusCode};
use chrono::Utc;
use rusqlite::params;
use uuid::Uuid;

use dbward_core::Role;

use crate::state::{AppState, AuthUser};

/// Create a new API token for a user.
pub fn create_token(
    state: &AppState,
    user: &str,
    role: Role,
) -> Result<(String, String), String> {
    let token_id = Uuid::new_v4().to_string();
    let raw_token = format!("dbw_{}", Uuid::new_v4().to_string().replace('-', ""));
    let hash = bcrypt::hash(&raw_token, 10).map_err(|e| e.to_string())?;

    let conn = state.sqlite.lock().map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT INTO tokens (id, user, role, hash, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![token_id, user, role.to_string(), hash, Utc::now().to_rfc3339()],
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

    let conn = state
        .sqlite
        .lock()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut stmt = conn
        .prepare("SELECT id, user, role, hash FROM tokens WHERE revoked = 0")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let tokens: Vec<(String, String, String, String)> = stmt
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .filter_map(|r| r.ok())
        .collect();

    for (id, user, role_str, hash) in tokens {
        if bcrypt::verify(raw_token, &hash).unwrap_or(false) {
            let role = match role_str.as_str() {
                "admin" => Role::Admin,
                "developer" => Role::Developer,
                "readonly" => Role::Readonly,
                _ => return Err((StatusCode::INTERNAL_SERVER_ERROR, "invalid role in db".into())),
            };
            return Ok(AuthUser {
                token_id: id,
                user,
                role,
            });
        }
    }

    Err((StatusCode::UNAUTHORIZED, "invalid token".into()))
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

        let result = authenticate(&headers, &state);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_token_rejected() {
        let state = test_state();
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer dbw_invalid".parse().unwrap());

        let result = authenticate(&headers, &state);
        assert!(result.is_err());
    }
}
