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
pub async fn create_token(
    state: &AppState,
    user: &str,
    role: Role,
) -> Result<(String, String), String> {
    let token_id = Uuid::new_v4().to_string();
    let raw_token = format!("dbw_{}", Uuid::new_v4().to_string().replace('-', ""));
    let hash = hash_token(&raw_token);
    let prefix = token_prefix(&raw_token);

    let conn = state.sqlite.lock().await;
    conn.execute(
        "INSERT INTO tokens (id, subject_type, subject_id, token_hash, token_prefix, role, status, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![token_id, "user", user, hash, prefix, role.to_string(), "active", Utc::now().to_rfc3339()],
    )
    .map_err(|e| e.to_string())?;

    Ok((token_id, raw_token))
}

/// Revoke a token by ID.
pub async fn revoke_token(state: &AppState, token_id: &str) -> Result<(), String> {
    let conn = state.sqlite.lock().await;
    let updated = conn
        .execute(
            "UPDATE tokens SET status = 'revoked', revoked_at = ?1 WHERE id = ?2",
            params![Utc::now().to_rfc3339(), token_id],
        )
        .map_err(|e| e.to_string())?;

    if updated == 0 {
        return Err("token not found".to_string());
    }
    Ok(())
}

/// Authenticate a request by extracting and verifying the Bearer token.
/// Supports both API tokens (dbw_) and OIDC JWTs (eyJ).
pub async fn authenticate(headers: &HeaderMap, state: &AppState) -> Result<AuthUser, (StatusCode, String)> {
    let header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or((StatusCode::UNAUTHORIZED, "missing Authorization header".into()))?;

    let raw_token = header
        .strip_prefix("Bearer ")
        .ok_or((StatusCode::UNAUTHORIZED, "invalid Authorization format".into()))?;

    // Route by token prefix
    if raw_token.starts_with("eyJ") {
        // JWT (OIDC)
        if state.auth_mode == "token" {
            return Err((StatusCode::UNAUTHORIZED, "OIDC not configured".into()));
        }
        let oidc = state.oidc.as_ref()
            .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "OIDC verifier not initialized".into()))?;
        let (identity, role) = oidc.verify(raw_token).await
            .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;
        Ok(AuthUser {
            token_id: format!("oidc:{identity}"),
            user: identity,
            role,
        })
    } else {
        // API token
        if state.auth_mode == "oidc" {
            return Err((StatusCode::UNAUTHORIZED, "API tokens disabled, use OIDC".into()));
        }
        authenticate_api_token(raw_token, state).await
    }
}

async fn authenticate_api_token(raw_token: &str, state: &AppState) -> Result<AuthUser, (StatusCode, String)> {
    let prefix = token_prefix(raw_token);
    let hash = hash_token(raw_token);

    let conn = state.sqlite.lock().await;

    let result: Result<(String, String, String), _> = conn.query_row(
        "SELECT id, subject_id, role FROM tokens WHERE token_prefix = ?1 AND token_hash = ?2 AND status = 'active'",
        params![prefix, hash],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    );

    match result {
        Ok((id, user, role_str)) => {
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
    use std::sync::Arc;

    fn test_state() -> AppState {
        let conn = Connection::open_in_memory().unwrap();
        db::init(&conn).unwrap();
        AppState {
            sqlite: Arc::new(tokio::sync::Mutex::new(conn)),
            token_signer: Arc::new(crate::token::TokenSigner::generate()),
            webhooks: Arc::new(crate::webhook::WebhookDispatcher::empty()),
            oidc: None,
            auth_mode: "token".to_string(),
            policy: Arc::new(Default::default()),
            result_channels: Arc::new(crate::state::ResultChannels::new()),
        }
    }

    #[tokio::test]
    async fn create_and_verify_token() {
        let state = test_state();
        let (token_id, raw_token) = create_token(&state, "alice", Role::Developer).await.unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {raw_token}").parse().unwrap());

        let user = authenticate(&headers, &state).await.unwrap();
        assert_eq!(user.user, "alice");
        assert_eq!(user.role, Role::Developer);
        assert_eq!(user.token_id, token_id);
    }

    #[tokio::test]
    async fn revoked_token_rejected() {
        let state = test_state();
        let (token_id, raw_token) = create_token(&state, "bob", Role::Admin).await.unwrap();
        revoke_token(&state, &token_id).await.unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {raw_token}").parse().unwrap());

        assert!(authenticate(&headers, &state).await.is_err());
    }

    #[tokio::test]
    async fn invalid_token_rejected() {
        let state = test_state();
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer dbw_invalid".parse().unwrap());

        assert!(authenticate(&headers, &state).await.is_err());
    }

    #[tokio::test]
    async fn wrong_token_rejected() {
        let state = test_state();
        create_token(&state, "alice", Role::Developer).await.unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer dbw_00000000aaaabbbbccccddddeeee".parse().unwrap());

        assert!(authenticate(&headers, &state).await.is_err());
    }

    #[tokio::test]
    async fn prefix_collision_still_authenticates() {
        let state = test_state();
        let (_, token_a) = create_token(&state, "alice", Role::Developer).await.unwrap();

        // Insert a second token with the same prefix but different hash
        let prefix_a = token_prefix(&token_a);
        {
            let conn = state.sqlite.lock().await;
            conn.execute(
                "INSERT INTO tokens (id, subject_type, subject_id, token_hash, token_prefix, role, status, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params!["fake-id", "user", "eve", "fakehash000", prefix_a, "admin", "active", "2024-01-01T00:00:00Z"],
            ).unwrap();
        }

        // alice's token should still work despite prefix collision
        let mut h = HeaderMap::new();
        h.insert("authorization", format!("Bearer {token_a}").parse().unwrap());
        let user = authenticate(&h, &state).await.unwrap();
        assert_eq!(user.user, "alice");
    }
}
