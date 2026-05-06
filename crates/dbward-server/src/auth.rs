use axum::http::{HeaderMap, StatusCode};
use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;

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

/// Create a new API token for a user or agent.
pub async fn create_token(
    state: &AppState,
    user: &str,
    role: &str,
) -> Result<(String, String), String> {
    create_token_with_type(state, user, role, "user").await
}

pub async fn create_token_with_groups(
    state: &AppState,
    user: &str,
    role: &str,
    groups: &[&str],
) -> Result<(String, String), String> {
    create_token_with_type_and_groups(state, user, role, "user", groups).await
}

/// Create a new API token with explicit subject_type ("user" or "agent").
pub async fn create_token_with_type(
    state: &AppState,
    user: &str,
    role: &str,
    subject_type: &str,
) -> Result<(String, String), String> {
    create_token_with_type_and_groups(state, user, role, subject_type, &[]).await
}

async fn create_token_with_type_and_groups(
    state: &AppState,
    user: &str,
    role: &str,
    subject_type: &str,
    groups: &[&str],
) -> Result<(String, String), String> {
    let token_id = Uuid::new_v4().to_string();
    let raw_token = format!("dbw_{}", Uuid::new_v4().to_string().replace('-', ""));
    let hash = hash_token(&raw_token);
    let prefix = token_prefix(&raw_token);

    let mut conn = state.sqlite.lock().await;
    crate::db::token_repo::insert_token(
        &conn,
        &token_id,
        subject_type,
        user,
        &hash,
        &prefix,
        role,
        &Utc::now().to_rfc3339(),
    )
    .map_err(|e| e.to_string())?;
    if !groups.is_empty() {
        let owned_groups: Vec<String> = groups.iter().map(|group| (*group).to_string()).collect();
        crate::db::token_repo::insert_token_groups(&conn, &token_id, &owned_groups)
            .map_err(|e| e.to_string())?;
    }

    // Audit: token_created
    let meta = serde_json::json!({"subject_user": user, "role": role, "subject_type": subject_type}).to_string();
    let _ = crate::db::audit_event_repo::insert_audit_event(
        &mut conn,
        &crate::db::audit_event_repo::AuditEvent {
            event_type: "token_created",
            event_category: "token",
            outcome: "success",
            actor_id: "system",
            actor_type: "system",
            resource_type: Some("token"),
            resource_id: Some(&token_id),
            peer_ip: None,
            client_ip: None,
            client_ip_source: None,
            request_id: None,
            operation: None,
            environment: None,
            database_name: None,
            detail_fingerprint: None,
            detail_raw: None,
            reason: None,
            metadata_json: &meta,
        },
    );

    Ok((token_id, raw_token))
}

/// Revoke a token by ID.
pub async fn revoke_token(state: &AppState, token_id: &str) -> Result<(), String> {
    let mut conn = state.sqlite.lock().await;
    let found = crate::db::token_repo::revoke_token(&conn, token_id, &Utc::now().to_rfc3339())
        .map_err(|e| e.to_string())?;
    if !found {
        return Err("token not found".to_string());
    }
    // Audit: token_revoked
    let _ = crate::db::audit_event_repo::insert_audit_event(
        &mut conn,
        &crate::db::audit_event_repo::AuditEvent {
            event_type: "token_revoked",
            event_category: "token",
            outcome: "success",
            actor_id: "system",
            actor_type: "system",
            resource_type: Some("token"),
            resource_id: Some(token_id),
            peer_ip: None,
            client_ip: None,
            client_ip_source: None,
            request_id: None,
            operation: None,
            environment: None,
            database_name: None,
            detail_fingerprint: None,
            detail_raw: None,
            reason: None,
            metadata_json: "{}",
        },
    );
    Ok(())
}

/// Authenticate a request by extracting and verifying the Bearer token.
/// Supports both API tokens (dbw_) and OIDC JWTs (eyJ).
pub async fn authenticate(
    headers: &HeaderMap,
    state: &AppState,
) -> Result<AuthUser, (StatusCode, String)> {
    let header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            state.metrics.record_auth_failure("invalid");
            (
                StatusCode::UNAUTHORIZED,
                "missing Authorization header".into(),
            )
        })?;

    let raw_token = header.strip_prefix("Bearer ").ok_or_else(|| {
        state.metrics.record_auth_failure("invalid");
        (
            StatusCode::UNAUTHORIZED,
            "invalid Authorization format".into(),
        )
    })?;

    // Route by token prefix
    if raw_token.starts_with("eyJ") {
        // JWT (OIDC)
        if state.auth_mode == "token" {
            return Err((StatusCode::UNAUTHORIZED, "OIDC not configured".into()));
        }
        let oidc = state.oidc.as_ref().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "OIDC verifier not initialized".into(),
        ))?;
        match oidc.verify(raw_token).await {
            Ok((identity, roles, groups)) => {
                // Audit: login_success
                let mut conn = state.sqlite.lock().await;
                let _ = crate::db::audit_event_repo::insert_audit_event(
                    &mut conn,
                    &crate::db::audit_event_repo::AuditEvent {
                        event_type: "login_success",
                        event_category: "auth",
                        outcome: "success",
                        actor_id: &identity,
                        actor_type: "user",
                        resource_type: None,
                        resource_id: None,
                        peer_ip: None,
                        client_ip: None,
                        client_ip_source: None,
                        request_id: None,
                        operation: None,
                        environment: None,
                        database_name: None,
                        detail_fingerprint: None,
                        detail_raw: None,
                        reason: None,
                        metadata_json: "{\"method\":\"oidc\"}",
                    },
                );
                Ok(AuthUser {
                    token_id: format!("oidc:{identity}"),
                    user: identity,
                    roles,
                    groups,
                    subject_type: "user".into(),
                })
            }
            Err(e) => {
                let reason = if e.to_ascii_lowercase().contains("expired") {
                    "expired"
                } else {
                    "invalid"
                };
                state.metrics.record_auth_failure(reason);
                // Audit: auth_failure
                let mut conn = state.sqlite.lock().await;
                let meta = serde_json::json!({"method": "oidc", "error": reason}).to_string();
                let _ = crate::db::audit_event_repo::insert_audit_event(
                    &mut conn,
                    &crate::db::audit_event_repo::AuditEvent {
                        event_type: "auth_failure",
                        event_category: "auth",
                        outcome: "failure",
                        actor_id: "unknown",
                        actor_type: "user",
                        resource_type: None,
                        resource_id: None,
                        peer_ip: None,
                        client_ip: None,
                        client_ip_source: None,
                        request_id: None,
                        operation: None,
                        environment: None,
                        database_name: None,
                        detail_fingerprint: None,
                        detail_raw: None,
                        reason: Some(reason),
                        metadata_json: &meta,
                    },
                );
                Err((StatusCode::UNAUTHORIZED, e))
            }
        }
    } else {
        // API token
        if state.auth_mode == "oidc" {
            return Err((
                StatusCode::UNAUTHORIZED,
                "API tokens disabled, use OIDC".into(),
            ));
        }
        authenticate_api_token(raw_token, state).await
    }
}

async fn authenticate_api_token(
    raw_token: &str,
    state: &AppState,
) -> Result<AuthUser, (StatusCode, String)> {
    let prefix = token_prefix(raw_token);
    let hash = hash_token(raw_token);

    let mut conn = state.sqlite.lock().await;

    match crate::db::token_repo::lookup_active_token(&conn, &prefix, &hash) {
        Ok(Some(row)) => {
            Ok(AuthUser {
                token_id: row.id,
                user: row.subject_id,
                roles: vec![row.role],
                groups: row.groups,
                subject_type: row.subject_type,
            })
        }
        Ok(None) => {
            let reason = match crate::db::token_repo::lookup_token_status(&conn, &prefix, &hash) {
                Ok(Some(status)) if status == "revoked" => "revoked",
                Ok(Some(_)) => "invalid",
                Ok(None) => "invalid",
                Err(_) => "invalid",
            };
            state.metrics.record_auth_failure(reason);
            // Audit: auth_failure
            let meta = serde_json::json!({"method": "api_token", "error": reason}).to_string();
            let _ = crate::db::audit_event_repo::insert_audit_event(
                &mut conn,
                &crate::db::audit_event_repo::AuditEvent {
                    event_type: "auth_failure",
                    event_category: "auth",
                    outcome: "failure",
                    actor_id: "unknown",
                    actor_type: "user",
                    resource_type: None,
                    resource_id: None,
                    peer_ip: None,
                    client_ip: None,
                    client_ip_source: None,
                    request_id: None,
                    operation: None,
                    environment: None,
                    database_name: None,
                    detail_fingerprint: None,
                    detail_raw: None,
                    reason: Some(reason),
                    metadata_json: &meta,
                },
            );
            Err((StatusCode::UNAUTHORIZED, "invalid token".into()))
        }
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
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
            metrics: Arc::new(crate::Metrics::new()),
            oidc: None,
            auth_mode: "token".to_string(),
            result_channels: Arc::new(crate::state::ResultChannels::new()),
            retention: Default::default(),
            request_notifier: Arc::new(crate::state::RequestNotifier::new()),
            result_store: None,
            draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            break_glass_roles: crate::server_config::default_break_glass_roles(),
        }
    }

    #[tokio::test]
    async fn create_and_verify_token() {
        let state = test_state();
        let (token_id, raw_token) = create_token(&state, "alice", "developer").await.unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            format!("Bearer {raw_token}").parse().unwrap(),
        );

        let user = authenticate(&headers, &state).await.unwrap();
        assert_eq!(user.user, "alice");
        assert_eq!(user.effective_permission(), "developer");
        assert_eq!(user.token_id, token_id);
    }

    #[tokio::test]
    async fn create_and_verify_token_with_groups() {
        let state = test_state();
        let (_, raw_token) = create_token_with_groups(
            &state,
            "alice",
            "readonly",
            &["prod-approvers", "data-team"],
        )
        .await
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            format!("Bearer {raw_token}").parse().unwrap(),
        );

        let user = authenticate(&headers, &state).await.unwrap();
        assert_eq!(user.user, "alice");
        assert_eq!(user.groups, vec!["prod-approvers", "data-team"]);
    }

    #[tokio::test]
    async fn revoked_token_rejected() {
        let state = test_state();
        let (token_id, raw_token) = create_token(&state, "bob", "admin").await.unwrap();
        revoke_token(&state, &token_id).await.unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            format!("Bearer {raw_token}").parse().unwrap(),
        );

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
        create_token(&state, "alice", "developer").await.unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer dbw_00000000aaaabbbbccccddddeeee".parse().unwrap(),
        );

        assert!(authenticate(&headers, &state).await.is_err());
    }

    #[tokio::test]
    async fn prefix_collision_still_authenticates() {
        let state = test_state();
        let (_, token_a) = create_token(&state, "alice", "developer").await.unwrap();

        // Insert a second token with the same prefix but different hash
        let prefix_a = token_prefix(&token_a);
        {
            let conn = state.sqlite.lock().await;
            crate::db::token_repo::insert_token(
                &conn,
                "fake-id",
                "user",
                "eve",
                "fakehash000",
                &prefix_a,
                "admin",
                "2024-01-01T00:00:00Z",
            )
            .unwrap();
        }

        // alice's token should still work despite prefix collision
        let mut h = HeaderMap::new();
        h.insert(
            "authorization",
            format!("Bearer {token_a}").parse().unwrap(),
        );
        let user = authenticate(&h, &state).await.unwrap();
        assert_eq!(user.user, "alice");
    }
}
