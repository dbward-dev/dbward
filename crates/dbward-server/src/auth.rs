use axum::http::{HeaderMap, StatusCode};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant};
use tracing::{error, warn};
use uuid::Uuid;

use crate::state::{AppState, AuthUser};

const OIDC_LOGIN_SUCCESS_CACHE_TTL: Duration = Duration::from_secs(3600);

static OIDC_LOGIN_SUCCESS_CACHE: OnceLock<StdMutex<HashMap<String, Instant>>> = OnceLock::new();

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

fn best_effort_insert_audit_event(
    state: &AppState,
    event: crate::db::audit_event_repo::AuditEvent<'_>,
    headers: &HeaderMap,
) {
    if let Ok(mut conn) = state.sqlite.try_lock() {
        if let Err(e) = crate::db::audit_event_repo::record_audit_event(
            &mut conn,
            event,
            headers,
            &state.audit_config,
            &state.trusted_proxies,
        ) {
            error!(error = %e, "audit write failed");
        }
    } else {
        warn!(event_type = %event.event_type, "audit event dropped (lock contention)");
    }
}

fn should_record_oidc_login_success(raw_token: &str) -> bool {
    let cache = OIDC_LOGIN_SUCCESS_CACHE.get_or_init(|| StdMutex::new(HashMap::new()));
    let Ok(mut cache) = cache.lock() else {
        return false;
    };
    let now = Instant::now();
    cache.retain(|_, seen_at| now.duration_since(*seen_at) < OIDC_LOGIN_SUCCESS_CACHE_TTL);

    let token_key = hash_token(raw_token);
    if cache.contains_key(&token_key) {
        return false;
    }
    cache.insert(token_key, now);
    true
}

fn record_auth_failure(state: &AppState, headers: &HeaderMap, method: &str, reason: &str) {
    state.metrics.record_auth_failure(reason);
    let metadata = serde_json::json!({
        "method": method,
        "error": reason,
    })
    .to_string();
    best_effort_insert_audit_event(
        state,
        crate::db::audit_event_repo::AuditEvent {
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
            metadata_json: &metadata,
        },
        headers,
    );
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
    create_token_full(state, user, role, subject_type, groups, None, None).await
}

pub async fn create_token_full(
    state: &AppState,
    user: &str,
    role: &str,
    subject_type: &str,
    groups: &[&str],
    name: Option<&str>,
    expires_at: Option<&str>,
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
        name,
        expires_at,
        &Utc::now().to_rfc3339(),
    )
    .map_err(|e| e.to_string())?;
    if !groups.is_empty() {
        let owned_groups: Vec<String> = groups.iter().map(|group| (*group).to_string()).collect();
        crate::db::token_repo::insert_token_groups(&conn, &token_id, &owned_groups)
            .map_err(|e| e.to_string())?;
    }

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
    if let Err(e) = crate::db::audit_event_repo::insert_audit_event(&mut conn,
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
    },) {
                error!(error = %e, "audit write failed");
            }
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
            record_auth_failure(state, headers, "authorization_header", "invalid");
            (
                StatusCode::UNAUTHORIZED,
                "missing Authorization header".into(),
            )
        })?;

    let raw_token = header.strip_prefix("Bearer ").ok_or_else(|| {
        record_auth_failure(state, headers, "authorization_header", "invalid");
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
                if should_record_oidc_login_success(raw_token) {
                    best_effort_insert_audit_event(
                        state,
                        crate::db::audit_event_repo::AuditEvent {
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
                        headers,
                    );
                }
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
                record_auth_failure(state, headers, "oidc", reason);
                Err((StatusCode::UNAUTHORIZED, e))
            }
        }
    } else {
        // API token
        if state.auth_mode == "oidc" {
            // Allow agent tokens even in OIDC mode (agents can't do browser flows)
            let user = authenticate_api_token(raw_token, state, headers).await?;
            if user.subject_type != "agent" {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    "invalid token".into(),
                ));
            }
            Ok(user)
        } else {
            authenticate_api_token(raw_token, state, headers).await
        }
    }
}

async fn authenticate_api_token(
    raw_token: &str,
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthUser, (StatusCode, String)> {
    let prefix = token_prefix(raw_token);
    let hash = hash_token(raw_token);

    let conn = state.sqlite.lock().await;

    match crate::db::token_repo::lookup_active_token(&conn, &prefix, &hash) {
        Ok(Some(row)) => {
            // Reject expired tokens (parse for timezone-safe comparison)
            if let Some(ref exp) = row.expires_at {
                if let Ok(exp_time) = chrono::DateTime::parse_from_rfc3339(exp) {
                    if chrono::Utc::now() >= exp_time {
                        drop(conn);
                        record_auth_failure(state, headers, "api_token", "expired");
                        return Err((StatusCode::UNAUTHORIZED, "token expired".into()));
                    }
                } else {
                    // Unparseable expires_at: fail-closed
                    drop(conn);
                    record_auth_failure(state, headers, "api_token", "expired");
                    return Err((StatusCode::UNAUTHORIZED, "token expired".into()));
                }
            }
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
            drop(conn);
            record_auth_failure(state, headers, "api_token", reason);
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
            license: crate::license::License { plan: crate::license::Plan::Pro },
            sqlite: Arc::new(tokio::sync::Mutex::new(conn)),
            token_signer: Arc::new(crate::token::TokenSigner::generate()),
            webhooks: Arc::new(std::sync::RwLock::new(crate::webhook::WebhookDispatcher::empty())),
            metrics: Arc::new(crate::Metrics::new()),
            oidc: None,
            auth_mode: "token".to_string(),
            result_channels: Arc::new(crate::state::ResultChannels::new()),
            retention: Default::default(),
            request_notifier: Arc::new(crate::state::RequestNotifier::new()),
            result_store: None,
            draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            break_glass_roles: crate::server_config::default_break_glass_roles(),
            audit_config: Default::default(),
            trusted_proxies: vec![],
        update_available: Arc::new(tokio::sync::Mutex::new(None)),
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
                None,
                None,
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

    #[tokio::test]
    async fn oidc_mode_allows_agent_token() {
        let mut state = test_state();
        state.auth_mode = "oidc".to_string();
        let (_, token) = create_token_with_type(&state, "my-agent", "admin", "agent")
            .await
            .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        let user = authenticate(&headers, &state).await.unwrap();
        assert_eq!(user.subject_type, "agent");
    }

    #[tokio::test]
    async fn oidc_mode_rejects_user_token() {
        let mut state = test_state();
        state.auth_mode = "oidc".to_string();
        let (_, token) = create_token(&state, "alice", "developer").await.unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        let err = authenticate(&headers, &state).await.unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
        assert!(err.1.contains("invalid token"));
    }

    #[tokio::test]
    async fn oidc_mode_rejects_revoked_agent_token() {
        let mut state = test_state();
        state.auth_mode = "oidc".to_string();
        let (token_id, token) = create_token_with_type(&state, "my-agent", "admin", "agent")
            .await
            .unwrap();
        revoke_token(&state, &token_id).await.unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        let err = authenticate(&headers, &state).await.unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }
}
