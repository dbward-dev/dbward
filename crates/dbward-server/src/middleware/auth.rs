use axum::{extract::Request, extract::State, http::StatusCode, middleware::Next, response::Response};
use dbward_app::error::AuthError;
use dbward_domain::auth::{AuthUser, SubjectType};
use dbward_domain::entities::{User, UserStatus};
use std::sync::Mutex;
use std::collections::HashMap;

use crate::state::AppState;

/// Cache of recent login_success audit events to avoid spamming on every request.
/// Key: subject_id, Value: last audit timestamp.
static LOGIN_AUDIT_CACHE: std::sync::LazyLock<Mutex<HashMap<String, std::time::Instant>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

fn auth_error_response(e: AuthError) -> (StatusCode, String) {
    match e {
        AuthError::Internal(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"error": "internal server error", "code": "internal_error"}).to_string(),
        ),
        _ => (
            StatusCode::UNAUTHORIZED,
            serde_json::json!({"error": "authentication failed", "code": "unauthorized"}).to_string(),
        ),
    }
}

fn log_auth_failure(state: &AppState, e: &AuthError) {
    use dbward_domain::entities::{AuditEvent, EventCategory, EventOutcome, ActorType};
    let event = AuditEvent {
        id: String::new(),
        event_type: "auth.failure".to_string(),
        event_category: EventCategory::Auth,
        event_version: 1,
        outcome: EventOutcome::Denied,
        actor_id: "anonymous".to_string(),
        actor_type: ActorType::User,
        resource_type: None,
        resource_id: None,
        peer_ip: None,
        client_ip: None,
        client_ip_source: None,
        request_id: None,
        operation: None,
        database_name: None,
        environment: None,
        detail_fingerprint: None,
        detail_raw: Some(e.to_string()),
        reason: Some(e.to_string()),
        metadata_json: "{}".to_string(),
        prev_hash: None,
        event_hash: String::new(),
        created_at: chrono::Utc::now(),
    };
    let _ = state.audit_logger.record(&event);
}

pub async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, (StatusCode, String)> {
    let token = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or((
            StatusCode::UNAUTHORIZED,
            serde_json::json!({"error": "authentication failed", "code": "unauthorized"}).to_string(),
        ))?;

    // H-17: Enforce auth_mode
    let is_jwt = token.starts_with("eyJ");
    match state.auth_mode.as_str() {
        "token" if is_jwt => return Err(auth_error_response(AuthError::OidcNotConfigured)),
        "oidc" if !is_jwt => return Err(auth_error_response(AuthError::InvalidToken)),
        _ => {}
    }

    let user = if is_jwt {
        let (subject_id, groups) = state
            .token_verifier
            .verify_oidc_token(token)
            .await
            .map_err(|e| {
                log_auth_failure(&state, &e);
                auth_error_response(e)
            })?;

        // Upsert user
        let now = chrono::Utc::now();
        let user_entity = User {
            id: subject_id.clone(),
            display_name: None,
            email: None,
            groups: groups.clone(),
            roles: vec![],
            status: UserStatus::Active,
            last_seen_at: Some(now),
            created_at: now,
            updated_at: now,
        };
        if let Err(e) = state.user_repo.upsert(&user_entity) {
            tracing::error!("user upsert failed: {e}");
            return Err(auth_error_response(AuthError::Internal("user upsert failed".into())));
        }

        // Check suspended (fail-closed: DB error → reject)
        match state.user_repo.is_suspended(&subject_id) {
            Ok(true) => {
                let e = AuthError::UserSuspended;
                log_auth_failure(&state, &e);
                return Err(auth_error_response(AuthError::UserSuspended));
            }
            Err(_) => {
                return Err(auth_error_response(AuthError::Internal("suspended check failed".into())));
            }
            Ok(false) => {}
        }

        let roles = state
            .role_resolver
            .resolve(&subject_id, SubjectType::User, &groups)
            .map_err(|e| {
                log_auth_failure(&state, &e);
                auth_error_response(e)
            })?;

        // Emit login_success audit (cached for 1 hour per subject)
        {
            let should_emit = {
                let cache = LOGIN_AUDIT_CACHE.lock().unwrap();
                cache.get(&subject_id)
                    .is_none_or(|t| t.elapsed() > std::time::Duration::from_secs(3600))
            };
            if should_emit {
                let event = dbward_domain::entities::AuditEvent::simple(
                    "login_success", "auth", &subject_id, None,
                );
                let _ = state.audit_logger.record(&event);
                let mut cache = LOGIN_AUDIT_CACHE.lock().unwrap();
                // Evict stale entries if cache is too large
                if cache.len() > 10_000 {
                    let cutoff = std::time::Duration::from_secs(3600);
                    cache.retain(|_, t| t.elapsed() < cutoff);
                }
                cache.insert(subject_id.clone(), std::time::Instant::now());
            }
        }

        AuthUser {
            subject_id,
            subject_type: SubjectType::User,
            roles,
            groups,
            token_id: None,
        }
    } else {
        state
            .token_verifier
            .verify_api_token(token)
            .await
            .map_err(|e| {
                log_auth_failure(&state, &e);
                auth_error_response(e)
            })?
    };

    req.extensions_mut().insert(user);
    Ok(next.run(req).await)
}
