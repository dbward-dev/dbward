use axum::{
    extract::Request, extract::State, http::StatusCode, middleware::Next, response::Response,
};
use dbward_app::error::AuthError;
use dbward_domain::auth::{AuthUser, SubjectType};
use dbward_domain::entities::{User, UserStatus};
use std::collections::HashMap;
use std::sync::Mutex;

use crate::state::AppState;

/// Cache of recent login_success audit events to avoid spamming on every request.
/// Key: subject_id, Value: last audit timestamp.
static LOGIN_AUDIT_CACHE: std::sync::LazyLock<Mutex<HashMap<String, std::time::Instant>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

fn auth_error_response(e: AuthError) -> (StatusCode, String) {
    match e {
        AuthError::Internal(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({"error": "internal server error", "code": "internal_error"})
                .to_string(),
        ),
        AuthError::UserLimitReached => (
            StatusCode::PAYMENT_REQUIRED,
            serde_json::json!({"error": "user limit reached", "code": "policy.limit_exceeded", "hint": "contact your administrator or upgrade to Team"})
                .to_string(),
        ),
        AuthError::NoRolesResolved | AuthError::InsufficientScope => (
            StatusCode::FORBIDDEN,
            serde_json::json!({"error": "insufficient permissions", "code": e.code()})
                .to_string(),
        ),
        _ => (
            StatusCode::UNAUTHORIZED,
            serde_json::json!({"error": "authentication failed", "code": "unauthorized"})
                .to_string(),
        ),
    }
}

fn log_auth_failure(state: &AppState, e: &AuthError, req: &Request) {
    use axum::extract::ConnectInfo;
    use dbward_domain::entities::{ActorType, AuditEvent, EventCategory, EventOutcome};
    use std::net::SocketAddr;
    let peer_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip().to_string());
    let client_ip = req.extensions().get::<super::trusted_proxies::ClientIp>();
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
        peer_ip,
        client_ip: client_ip.map(|c| c.ip.to_string()),
        client_ip_source: client_ip.map(|c| c.source.as_str().to_string()),
        request_id: None,
        operation: None,
        database_name: None,
        environment: None,
        detail_fingerprint: None,
        detail_raw: Some(e.to_string()),
        reason: Some(e.to_string()),
        metadata_json: serde_json::json!({"failure_reason": e.to_string(), "code": e.code()})
            .to_string(),
        prev_hash: None,
        event_hash: String::new(),
        created_at: chrono::Utc::now(),
    };
    if let Err(e) = state.audit_logger().record(&event) {
        tracing::error!(error = %e, "failed to record auth.failure audit event");
    }
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
            serde_json::json!({"error": "authentication failed", "code": "unauthorized"})
                .to_string(),
        ))?;

    // H-17: Enforce auth_mode
    let is_jwt = token.starts_with("eyJ");
    match state.auth_mode.as_str() {
        "token" if is_jwt => return Err(auth_error_response(AuthError::OidcNotConfigured)),
        "oidc" if !is_jwt => return Err(auth_error_response(AuthError::InvalidToken)),
        _ => {}
    }

    let mut user = if is_jwt {
        let (subject_id, groups) = state
            .token_verifier
            .verify_oidc_token(token)
            .await
            .map_err(|e| {
                log_auth_failure(&state, &e, &req);
                auth_error_response(e)
            })?;

        // User limit check: block new users when at limit
        let user_exists = match state.user_repo().get(&subject_id) {
            Ok(u) => u.is_some(),
            Err(e) => {
                tracing::error!("user_repo.get failed: {e}");
                return Err(auth_error_response(AuthError::Internal(
                    "user lookup failed".into(),
                )));
            }
        };
        if !user_exists {
            let count = match state.user_repo().count_active() {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!("user_repo.count_active failed: {e}");
                    return Err(auth_error_response(AuthError::Internal(
                        "user count failed".into(),
                    )));
                }
            };
            if count >= state.license_checker().max_users() {
                let e = AuthError::UserLimitReached;
                log_auth_failure(&state, &e, &req);
                return Err(auth_error_response(e));
            }
        }

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
        if let Err(e) = state.user_repo().upsert(&user_entity) {
            tracing::error!("user upsert failed: {e}");
            return Err(auth_error_response(AuthError::Internal(
                "user upsert failed".into(),
            )));
        }

        // Check suspended (fail-closed: DB error → reject)
        match state.user_repo().is_suspended(&subject_id) {
            Ok(true) => {
                let e = AuthError::UserSuspended;
                log_auth_failure(&state, &e, &req);
                return Err(auth_error_response(AuthError::UserSuspended));
            }
            Err(_) => {
                return Err(auth_error_response(AuthError::Internal(
                    "suspended check failed".into(),
                )));
            }
            Ok(false) => {}
        }

        let roles = state
            .reloadable
            .load()
            .role_resolver
            .resolve(&subject_id, SubjectType::User, &groups)
            .map_err(|e| {
                log_auth_failure(&state, &e, &req);
                auth_error_response(e)
            })?;

        if roles.is_empty() {
            let e = AuthError::NoRolesResolved;
            log_auth_failure(&state, &e, &req);
            return Err(auth_error_response(e));
        }

        // Emit login_success audit (cached for 1 hour per subject)
        {
            let should_emit = {
                let cache = LOGIN_AUDIT_CACHE.lock().unwrap();
                cache
                    .get(&subject_id)
                    .is_none_or(|t| t.elapsed() > std::time::Duration::from_secs(3600))
            };
            if should_emit {
                use axum::extract::ConnectInfo;
                use dbward_domain::entities::{AuditContext, ClientInfo, IpSource};
                use std::net::SocketAddr;
                let ctx = match req.extensions().get::<super::trusted_proxies::ClientIp>() {
                    Some(cip) => {
                        let peer = req
                            .extensions()
                            .get::<ConnectInfo<SocketAddr>>()
                            .map(|ci| ci.0.ip())
                            .unwrap_or(cip.ip);
                        let source = match cip.source {
                            super::trusted_proxies::ClientIpSource::Peer => IpSource::Direct,
                            super::trusted_proxies::ClientIpSource::Xff => IpSource::Forwarded,
                        };
                        AuditContext::Request(ClientInfo {
                            peer_ip: peer,
                            client_ip: cip.ip,
                            source,
                        })
                    }
                    None => AuditContext::System,
                };
                let event = dbward_domain::entities::AuditEvent::simple(
                    "auth.login_success",
                    "auth",
                    &subject_id,
                    None,
                    state.clock().now(),
                    &ctx,
                );
                if let Err(e) = state.audit_logger().record(&event) {
                    tracing::error!(error = %e, "failed to record login_success audit event");
                } else {
                    let mut cache = LOGIN_AUDIT_CACHE.lock().unwrap();
                    // Evict stale entries if cache is too large
                    if cache.len() > 10_000 {
                        let cutoff = std::time::Duration::from_secs(3600);
                        cache.retain(|_, t| t.elapsed() < cutoff);
                    }
                    cache.insert(subject_id.clone(), std::time::Instant::now());
                }
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
        // API Token path (NEW: VerifiedToken → role resolution → ceiling → AuthUser)
        let verified = state
            .token_verifier
            .verify_api_token(token)
            .await
            .map_err(|e| {
                log_auth_failure(&state, &e, &req);
                auth_error_response(e)
            })?;

        // Suspended check (user only; agents have no user record)
        if verified.subject_type == SubjectType::User {
            match state.user_repo().is_suspended(&verified.subject_id) {
                Ok(true) => {
                    let e = AuthError::UserSuspended;
                    log_auth_failure(&state, &e, &req);
                    return Err(auth_error_response(e));
                }
                Err(_) => {
                    return Err(auth_error_response(AuthError::Internal(
                        "suspended check failed".into(),
                    )));
                }
                Ok(false) => {}
            }
        }

        // Role resolution (empty groups — Config membership is resolved internally)
        let resolved_roles = state
            .reloadable
            .load()
            .role_resolver
            .resolve(&verified.subject_id, verified.subject_type, &[])
            .map_err(|e| {
                log_auth_failure(&state, &e, &req);
                auth_error_response(e)
            })?;

        // Groups for AuthUser (approval matching): Config groups only
        let groups = state
            .reloadable
            .load()
            .role_resolver
            .config_groups_for(&verified.subject_id)
            .cloned()
            .unwrap_or_default();

        // scope_ceiling application
        let effective_roles = match &verified.scope_ceiling {
            Some(ceiling) if ceiling.roles.is_empty() => {
                let e = AuthError::InsufficientScope;
                log_auth_failure(&state, &e, &req);
                return Err(auth_error_response(e));
            }
            Some(ceiling) => {
                let filtered: Vec<_> = resolved_roles
                    .into_iter()
                    .filter(|r| ceiling.roles.contains(&r.name))
                    .collect();
                if filtered.is_empty() {
                    let e = AuthError::InsufficientScope;
                    log_auth_failure(&state, &e, &req);
                    return Err(auth_error_response(e));
                }
                filtered
            }
            None => {
                // scope_ceiling=None: agent only. User tokens with NULL ceiling are fail-closed.
                if verified.subject_type == SubjectType::User {
                    let e = AuthError::InsufficientScope;
                    log_auth_failure(&state, &e, &req);
                    return Err(auth_error_response(e));
                }
                if resolved_roles.is_empty() {
                    let e = AuthError::NoRolesResolved;
                    log_auth_failure(&state, &e, &req);
                    return Err(auth_error_response(e));
                }
                resolved_roles
            }
        };

        AuthUser {
            subject_id: verified.subject_id,
            subject_type: verified.subject_type,
            roles: effective_roles,
            groups,
            token_id: Some(verified.id),
        }
    };

    // Post-auth: user limit + ensure_exists (only after successful auth)
    if user.subject_type == SubjectType::User && user.token_id.is_some() {
        let user_exists = match state.user_repo().get(&user.subject_id) {
            Ok(u) => u.is_some(),
            Err(e) => {
                tracing::error!("user_repo.get failed: {e}");
                return Err(auth_error_response(AuthError::Internal(
                    "user lookup failed".into(),
                )));
            }
        };
        if !user_exists {
            let count = match state.user_repo().count_active() {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!("user_repo.count_active failed: {e}");
                    return Err(auth_error_response(AuthError::Internal(
                        "user count failed".into(),
                    )));
                }
            };
            if count >= state.license_checker().max_users() {
                let e = AuthError::UserLimitReached;
                log_auth_failure(&state, &e, &req);
                return Err(auth_error_response(e));
            }
        }
        if let Err(e) = state.user_repo().ensure_exists(&user.subject_id) {
            tracing::error!("user ensure_exists failed: {e}");
            return Err(auth_error_response(AuthError::Internal(
                "user record creation failed".into(),
            )));
        }
    }

    // Augment AuthUser.groups with TOML [[auth.groups]] membership
    if let Some(config_groups) = state
        .reloadable
        .load()
        .role_resolver
        .config_groups_for(&user.subject_id)
    {
        for g in config_groups {
            if !user.groups.contains(g) {
                user.groups.push(g.clone());
            }
        }
    }

    req.extensions_mut().insert(user.clone());

    // Agent tokens are restricted to agent-specific endpoints only
    if user.subject_type == SubjectType::Agent {
        let path = req.uri().path();
        if !path.starts_with("/api/agent/") && path != "/api/public-key" {
            return Err((
                StatusCode::FORBIDDEN,
                serde_json::json!({"error": "agent tokens cannot access this endpoint", "code": "forbidden"}).to_string(),
            ));
        }
    }

    Ok(next.run(req).await)
}
