use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use serde::Deserialize;
use serde_json::json;

use crate::api_error::ApiError;
use crate::auth;
use crate::authz::{self, Action, Resource};
use crate::state::AppState;

#[derive(Deserialize)]
pub(crate) struct CreateTokenRequest {
    pub subject_id: String,
    #[serde(default = "default_role")]
    pub role: String,
    #[serde(default = "default_subject_type")]
    pub subject_type: String,
    pub name: Option<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    /// TTL in seconds (alternative to expires_at)
    pub expires_in: Option<u64>,
    /// Absolute expiration time (RFC 3339)
    pub expires_at: Option<String>,
}

fn default_role() -> String {
    "developer".to_string()
}
fn default_subject_type() -> String {
    "user".to_string()
}

pub(crate) async fn create_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateTokenRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::ManageToken, Resource::Global).await?;

    if body.subject_id.is_empty() {
        return Err(ApiError::bad_request("subject_id is required").with_code("validation_error"));
    }
    let valid_roles = ["admin", "developer", "readonly"];
    if !valid_roles.contains(&body.role.as_str()) {
        return Err(
            ApiError::bad_request("role must be admin, developer, or readonly")
                .with_code("validation_error"),
        );
    }
    if body.subject_type != "user" && body.subject_type != "agent" {
        return Err(ApiError::bad_request("subject_type must be user or agent")
            .with_code("validation_error"));
    }

    // Reject token creation for disabled users or role mismatch
    {
        let conn = state.db().await;
        if crate::db::user_repo::is_user_disabled(&conn, &body.subject_type, &body.subject_id)? {
            return Err(ApiError::forbidden("cannot create token for disabled user"));
        }
        // Warn if user exists with a different role
        if let Ok(Some(existing)) =
            crate::db::user_repo::get_user(&conn, &body.subject_type, &body.subject_id)
        {
            if existing.role != body.role {
                return Err(ApiError::conflict(format!(
                    "user '{}' already exists with role '{}'. Use PUT /api/users/{}/{} to change the role",
                    body.subject_id, existing.role, body.subject_type, body.subject_id
                )));
            }
        } else if crate::db::user_repo::get_user(&conn, &body.subject_type, &body.subject_id).is_err() {
            return Err(ApiError::internal("failed to verify user role"));
        }
    }

    let group_refs: Vec<&str> = body.groups.iter().map(|s| s.as_str()).collect();
    let expires_at = match (body.expires_in, &body.expires_at) {
        (Some(_), Some(_)) => {
            return Err(
                ApiError::bad_request("specify either expires_in or expires_at, not both")
                    .with_code("validation_error"),
            );
        }
        (Some(secs), None) => {
            Some((chrono::Utc::now() + chrono::Duration::seconds(secs as i64)).to_rfc3339())
        }
        (None, Some(at)) => {
            let parsed = chrono::DateTime::parse_from_rfc3339(at).map_err(|_| {
                ApiError::bad_request("expires_at must be valid RFC 3339")
                    .with_code("validation_error")
            })?;
            if parsed <= chrono::Utc::now() {
                return Err(ApiError::bad_request("expires_at must be in the future")
                    .with_code("validation_error"));
            }
            Some(parsed.to_utc().to_rfc3339())
        }
        (None, None) => None,
    };
    let (token_id, raw_token) = auth::create_token_full(
        &state,
        &body.subject_id,
        &body.role,
        &body.subject_type,
        &group_refs,
        body.name.as_deref(),
        expires_at.as_deref(),
    )
    .await
    .map_err(|e| ApiError::internal(e))?;

    // Record with caller IP (the insert in create_token_full has actor=system, no IP)
    {
        let mut conn = state.db().await;
        let meta = serde_json::json!({
            "subject_user": body.subject_id,
            "role": body.role,
            "subject_type": body.subject_type,
            "groups": body.groups,
        })
        .to_string();
        let _ = crate::db::audit_event_repo::record_audit_event(
            &mut conn,
            crate::db::audit_event_repo::AuditEvent {
                event_type: "token_created",
                event_category: "token",
                outcome: "success",
                actor_id: &user.user,
                actor_type: "user",
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
            &headers,
            &state.audit_config,
            &state.trusted_proxies,
        );
    }

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": token_id,
            "token": raw_token,
            "subject_id": body.subject_id,
            "subject_type": body.subject_type,
            "role": body.role,
            "name": body.name,
            "groups": body.groups,
            "expires_at": expires_at,
            "created_at": chrono::Utc::now().to_rfc3339(),
        })),
    ))
}

pub(crate) async fn list_tokens(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::ManageToken, Resource::Global).await?;

    let conn = state.db().await;
    let tokens = crate::db::token_repo::list_tokens(&conn)?;

    let items: Vec<serde_json::Value> = tokens
        .into_iter()
        .map(|t| {
            json!({
                "id": t.id,
                "prefix": t.prefix,
                "subject_id": t.subject_id,
                "subject_type": t.subject_type,
                "role": t.role,
                "name": t.name,
                "status": t.status,
                "groups": t.groups,
                "created_at": t.created_at,
                "expires_at": t.expires_at,
                "revoked_at": t.revoked_at,
            })
        })
        .collect();

    Ok(Json(json!({ "tokens": items })))
}

pub(crate) async fn revoke_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = auth::authenticate(&headers, &state).await?;

    // Allow self-revoke: if the token belongs to the caller, skip admin check
    let is_owner = {
        let conn = state.db().await;
        crate::db::token_repo::get_token_owner(&conn, &id)?
            .map(|owner| owner == user.user)
            .unwrap_or(false)
    };
    if !is_owner {
        authz::authorize(&user, Action::ManageToken, Resource::Global).await?;
    }

    let now = chrono::Utc::now().to_rfc3339();
    let mut conn = state.db().await;
    let found = crate::db::token_repo::revoke_token(&conn, &id, &now)?;

    if !found {
        return Err(ApiError::not_found("token not found").with_code("token_not_found"));
    }

    let meta = json!({"revoked_by": user.user, "self_revoke": is_owner}).to_string();
    let _ = crate::db::audit_event_repo::record_audit_event(
        &mut conn,
        crate::db::audit_event_repo::AuditEvent {
            event_type: "token_revoked",
            event_category: "token",
            outcome: "success",
            actor_id: &user.user,
            actor_type: "user",
            resource_type: Some("token"),
            resource_id: Some(&id),
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
        &headers,
        &state.audit_config,
        &state.trusted_proxies,
    );

    Ok(Json(json!({
        "id": id,
        "status": "revoked",
        "revoked_at": now,
    })))
}
