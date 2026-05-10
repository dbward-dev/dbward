use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde_json::json;

use crate::api_error::ApiError;
use crate::auth;
use crate::authz::{self, Action, Resource};
use crate::state::AppState;

pub(crate) async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize_and_audit(&user, Action::ManageUsers, Resource::Global, &state).await?;

    let mut conn = state.db().await;
    let users = crate::db::user_repo::list_users(&conn)?;
    let items: Vec<_> = users
        .iter()
        .map(|u| {
            json!({
                "subject_type": u.subject_type,
                "subject_id": u.subject_id,
                "role": u.role,
                "disabled": u.disabled,
                "created_at": u.created_at,
            })
        })
        .collect();
    Ok(Json(json!({ "users": items })))
}

pub(crate) async fn update_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((subject_type, subject_id)): Path<(String, String)>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize_and_audit(&user, Action::ManageUsers, Resource::Global, &state).await?;

    let new_role = body["role"]
        .as_str()
        .ok_or_else(|| ApiError::bad_request("role is required"))?;

    if !["admin", "developer", "readonly"].contains(&new_role) {
        return Err(ApiError::bad_request("role must be admin, developer, or readonly"));
    }

    let mut conn = state.db().await;
    let old_role = crate::db::user_repo::update_role(&conn, &subject_type, &subject_id, new_role)?;

    match old_role {
        Some(old) => {
            crate::db::audit_event_repo::insert_audit_event(
                &mut conn,
                &crate::db::audit_event_repo::AuditEvent {
                    event_type: "user_role_changed",
                    event_category: "identity",
                    outcome: "success",
                    actor_id: &user.user,
                    actor_type: &user.subject_type,
                    resource_type: Some("user"),
                    resource_id: Some(&subject_id),
                    peer_ip: None,
                    client_ip: None,
                    client_ip_source: None,
                    request_id: None,
                    operation: None,
                    environment: None,
                    database_name: None,
                    detail_fingerprint: None,
                    detail_raw: None,
                    reason: Some(&format!("{old} → {new_role}")),
                    metadata_json: &json!({"old_role": old, "new_role": new_role}).to_string(),
                },
            )?;
            Ok(Json(json!({"subject_type": subject_type, "subject_id": subject_id, "role": new_role})))
        }
        None => Err(ApiError::not_found("user not found")),
    }
}

pub(crate) async fn disable_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((subject_type, subject_id)): Path<(String, String)>,
) -> Result<impl IntoResponse, ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize_and_audit(&user, Action::ManageUsers, Resource::Global, &state).await?;

    let mut conn = state.db().await;
    let disabled = crate::db::user_repo::disable_user(&conn, &subject_type, &subject_id)?;
    if !disabled {
        return Err(ApiError::not_found("user not found or already disabled"));
    }

    let cancelled = if subject_type == "user" {
        crate::db::user_repo::cancel_user_requests(&conn, &subject_id)?
    } else {
        0 // Agents don't create requests
    };

    crate::db::audit_event_repo::insert_audit_event(
        &mut conn,
        &crate::db::audit_event_repo::AuditEvent {
            event_type: "user_disabled",
            event_category: "identity",
            outcome: "success",
            actor_id: &user.user,
            actor_type: &user.subject_type,
            resource_type: Some("user"),
            resource_id: Some(&subject_id),
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
            metadata_json: &json!({"cancelled_requests": cancelled}).to_string(),
        },
    )?;

    Ok((
        StatusCode::OK,
        Json(json!({"disabled": true, "cancelled_requests": cancelled})),
    ))
}
