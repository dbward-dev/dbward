use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
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
        return Err(
            ApiError::bad_request("subject_type must be user or agent")
                .with_code("validation_error"),
        );
    }

    let group_refs: Vec<&str> = body.groups.iter().map(|s| s.as_str()).collect();
    let (token_id, raw_token) = auth::create_token_full(
        &state,
        &body.subject_id,
        &body.role,
        &body.subject_type,
        &group_refs,
        body.name.as_deref(),
    )
    .await
    .map_err(|e| ApiError::internal(e))?;

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

    let conn = state.sqlite.lock().await;
    let tokens = crate::db::token_repo::list_tokens(&conn)
        .map_err(|e| ApiError::internal(e.to_string()))?;

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
    authz::authorize(&user, Action::ManageToken, Resource::Global).await?;

    let now = chrono::Utc::now().to_rfc3339();
    let conn = state.sqlite.lock().await;
    let found = crate::db::token_repo::revoke_token(&conn, &id, &now)
        .map_err(|e| ApiError::internal(e.to_string()))?;

    if !found {
        return Err(ApiError::not_found("token not found").with_code("token_not_found"));
    }

    Ok(Json(json!({
        "id": id,
        "status": "revoked",
        "revoked_at": now,
    })))
}
