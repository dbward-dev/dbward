use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use dbward_app::use_cases::user_manage::UserSuspendInput;
use dbward_domain::auth::AuthUser;

use crate::middleware::trusted_proxies::ClientIp;
use crate::state::AppState;

use super::map_error;

pub async fn me(Extension(user): Extension<AuthUser>) -> (StatusCode, Json<serde_json::Value>) {
    let roles: Vec<serde_json::Value> = user
        .roles
        .iter()
        .map(|r| {
            serde_json::json!({
                "name": r.name,
                "permissions": r.permissions.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
                "databases": r.databases.iter().map(|d| d.as_str()).collect::<Vec<_>>(),
                "environments": r.environments.iter().map(|e| e.as_str()).collect::<Vec<_>>(),
            })
        })
        .collect();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "subject_id": user.subject_id,
            "subject_type": user.subject_type,
            "roles": roles,
            "groups": user.groups,
        })),
    )
}

pub async fn list(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let uc = state.users().manage();
    let output = uc.list(&user).map_err(map_error)?;
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({ "users": output.users })),
    ))
}

pub async fn suspend(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    client_ip: Option<Extension<ClientIp>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let ctx = super::extract_audit_context(
        client_ip.as_ref().map(|e| &e.0),
        connect_info.as_ref().map(|e| &e.0),
    );
    let uc = state.users().manage();
    let output = uc
        .suspend(
            UserSuspendInput {
                user_id: id.clone(),
            },
            &user,
            &ctx,
        )
        .map_err(map_error)?;

    // Check if user is config-managed → add warning
    let source = get_user_source(state.user_repo(), &id);
    let mut resp = serde_json::json!({
        "id": output.id,
        "revoked_tokens": output.revoked_tokens,
        "cancelled_requests": output.cancelled_requests,
    });
    if source.as_deref() == Some("config") {
        resp["warning"] = serde_json::json!(
            "this user is config-managed; status will revert to config value on next server restart"
        );
        resp["source"] = serde_json::json!("config");
    }

    Ok((StatusCode::OK, Json(resp)))
}

pub async fn activate(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    client_ip: Option<Extension<ClientIp>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let ctx = super::extract_audit_context(
        client_ip.as_ref().map(|e| &e.0),
        connect_info.as_ref().map(|e| &e.0),
    );
    let uc = state.users().manage();
    uc.activate(&id, &user, &ctx).map_err(map_error)?;

    let source = get_user_source(state.user_repo(), &id);
    let mut resp = serde_json::json!({ "id": id });
    if source.as_deref() == Some("config") {
        resp["warning"] = serde_json::json!(
            "this user is config-managed; status will revert to config value on next server restart"
        );
        resp["source"] = serde_json::json!("config");
    }
    Ok((StatusCode::OK, Json(resp)))
}

pub async fn patch(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    use dbward_domain::auth::{Permission, ResourceContext};

    for field in ["role", "roles", "groups", "subject_type", "status"] {
        if body.get(field).is_some() {
            return Err(map_error(dbward_app::error::AppError::Validation(format!(
                "cannot update field '{field}' via this endpoint"
            ))));
        }
    }

    let ctx = ResourceContext::User {
        target_id: id.clone(),
    };
    let db = dbward_domain::values::DatabaseName::wildcard();
    let env = dbward_domain::values::Environment::wildcard();
    state
        .authorizer
        .authorize_scoped(&user, Permission::UserWrite, &db, &env, &ctx)
        .map_err(|e| map_error(dbward_app::error::AppError::Forbidden(e)))?;

    let slack_user_id = match body.get("slack_user_id") {
        Some(serde_json::Value::String(s)) => {
            let valid = s.len() >= 2
                && matches!(s.as_bytes()[0], b'U' | b'W')
                && s[1..]
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit());
            if !valid {
                return Err(map_error(dbward_app::error::AppError::Validation(
                    "invalid slack_user_id format (expected ^[UW][A-Z0-9]+$)".into(),
                )));
            }
            Some(s.as_str().to_string())
        }
        Some(serde_json::Value::Null) => None,
        Some(_) => {
            return Err(map_error(dbward_app::error::AppError::Validation(
                "slack_user_id must be a string or null".into(),
            )));
        }
        None => {
            return Err(map_error(dbward_app::error::AppError::Validation(
                "no updateable fields provided".into(),
            )));
        }
    };

    state
        .users()
        .user_repo()
        .update_slack_user_id(&id, slack_user_id.as_deref())
        .map_err(map_error)?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "id": id,
            "slack_user_id": slack_user_id,
        })),
    ))
}

/// Query the source column for a user (returns None if user not found or error).
fn get_user_source(
    repo: &std::sync::Arc<dyn dbward_app::ports::UserRepo>,
    user_id: &str,
) -> Option<String> {
    repo.get_source(user_id).ok().flatten()
}
