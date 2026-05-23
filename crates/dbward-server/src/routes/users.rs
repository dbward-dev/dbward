use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use dbward_app::use_cases::user_manage::{UserManage, UserSuspendInput};
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
    let uc = UserManage {
        authorizer: state.authorizer.clone(),
        user_repo: state.user_repo.clone(),
        token_repo: state.token_repo.clone(),
        request_writer: state.request_writer.clone(),
        audit: state.audit_logger.clone(),
        clock: state.clock.clone(),
    };
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
    let uc = UserManage {
        authorizer: state.authorizer.clone(),
        user_repo: state.user_repo.clone(),
        token_repo: state.token_repo.clone(),
        request_writer: state.request_writer.clone(),
        audit: state.audit_logger.clone(),
        clock: state.clock.clone(),
    };
    let output = uc
        .suspend(UserSuspendInput { user_id: id }, &user, &ctx)
        .map_err(map_error)?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "id": output.id,
            "revoked_tokens": output.revoked_tokens,
            "cancelled_requests": output.cancelled_requests,
        })),
    ))
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
    let uc = UserManage {
        authorizer: state.authorizer.clone(),
        user_repo: state.user_repo.clone(),
        token_repo: state.token_repo.clone(),
        request_writer: state.request_writer.clone(),
        audit: state.audit_logger.clone(),
        clock: state.clock.clone(),
    };
    uc.activate(&id, &user, &ctx).map_err(map_error)?;
    Ok((StatusCode::OK, Json(serde_json::json!({ "id": id }))))
}

pub async fn patch(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    use dbward_domain::auth::Permission;

    // Forbid dangerous fields
    for field in ["role", "roles", "groups", "subject_type", "status"] {
        if body.get(field).is_some() {
            return Err(map_error(dbward_app::error::AppError::Validation(format!(
                "cannot update field '{field}' via this endpoint"
            ))));
        }
    }

    // Auth: self or UserManage
    if user.subject_id != id {
        state
            .authorizer
            .authorize_global(&user, Permission::UserManage)
            .map_err(|e| map_error(dbward_app::error::AppError::Forbidden(e)))?;
    }

    // Extract and validate slack_user_id
    let slack_user_id = match body.get("slack_user_id") {
        Some(serde_json::Value::String(s)) => {
            // Validate: ^[UW][A-Z0-9]+$
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
        .user_repo
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
