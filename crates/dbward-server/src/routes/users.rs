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
    let role_names: Vec<&str> = user.roles.iter().map(|r| r.name.as_str()).collect();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "subject_id": user.subject_id,
            "subject_type": user.subject_type,
            "roles": role_names,
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
        request_repo: state.request_repo.clone(),
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
        request_repo: state.request_repo.clone(),
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
        request_repo: state.request_repo.clone(),
        audit: state.audit_logger.clone(),
        clock: state.clock.clone(),
    };
    uc.activate(&id, &user, &ctx).map_err(map_error)?;
    Ok((StatusCode::OK, Json(serde_json::json!({ "id": id }))))
}
