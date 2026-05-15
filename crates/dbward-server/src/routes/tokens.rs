use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use chrono::{DateTime, Utc};
use dbward_app::use_cases::token_manage::{TokenCreateInput, TokenManage, TokenRevokeInput};
use dbward_domain::auth::AuthUser;
use serde::Deserialize;

use crate::middleware::trusted_proxies::ClientIp;
use crate::state::AppState;

use super::map_error;

#[derive(Deserialize)]
pub struct CreateBody {
    pub subject_id: String,
    pub subject_type: String,
    pub name: Option<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

pub async fn create(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    client_ip: Option<Extension<ClientIp>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    Json(body): Json<CreateBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let ctx = super::extract_audit_context(
        client_ip.as_ref().map(|e| &e.0),
        connect_info.as_ref().map(|e| &e.0),
    );
    let uc = TokenManage {
        authorizer: state.authorizer.clone(),
        token_repo: state.token_repo.clone(),
        user_repo: state.user_repo.clone(),
        policy_repo: state.policy_repo.clone(),
        license: state.license_checker.clone(),
        audit: state.audit_logger.clone(),
        clock: state.clock.clone(),
        id_gen: state.id_generator.clone(),
        token_gen: state.token_value_generator.clone(),
    };
    let output = uc
        .create(
            TokenCreateInput {
                subject_id: body.subject_id,
                subject_type: body.subject_type,
                name: body.name,
                roles: body.roles,
                groups: body.groups,
                expires_at: body.expires_at,
            },
            &user,
            &ctx,
        )
        .map_err(map_error)?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": output.id,
            "token": output.token,
            "prefix": output.prefix,
            "subject_id": output.subject_id,
            "expires_at": output.expires_at,
            "permissions": output.permissions,
        })),
    ))
}

pub async fn list(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let uc = TokenManage {
        authorizer: state.authorizer.clone(),
        token_repo: state.token_repo.clone(),
        user_repo: state.user_repo.clone(),
        policy_repo: state.policy_repo.clone(),
        license: state.license_checker.clone(),
        audit: state.audit_logger.clone(),
        clock: state.clock.clone(),
        id_gen: state.id_generator.clone(),
        token_gen: state.token_value_generator.clone(),
    };
    let output = uc.list(&user).map_err(map_error)?;
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({ "tokens": output.tokens })),
    ))
}

pub async fn revoke(
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
    let uc = TokenManage {
        authorizer: state.authorizer.clone(),
        token_repo: state.token_repo.clone(),
        user_repo: state.user_repo.clone(),
        policy_repo: state.policy_repo.clone(),
        license: state.license_checker.clone(),
        audit: state.audit_logger.clone(),
        clock: state.clock.clone(),
        id_gen: state.id_generator.clone(),
        token_gen: state.token_value_generator.clone(),
    };
    let output = uc
        .revoke(TokenRevokeInput { token_id: id }, &user, &ctx)
        .map_err(map_error)?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "id": output.id,
            "revoked_at": output.revoked_at,
        })),
    ))
}
