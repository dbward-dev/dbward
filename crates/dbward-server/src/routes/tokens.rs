use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use chrono::{DateTime, Utc};
use dbward_app::use_cases::token_manage::{TokenCreateInput, TokenRevokeInput};
use dbward_domain::auth::AuthUser;
use dbward_domain::entities::ScopeCeiling;
use serde::Deserialize;

use crate::middleware::trusted_proxies::ClientIp;
use crate::state::AppState;

use super::map_error;

#[derive(Deserialize)]
pub struct CreateBody {
    pub subject_id: String,
    pub subject_type: String,
    pub name: Option<String>,
    pub scope_ceiling: Option<ScopeCeilingBody>,
    /// Legacy field: converted to scope_ceiling internally (deprecated)
    #[serde(default)]
    pub roles: Option<Vec<String>>,
    /// Rejected if non-empty (token.groups is abolished)
    #[serde(default)]
    pub groups: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
pub struct ScopeCeilingBody {
    pub roles: Vec<String>,
}

pub async fn create(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    client_ip: Option<Extension<ClientIp>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    Json(body): Json<CreateBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    // Validation 8: groups field must be empty
    if !body.groups.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({"error": "token.groups is abolished; use Config [[auth.groups]] instead", "code": "validation.failed"}),
            ),
        ));
    }

    // Convert legacy roles field to scope_ceiling
    let scope_ceiling = if let Some(sc) = body.scope_ceiling {
        // Reject ambiguous input: both scope_ceiling and legacy roles specified
        if body.roles.is_some() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({"error": "cannot specify both 'scope_ceiling' and 'roles'; use 'scope_ceiling' only", "code": "validation.failed"}),
                ),
            ));
        }
        Some(ScopeCeiling { roles: sc.roles })
    } else if let Some(roles) = body.roles {
        if roles.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({"error": "roles must not be empty (use scope_ceiling instead)", "code": "validation.failed"}),
                ),
            ));
        }
        // Legacy: roles → scope_ceiling conversion (deprecated)
        tracing::warn!(
            subject_id = %body.subject_id,
            "deprecated 'roles' field used; convert to 'scope_ceiling'"
        );
        Some(ScopeCeiling { roles })
    } else {
        None
    };

    let ctx = super::extract_audit_context(
        client_ip.as_ref().map(|e| &e.0),
        connect_info.as_ref().map(|e| &e.0),
    );
    let uc = state.tokens().manage();
    let output = uc
        .create(
            TokenCreateInput {
                subject_id: body.subject_id,
                subject_type: body.subject_type,
                name: body.name,
                scope_ceiling,
                expires_at: body.expires_at,
                issued_by: Some(user.subject_id.clone()),
                groups: vec![],
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
            "scope_ceiling": output.scope_ceiling,
            "effective_roles": output.effective_roles,
            "effective_permissions": output.effective_permissions,
            "expires_at": output.expires_at,
        })),
    ))
}

pub async fn list(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let uc = state.tokens().manage();
    let output = uc.list(&user).map_err(map_error)?;
    let tokens: Vec<serde_json::Value> = output
        .tokens
        .iter()
        .map(|t| {
            serde_json::json!({
                "id": t.id,
                "subject_type": t.subject_type,
                "subject_id": t.subject_id,
                "token_prefix": t.token_prefix,
                "scope_ceiling": t.scope_ceiling,
                "name": t.name,
                "status": t.status,
                "expires_at": t.expires_at,
                "created_at": t.created_at,
                "revoked_at": t.revoked_at,
            })
        })
        .collect();
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({ "tokens": tokens })),
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
    let uc = state.tokens().manage();
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

pub async fn inspect(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    use dbward_app::error::AppError;
    use dbward_domain::auth::Permission;

    let token = state
        .token_repo()
        .get(&id)
        .map_err(map_error)?
        .ok_or_else(|| map_error(AppError::NotFound("token not found".into())))?;

    // Authorization: owner or TokenWrite
    let is_owner = token.subject_id == user.subject_id && token.subject_type == user.subject_type;
    if !is_owner {
        state
            .authorizer()
            .authorize_global(&user, Permission::TokenWrite)
            .map_err(|e| map_error(AppError::Forbidden(e)))?;
    }

    // Resolve current effective roles
    let resolved = state
        .reloadable
        .load()
        .role_resolver
        .resolve(&token.subject_id, token.subject_type, &[])
        .map_err(|e| map_error(AppError::Internal(e.to_string())))?;

    // Mirror auth middleware logic: user + ceiling=None → always 403
    let effective_roles: Vec<&str> = if token.subject_type == dbward_domain::auth::SubjectType::User
        && token.scope_ceiling.is_none()
    {
        vec![] // will always fail auth — legacy token
    } else {
        match &token.scope_ceiling {
            Some(ceiling) => resolved
                .iter()
                .filter(|r| ceiling.roles.contains(&r.name))
                .map(|r| r.name.as_str())
                .collect(),
            None => resolved.iter().map(|r| r.name.as_str()).collect(),
        }
    };

    let effective_permissions: Vec<String> = {
        let mut perms: Vec<String> = resolved
            .iter()
            .filter(|r| effective_roles.contains(&r.name.as_str()))
            .flat_map(|r| r.permissions.iter())
            .map(|p| p.as_str().to_string())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        perms.sort();
        perms
    };

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "id": token.id,
            "subject_id": token.subject_id,
            "subject_type": token.subject_type,
            "scope_ceiling": token.scope_ceiling,
            "resolved_roles": resolved.iter().map(|r| &r.name).collect::<Vec<_>>(),
            "effective_roles": effective_roles,
            "effective_permissions": effective_permissions,
            "status": token.status,
        })),
    ))
}
