use axum::{extract::Request, extract::State, http::StatusCode, middleware::Next, response::Response};
use dbward_app::error::AuthError;
use dbward_domain::auth::{AuthUser, SubjectType};

use crate::state::AppState;

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

    let user = if token.starts_with("eyJ") {
        let (subject_id, groups) = state
            .token_verifier
            .verify_oidc_token(token)
            .await
            .map_err(auth_error_response)?;
        let roles = state
            .role_resolver
            .resolve(&subject_id, SubjectType::User, &groups)
            .map_err(auth_error_response)?;
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
            .map_err(auth_error_response)?
    };

    req.extensions_mut().insert(user);
    Ok(next.run(req).await)
}
