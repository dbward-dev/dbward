use axum::{extract::Request, extract::State, http::StatusCode, middleware::Next, response::Response};
use dbward_domain::auth::{AuthUser, SubjectType};

use crate::state::AppState;

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
        .ok_or((StatusCode::UNAUTHORIZED, "missing authorization".into()))?;

    let user = if token.starts_with("eyJ") {
        let (subject_id, groups) = state
            .token_verifier
            .verify_oidc_token(token)
            .await
            .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;
        let roles = state
            .role_resolver
            .resolve(&subject_id, SubjectType::User, &groups)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
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
            .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?
    };

    req.extensions_mut().insert(user);
    Ok(next.run(req).await)
}
