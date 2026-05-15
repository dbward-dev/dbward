use axum::Json;
use axum::{Extension, extract::State, http::StatusCode, response::IntoResponse};

use crate::state::AppState;
use dbward_domain::auth::AuthUser;

pub async fn metrics(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    // Admin-only (README: admin auth required for /metrics)
    if !user.roles.iter().any(|r| {
        r.permissions
            .contains(&dbward_domain::auth::Permission::All)
    }) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "admin role required for /metrics"})),
        ));
    }

    let body = crate::metrics::render(
        &state.metrics,
        state.request_reader.as_ref(),
        state.agent_repo.as_ref(),
    );

    Ok((
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    ))
}
