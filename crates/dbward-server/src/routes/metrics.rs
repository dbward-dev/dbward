use axum::Json;
use axum::{Extension, extract::State, http::StatusCode, response::IntoResponse};

use crate::state::AppState;
use dbward_domain::auth::AuthUser;

pub async fn metrics(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let body = state.render_metrics(&user).map_err(|_| {
        (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "metrics.view permission required"})),
        )
    })?;

    Ok((
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    ))
}
