use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use serde_json::json;

use crate::state::AppState;

pub(crate) async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let mut resp = json!({
        "status": "ok",
        "version": crate::VERSION,
        "api_version": crate::API_VERSION,
        "schema_version": crate::db::LATEST_SCHEMA_VERSION,
    });
    if let Some(ref v) = *state.update_available.lock().await {
        resp["update_available"] = json!(v);
    }
    Json(resp)
}

pub(crate) async fn ready(State(state): State<AppState>) -> impl IntoResponse {
    if state.draining.load(std::sync::atomic::Ordering::Relaxed) {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    let conn = state.db().await;
    match conn.query_row("SELECT 1", [], |row| row.get::<_, i64>(0)) {
        Ok(1) => StatusCode::OK,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}

pub(crate) async fn metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = crate::auth::authenticate(&headers, &state).await?;
    crate::authz::authorize(
        &user,
        crate::authz::Action::ReadMetrics,
        crate::authz::Resource::Global,
    )
    .await?;
    let body = state
        .metrics
        .render(&state.sqlite)
        .await
        .map_err(crate::api_error::ApiError::internal)?;
    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    ))
}

pub(crate) async fn get_public_key(State(state): State<AppState>) -> impl IntoResponse {
    let bytes = state.token_signer.verifying_key().to_bytes();
    (
        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
        bytes.to_vec(),
    )
}
