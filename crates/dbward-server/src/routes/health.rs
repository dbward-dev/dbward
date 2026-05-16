use std::sync::atomic::Ordering;

use axum::{
    Json,
    extract::{Extension, State},
    http::StatusCode,
};
use dbward_domain::auth::{AuthUser, SubjectType};

use crate::state::AppState;

pub async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "min_agent_version": env!("CARGO_PKG_VERSION")
    }))
}

pub async fn ready(State(state): State<AppState>) -> StatusCode {
    if state.draining.load(Ordering::SeqCst) {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    // Verify SQLite is alive
    if state.database_registry.list().is_err() {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    StatusCode::OK
}

pub async fn public_key(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if user.subject_type != SubjectType::Agent {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "agent token required", "code": "forbidden"})),
        ));
    }
    Ok(Json(
        serde_json::json!({"public_key": state.token_signer.public_key_hex()}),
    ))
}
