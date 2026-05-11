use std::sync::atomic::Ordering;

use axum::{extract::State, http::StatusCode, Json};

use crate::state::AppState;

pub async fn health() -> StatusCode {
    StatusCode::OK
}

pub async fn ready(State(state): State<AppState>) -> StatusCode {
    if state.draining.load(Ordering::SeqCst) {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    }
}

pub async fn public_key(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({"public_key": state.token_signer.public_key_hex()}))
}
