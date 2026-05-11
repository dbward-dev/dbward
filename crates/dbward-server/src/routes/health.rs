use axum::{extract::State, http::StatusCode, Json};

use crate::state::AppState;

pub async fn health() -> StatusCode {
    StatusCode::OK
}

pub async fn ready() -> StatusCode {
    StatusCode::OK
}

pub async fn public_key(State(_state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({"public_key": ""}))
}
