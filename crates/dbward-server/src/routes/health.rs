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

pub async fn ready(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    if state.draining.load(Ordering::SeqCst) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"status": "draining"})),
        );
    }

    let mut checks = serde_json::Map::new();
    let mut all_ok = true;

    match state.database_registry().list_active() {
        Ok(_) => {
            checks.insert("sqlite".into(), serde_json::json!("ok"));
        }
        Err(e) => {
            tracing::warn!(error = %e, "readiness: sqlite check failed");
            checks.insert("sqlite".into(), serde_json::json!("unavailable"));
            all_ok = false;
        }
    }

    match state.result_store().health_check().await {
        Ok(()) => {
            checks.insert("result_store".into(), serde_json::json!("ok"));
        }
        Err(e) => {
            tracing::warn!(error = %e, "readiness: result_store check failed");
            checks.insert("result_store".into(), serde_json::json!("unavailable"));
            all_ok = false;
        }
    }

    let status = if all_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let status_str = if all_ok { "ok" } else { "degraded" };
    (
        status,
        Json(serde_json::json!({"status": status_str, "checks": checks})),
    )
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
        serde_json::json!({"public_key": state.token_signer().public_key_hex()}),
    ))
}
