use axum::{http::StatusCode, middleware, Json, Router};
use dbward_app::error::AppError;

use crate::state::AppState;

mod agent;
mod audit;
mod databases;
mod health;
mod metrics;
mod policies;
mod requests;
mod tokens;
mod users;
mod webhooks;

fn map_error(e: AppError) -> (StatusCode, Json<serde_json::Value>) {
    let status = match &e {
        AppError::Forbidden(_) => StatusCode::FORBIDDEN,
        AppError::Auth(_) => StatusCode::UNAUTHORIZED,
        AppError::NotFound(_) => StatusCode::NOT_FOUND,
        AppError::Conflict(_) => StatusCode::CONFLICT,
        AppError::Gone(_) => StatusCode::GONE,
        AppError::Validation(_) => StatusCode::BAD_REQUEST,
        AppError::PlanLimit(_) => StatusCode::PAYMENT_REQUIRED,
        AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    let code = e.code();
    let message = match &e {
        AppError::Internal(_) => "internal server error".to_string(),
        other => other.to_string(),
    };
    (status, Json(serde_json::json!({"error": message, "code": code})))
}

async fn version_header(response: axum::response::Response) -> axum::response::Response {
    let mut response = response;
    response.headers_mut().insert("x-dbward-version", "0.1.0".parse().unwrap());
    response
}

pub fn build_router(state: AppState) -> Router {
    let authed = Router::new()
        // Requests
        .route("/api/requests", axum::routing::post(requests::create).get(requests::list))
        .route("/api/requests/{id}", axum::routing::get(requests::get))
        .route("/api/requests/{id}/approve", axum::routing::post(requests::approve))
        .route("/api/requests/{id}/reject", axum::routing::post(requests::reject))
        .route("/api/requests/{id}/cancel", axum::routing::post(requests::cancel))
        .route("/api/requests/{id}/dispatch", axum::routing::post(requests::dispatch))
        .route("/api/requests/{id}/result/stream", axum::routing::get(requests::stream_result))
        .route("/api/requests/{id}/result/content", axum::routing::get(requests::get_result))
        // Agent
        .route("/api/agent/poll", axum::routing::post(agent::poll))
        .route("/api/agent/jobs/{id}/claim", axum::routing::post(agent::claim))
        .route("/api/agent/jobs/{id}/heartbeat", axum::routing::post(agent::heartbeat))
        .route("/api/agent/jobs/{id}/result", axum::routing::post(agent::submit_result))
        .route("/api/agents", axum::routing::get(agent::list_agents))
        // Tokens
        .route("/api/tokens", axum::routing::post(tokens::create).get(tokens::list))
        .route("/api/tokens/{id}", axum::routing::delete(tokens::revoke))
        // Users
        .route("/api/users", axum::routing::get(users::list))
        .route("/api/users/{id}/suspend", axum::routing::post(users::suspend))
        .route("/api/users/{id}/activate", axum::routing::post(users::activate))
        // Webhooks
        .route("/api/webhooks", axum::routing::post(webhooks::create).get(webhooks::list))
        .route("/api/webhooks/{id}", axum::routing::get(webhooks::get).put(webhooks::update).delete(webhooks::delete))
        // Policies
        .route("/api/workflows", axum::routing::post(policies::create_workflow).get(policies::list_workflows))
        .route("/api/workflows/{id}", axum::routing::delete(policies::delete_workflow))
        .route("/api/execution-policies", axum::routing::post(policies::create_execution_policy).get(policies::list_execution_policies))
        .route("/api/execution-policies/{id}", axum::routing::delete(policies::delete_execution_policy))
        .route("/api/roles", axum::routing::post(policies::create_role).get(policies::list_roles))
        .route("/api/roles/{name}", axum::routing::delete(policies::delete_role))
        // Audit
        .route("/api/audit/events", axum::routing::get(audit::list_events))
        .route("/api/audit/verify", axum::routing::get(audit::verify_chain))
        // Databases
        .route("/api/databases", axum::routing::get(databases::list))
        // Metrics
        .route("/api/metrics", axum::routing::get(metrics::metrics))
        // Public key
        .route("/api/public-key", axum::routing::get(health::public_key))
        .layer(middleware::from_fn_with_state(state.clone(), super::middleware::auth::auth_middleware))
        .with_state(state.clone());

    let public = Router::new()
        .route("/health", axum::routing::get(health::health))
        .route("/ready", axum::routing::get(health::ready))
        .with_state(state);

    public.merge(authed)
        .layer(middleware::map_response(version_header))
}
