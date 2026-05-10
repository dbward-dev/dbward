mod agent;
mod audit;
mod databases;
mod health;
mod policies;
pub(crate) mod requests;
pub(crate) mod results;
mod tokens;
mod users;
mod webhooks;

use axum::Router;
use axum::extract::MatchedPath;
use axum::http::Request;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{delete, get, put};
use std::time::Instant;

use crate::state::AppState;
use health::{get_public_key, health, metrics, ready};
use requests::{
    approve_request, cancel_request, create_request, dispatch_request, get_request, list_requests,
    reject_request, stream_result,
};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/metrics", get(metrics))
        .route("/api/requests", get(list_requests).post(create_request))
        .route("/api/requests/{id}", get(get_request))
        .route(
            "/api/requests/{id}/approve",
            axum::routing::post(approve_request),
        )
        .route(
            "/api/requests/{id}/reject",
            axum::routing::post(reject_request),
        )
        .route(
            "/api/requests/{id}/dispatch",
            axum::routing::post(dispatch_request),
        )
        .route(
            "/api/requests/{id}/cancel",
            axum::routing::post(cancel_request),
        )
        .route("/api/requests/{id}/result/stream", get(stream_result))
        .route(
            "/api/requests/{id}/result/content",
            get(results::get_result_content),
        )
        .route("/api/results", get(results::list_results))
        .route("/api/storage-config", get(results::get_storage_config))
        .route("/api/agent/poll", axum::routing::post(agent::agent_poll))
        .route("/api/agents", get(agent::list_agents))
        .route(
            "/api/agent/jobs/{id}/claim",
            axum::routing::post(agent::agent_claim),
        )
        .route(
            "/api/agent/jobs/{id}/heartbeat",
            axum::routing::post(agent::agent_heartbeat),
        )
        .route(
            "/api/agent/jobs/{id}/result",
            axum::routing::post(agent::agent_result),
        )
        .route("/api/audit", get(audit::list_audit))
        .route("/api/audit/events", get(audit::list_audit_events))
        .route("/api/audit/verify", get(audit::verify_audit_chain))
        .route("/api/databases", get(databases::list_databases))
        .route("/api/users", get(users::list_users))
        .route(
            "/api/users/{subject_type}/{subject_id}",
            put(users::update_user).delete(users::disable_user),
        )
        .route("/api/public-key", get(get_public_key))
        .route(
            "/api/workflows",
            get(policies::list_workflows).post(policies::create_workflow),
        )
        .route(
            "/api/workflows/{id}",
            get(policies::get_workflow)
                .put(policies::update_workflow)
                .delete(policies::delete_workflow),
        )
        .route(
            "/api/execution-policies",
            get(policies::list_execution_policies).post(policies::create_execution_policy),
        )
        .route(
            "/api/execution-policies/{id}",
            get(policies::get_execution_policy_handler)
                .put(policies::update_execution_policy)
                .delete(policies::delete_execution_policy),
        )
        .route(
            "/api/result-policies",
            get(policies::list_result_policies).post(policies::create_result_policy),
        )
        .route(
            "/api/result-policies/{id}",
            get(policies::get_result_policy_handler)
                .put(policies::update_result_policy)
                .delete(policies::delete_result_policy),
        )
        .route(
            "/api/notification-policies",
            get(policies::list_notification_policies).post(policies::create_notification_policy),
        )
        .route(
            "/api/notification-policies/{id}",
            get(policies::get_notification_policy)
                .put(policies::update_notification_policy)
                .delete(policies::delete_notification_policy),
        )
        .route(
            "/api/access-policies",
            get(policies::list_access_policies).post(policies::create_access_policy),
        )
        .route(
            "/api/access-policies/{id}",
            delete(policies::delete_access_policy),
        )
        .route(
            "/api/tokens",
            get(tokens::list_tokens).post(tokens::create_token),
        )
        .route("/api/tokens/{id}", delete(tokens::revoke_token))
        .route(
            "/api/webhooks",
            get(webhooks::list_webhooks).post(webhooks::create_webhook),
        )
        .route(
            "/api/webhooks/{id}",
            get(webhooks::get_webhook)
                .put(webhooks::update_webhook)
                .delete(webhooks::delete_webhook),
        )
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024 * 1024)) // 64MB (agent results can be up to 50MB)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            http_metrics_middleware,
        ))
        .with_state(state)
}

async fn http_metrics_middleware(
    axum::extract::State(state): axum::extract::State<AppState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let method = req.method().to_string();
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|matched| matched.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let started = Instant::now();
    let response = next.run(req).await;
    state.metrics.record_http_request(
        &method,
        &route,
        response.status().as_u16(),
        started.elapsed().as_secs_f64(),
    );
    response
}
