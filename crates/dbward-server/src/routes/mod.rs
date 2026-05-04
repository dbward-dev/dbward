mod agent;
mod audit;
mod policies;
mod requests;

use axum::Router;
use axum::routing::get;

use crate::state::AppState;
use requests::{
    approve_request, create_request, dispatch_request, get_public_key, get_request, health,
    list_requests, reject_request, stream_result,
};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
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
        .route("/api/requests/{id}/result/stream", get(stream_result))
        .route("/api/agent/poll", axum::routing::post(agent::agent_poll))
        .route(
            "/api/agent/jobs/{id}/claim",
            axum::routing::post(agent::agent_claim),
        )
        .route(
            "/api/agent/jobs/{id}/result",
            axum::routing::post(agent::agent_result),
        )
        .route("/api/audit", get(audit::list_audit))
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
        .with_state(state)
}
