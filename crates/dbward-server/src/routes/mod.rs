use axum::{Json, Router, extract::DefaultBodyLimit, http::StatusCode, middleware};
use dbward_app::error::AppError;

use crate::state::AppState;

mod agent;
mod audit;
mod databases;
mod health;
mod metrics;
mod policies;
mod requests;
pub(crate) mod slack;
mod tokens;
mod users;
mod webhooks;

pub(crate) fn extract_audit_context(
    client_ip: Option<&crate::middleware::trusted_proxies::ClientIp>,
    connect_info: Option<&axum::extract::ConnectInfo<std::net::SocketAddr>>,
) -> dbward_domain::entities::AuditContext {
    use dbward_domain::entities::{AuditContext, ClientInfo, IpSource};
    match client_ip {
        Some(cip) => {
            let peer = connect_info.map(|ci| ci.0.ip()).unwrap_or(cip.ip);
            let source = match cip.source {
                crate::middleware::trusted_proxies::ClientIpSource::Peer => IpSource::Direct,
                crate::middleware::trusted_proxies::ClientIpSource::Xff => IpSource::Forwarded,
            };
            AuditContext::Request(ClientInfo {
                peer_ip: peer,
                client_ip: cip.ip,
                source,
            })
        }
        None => AuditContext::System,
    }
}

async fn not_implemented() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(
            serde_json::json!({"error": "not implemented", "hint": "this endpoint will be available in a future version"}),
        ),
    )
}

fn map_error(e: AppError) -> (StatusCode, Json<serde_json::Value>) {
    let status = match &e {
        AppError::Forbidden(_) => StatusCode::FORBIDDEN,
        AppError::Auth(_) => StatusCode::UNAUTHORIZED,
        AppError::NotFound(_) => StatusCode::NOT_FOUND,
        AppError::Conflict(_) => StatusCode::CONFLICT,
        AppError::Gone(_) => StatusCode::GONE,
        AppError::Validation(_) => StatusCode::BAD_REQUEST,
        AppError::PlanLimit(_) => StatusCode::PAYMENT_REQUIRED,
        AppError::PayloadTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
        AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    let code = e.code();
    let message = match &e {
        AppError::Internal(_) => "internal server error".to_string(),
        other => other.to_string(),
    };
    (
        status,
        Json(serde_json::json!({"error": message, "code": code})),
    )
}

async fn version_header(response: axum::response::Response) -> axum::response::Response {
    let mut response = response;
    response.headers_mut().insert(
        "x-dbward-version",
        env!("CARGO_PKG_VERSION").parse().unwrap(),
    );
    response
}

pub fn build_router(state: AppState) -> Router {
    let authed = Router::new()
        // Requests
        .route(
            "/api/requests",
            axum::routing::post(requests::create).get(requests::list),
        )
        .route("/api/requests/{id}", axum::routing::get(requests::get))
        .route(
            "/api/requests/{id}/approve",
            axum::routing::post(requests::approve),
        )
        .route(
            "/api/requests/{id}/reject",
            axum::routing::post(requests::reject),
        )
        .route(
            "/api/requests/{id}/cancel",
            axum::routing::post(requests::cancel),
        )
        .route(
            "/api/requests/{id}/dispatch",
            axum::routing::post(requests::dispatch),
        )
        .route(
            "/api/requests/{id}/result/stream",
            axum::routing::get(requests::stream_result),
        )
        .route(
            "/api/requests/{id}/result/content",
            axum::routing::get(requests::get_result),
        )
        // Agent
        .route("/api/agent/poll", axum::routing::post(agent::poll))
        .route(
            "/api/agent/jobs/{id}/claim",
            axum::routing::post(agent::claim),
        )
        .route(
            "/api/agent/jobs/{id}/heartbeat",
            axum::routing::post(agent::heartbeat),
        )
        .route(
            "/api/agent/jobs/{id}/result",
            axum::routing::post(agent::submit_result).layer(DefaultBodyLimit::max(
                // Headroom for JSON envelope + escaping (worst case ~2x expansion)
                state.max_persist_bytes * 2 + 2 * 1024 * 1024,
            )),
        )
        .route("/api/agents", axum::routing::get(agent::list_agents))
        // Tokens
        .route(
            "/api/tokens",
            axum::routing::post(tokens::create).get(tokens::list),
        )
        .route("/api/tokens/{id}", axum::routing::delete(tokens::revoke))
        // Users
        .route("/api/me", axum::routing::get(users::me))
        .route("/api/users", axum::routing::get(users::list))
        .route(
            "/api/users/{id}/suspend",
            axum::routing::post(users::suspend),
        )
        .route(
            "/api/users/{id}/activate",
            axum::routing::post(users::activate),
        )
        // Webhooks
        .route(
            "/api/webhooks",
            axum::routing::post(webhooks::create).get(webhooks::list),
        )
        .route(
            "/api/webhooks/{id}",
            axum::routing::get(webhooks::get)
                .put(webhooks::update)
                .delete(webhooks::delete),
        )
        .route(
            "/api/webhook-deliveries",
            axum::routing::get(webhooks::list_deliveries),
        )
        // Policies
        .route(
            "/api/workflows",
            axum::routing::post(policies::create_workflow).get(policies::list_workflows),
        )
        .route(
            "/api/workflows/{id}",
            axum::routing::delete(policies::delete_workflow),
        )
        .route(
            "/api/execution-policies",
            axum::routing::post(policies::create_execution_policy)
                .get(policies::list_execution_policies),
        )
        .route(
            "/api/execution-policies/{id}",
            axum::routing::delete(policies::delete_execution_policy),
        )
        .route(
            "/api/roles",
            axum::routing::post(policies::create_role).get(policies::list_roles),
        )
        .route(
            "/api/roles/{name}",
            axum::routing::delete(policies::delete_role),
        )
        // Result policies
        .route(
            "/api/result-policies",
            axum::routing::post(policies::create_result_policy).get(policies::list_result_policies),
        )
        .route(
            "/api/result-policies/{id}",
            axum::routing::get(policies::get_result_policy)
                .put(policies::update_result_policy)
                .delete(policies::delete_result_policy),
        )
        // Notification policies
        .route(
            "/api/notification-policies",
            axum::routing::post(policies::create_notification_policy)
                .get(policies::list_notification_policies),
        )
        .route(
            "/api/notification-policies/{id}",
            axum::routing::get(policies::get_notification_policy)
                .put(policies::update_notification_policy)
                .delete(policies::delete_notification_policy),
        )
        // Audit
        .route("/api/audit/events", axum::routing::get(audit::list_events))
        .route("/api/audit/verify", axum::routing::get(audit::verify_chain))
        // Databases
        .route("/api/databases", axum::routing::get(databases::list))
        // Public key
        .route("/api/public-key", axum::routing::get(health::public_key))
        // Stub endpoints (M-16)
        .route("/api/results", axum::routing::get(requests::list_results))
        .route(
            "/api/webhooks/{id}/test",
            axum::routing::post(not_implemented),
        )
        .route("/api/users/{id}", axum::routing::get(not_implemented))
        .route("/api/users/{id}/role", axum::routing::post(not_implemented))
        .route(
            "/api/workflows/{id}",
            axum::routing::get(not_implemented).put(not_implemented),
        )
        .route(
            "/api/execution-policies/{id}",
            axum::routing::get(not_implemented).put(not_implemented),
        )
        // Metrics (authed)
        .route("/metrics", axum::routing::get(metrics::metrics))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            super::middleware::auth::auth_middleware,
        ))
        .with_state(state.clone());

    let public = Router::new()
        .route("/health", axum::routing::get(health::health))
        .route("/ready", axum::routing::get(health::ready))
        .route(
            "/api/slack/interactions",
            axum::routing::post(slack::interactions),
        )
        .with_state(state);

    public
        .merge(authed)
        .layer(middleware::map_response(version_header))
}
