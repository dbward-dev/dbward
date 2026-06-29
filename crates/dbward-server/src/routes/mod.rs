use axum::{
    Json, Router,
    extract::DefaultBodyLimit,
    http::{StatusCode, header},
    middleware,
};
use dbward_app::error::AppError;

use crate::state::AppState;

mod agent;
mod audit;
mod databases;
mod health;
pub(crate) mod mcp;
mod metrics;
mod policies;
mod requests;
mod schemas;
pub(crate) mod slack;
pub(crate) mod slack_messages;
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
    let hint: Option<String> = match &e {
        AppError::Forbidden(_) => Some("check your role permissions".into()),
        AppError::Conflict(_) => Some("request may have been modified concurrently".into()),
        AppError::Validation(msg) if msg == "reason_required" => {
            Some("This workflow requires a reason. Pass the 'reason' parameter.".into())
        }
        AppError::Validation(msg) => Some(msg.clone()),
        _ => None,
    };
    let message = match &e {
        AppError::Internal(_) => "internal server error".to_string(),
        AppError::Validation(msg) if msg == "reason_required" => {
            "reason is required by workflow policy".to_string()
        }
        other => other.to_string(),
    };
    (
        status,
        Json(serde_json::json!({"error": message, "code": code, "hint": hint})),
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

/// Returns 405 for config-managed resources that cannot be modified via API.
async fn config_only_405() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        Json(serde_json::json!({
            "error": "this resource is config-managed; update server.toml and restart",
            "code": "config_only"
        })),
    )
}

pub fn build_router(state: AppState) -> Router {
    let metrics_state = state.clone();
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
            "/api/requests/{id}/resume",
            axum::routing::post(requests::resume),
        )
        .route(
            "/api/requests/{id}/result/stream",
            axum::routing::get(requests::stream_result),
        )
        .route(
            "/api/requests/{id}/result/content",
            axum::routing::get(requests::get_result),
        )
        .route(
            "/api/requests/{id}/executions",
            axum::routing::get(requests::list_executions),
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
        .route(
            "/api/agent/schema-sync",
            axum::routing::post(agent::schema_sync).layer(DefaultBodyLimit::max(10 * 1024 * 1024)), // 10 MB
        )
        .route(
            "/api/agent/dry-run/{id}/claim",
            axum::routing::post(agent::dry_run_claim),
        )
        .route(
            "/api/agent/dry-run/{id}/result",
            axum::routing::post(agent::dry_run_result),
        )
        // Tokens
        .route(
            "/api/tokens",
            axum::routing::post(tokens::create).get(tokens::list),
        )
        .route("/api/tokens/{id}", axum::routing::delete(tokens::revoke))
        .route(
            "/api/tokens/{id}/inspect",
            axum::routing::get(tokens::inspect),
        )
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
            axum::routing::post(config_only_405).get(webhooks::list),
        )
        .route(
            "/api/webhooks/{id}",
            axum::routing::get(webhooks::get)
                .put(config_only_405)
                .delete(config_only_405),
        )
        .route(
            "/api/webhook-deliveries",
            axum::routing::get(webhooks::list_deliveries),
        )
        // Policies
        .route(
            "/api/workflows",
            axum::routing::post(config_only_405).get(policies::list_workflows),
        )
        .route(
            "/api/workflows/{id}",
            axum::routing::delete(config_only_405),
        )
        .route(
            "/api/execution-policies",
            axum::routing::post(config_only_405).get(policies::list_execution_policies),
        )
        .route(
            "/api/execution-policies/{id}",
            axum::routing::delete(config_only_405),
        )
        .route(
            "/api/sql-review-policies",
            axum::routing::post(config_only_405).get(policies::list_sql_review_policies),
        )
        .route(
            "/api/roles",
            axum::routing::post(config_only_405).get(policies::list_roles),
        )
        .route("/api/roles/{name}", axum::routing::delete(config_only_405))
        // Result policies
        .route(
            "/api/result-policies",
            axum::routing::post(config_only_405).get(policies::list_result_policies),
        )
        .route(
            "/api/result-policies/{id}",
            axum::routing::get(policies::get_result_policy)
                .put(config_only_405)
                .delete(config_only_405),
        )
        // Notification policies
        .route(
            "/api/notification-policies",
            axum::routing::post(config_only_405).get(policies::list_notification_policies),
        )
        .route(
            "/api/notification-policies/{id}",
            axum::routing::get(policies::get_notification_policy)
                .put(config_only_405)
                .delete(config_only_405),
        )
        // Audit
        .route("/api/audit/events", axum::routing::get(audit::list_events))
        .route("/api/audit/verify", axum::routing::get(audit::verify_chain))
        // Databases
        .route("/api/databases", axum::routing::get(databases::list))
        // Policy resolution
        .route(
            "/api/policy-resolution",
            axum::routing::get(policies::policy_resolution),
        )
        .route("/api/schemas/{db}", axum::routing::get(schemas::get_schema))
        // MCP (moved to mcp_router below for CORS support)
        // Public key
        .route("/api/public-key", axum::routing::get(health::public_key))
        // Stub endpoints (M-16)
        .route("/api/results", axum::routing::get(requests::list_results))
        .route(
            "/api/webhooks/{id}/test",
            axum::routing::post(not_implemented),
        )
        .route(
            "/api/users/{id}",
            axum::routing::get(not_implemented).patch(users::patch),
        )
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

    // MCP router: auth + optional CORS (preflight must bypass auth)
    let mcp_router = {
        use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer};
        let mcp_route = Router::new()
            .route(
                "/mcp",
                axum::routing::post(mcp::post_mcp)
                    .get(mcp::get_mcp)
                    .delete(mcp::delete_mcp),
            )
            .layer(middleware::from_fn_with_state(
                state.clone(),
                super::middleware::auth::auth_middleware,
            ));

        let cors = if state.mcp_allowed_origins.is_empty() {
            None
        } else {
            let origins: Vec<_> = state
                .mcp_allowed_origins
                .iter()
                .filter_map(|o| o.parse().ok())
                .collect();
            Some(
                CorsLayer::new()
                    .allow_origin(AllowOrigin::list(origins))
                    .allow_methods(AllowMethods::list([
                        axum::http::Method::POST,
                        axum::http::Method::GET,
                        axum::http::Method::DELETE,
                        axum::http::Method::OPTIONS,
                    ]))
                    .allow_headers(AllowHeaders::list([
                        header::AUTHORIZATION,
                        header::CONTENT_TYPE,
                        header::ACCEPT,
                        // Phase 2: session management + SSE resumption
                        "mcp-session-id".parse().unwrap(),
                        "last-event-id".parse().unwrap(),
                    ])),
            )
        };

        if let Some(cors) = cors {
            mcp_route.layer(cors).with_state(state.clone())
        } else {
            mcp_route.with_state(state.clone())
        }
    };

    let public = Router::new()
        .route("/health", axum::routing::get(health::health))
        .route("/ready", axum::routing::get(health::ready))
        .route(
            "/api/slack/interactions",
            axum::routing::post(slack::interactions),
        )
        .route("/api/slack/commands", axum::routing::post(slack::commands))
        .with_state(state);

    public
        .merge(authed)
        .merge(mcp_router)
        .layer(middleware::map_response(version_header))
        .layer(middleware::from_fn_with_state(
            metrics_state,
            super::middleware::metrics::metrics_middleware,
        ))
}
