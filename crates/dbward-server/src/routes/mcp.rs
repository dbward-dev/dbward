use axum::Extension;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;

use dbward_domain::auth::AuthUser;
use dbward_mcp::handler;
use dbward_mcp::ports::NoopElicitation;
use dbward_mcp::protocol::JsonRpcResponse;

use crate::mcp_backend::ServerMcpBackend;
use crate::middleware::trusted_proxies::ClientIp;
use crate::state::AppState;

/// POST /mcp — MCP JSON-RPC endpoint.
pub(crate) async fn post_mcp(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    client_ip: Option<Extension<ClientIp>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if !state.mcp_enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    // Content-Type check
    match headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    {
        Some(ct) if ct.contains("application/json") => {}
        _ => return (StatusCode::UNSUPPORTED_MEDIA_TYPE, Vec::new()).into_response(),
    }

    // Accept check (Phase 1: only application/json is supported)
    if let Some(accept) = headers.get(header::ACCEPT) {
        let accept_str = accept.to_str().unwrap_or("");
        if !accept_str.contains("application/json") && !accept_str.contains("*/*") {
            return (StatusCode::NOT_ACCEPTABLE, Vec::new()).into_response();
        }
    }

    // Parse JSON-RPC request
    let req = match handler::parse_request(&body) {
        Ok(r) => r,
        Err(err_resp) => {
            return json_response(StatusCode::OK, &err_resp);
        }
    };

    // Dispatch
    let audit_ctx = super::extract_audit_context(
        client_ip.as_ref().map(|e| &e.0),
        connect_info.as_ref().map(|e| &e.0),
    );
    let backend = ServerMcpBackend {
        state: state.clone(),
        audit_ctx,
    };
    let elicit = NoopElicitation;

    let resp = handler::handle_request(
        req,
        &backend,
        &elicit,
        &user,
        &state.mcp_default_database,
        &state.mcp_default_environment,
    )
    .await;

    match resp {
        None => (StatusCode::ACCEPTED, Vec::new()).into_response(),
        Some(json_resp) => {
            let bytes = serde_json::to_vec(&json_resp).unwrap_or_default();
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                bytes,
            )
                .into_response()
        }
    }
}

/// GET /mcp or DELETE /mcp — 405 Method Not Allowed.
pub(crate) async fn method_not_allowed() -> impl IntoResponse {
    StatusCode::METHOD_NOT_ALLOWED
}

fn json_response(status: StatusCode, resp: &JsonRpcResponse) -> axum::response::Response {
    let bytes = serde_json::to_vec(resp).unwrap_or_default();
    (status, [(header::CONTENT_TYPE, "application/json")], bytes).into_response()
}
