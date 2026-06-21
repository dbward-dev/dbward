use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::Extension;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;
use axum::response::sse::{Event, KeepAlive, Sse};
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;

use dbward_domain::auth::AuthUser;
use dbward_mcp::handler;
use dbward_mcp::ports::NoopElicitation;
use dbward_mcp::protocol::{INVALID_REQUEST, JsonRpcMessage, JsonRpcResponse, parse_message};

use crate::http_elicitation::HttpElicitation;
use crate::mcp_backend::ServerMcpBackend;
use crate::middleware::trusted_proxies::ClientIp;
use crate::session::{
    PHASE_ACTIVE, PHASE_INITIALIZING, RequestRuntime, SessionRuntime, StreamRuntime,
};
use crate::state::AppState;

/// POST /mcp — MCP JSON-RPC endpoint (Phase 2: session-aware, SSE-capable).
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

    // Origin validation (MCP spec MUST)
    if let Err(status) = validate_origin(&headers, &state.mcp_allowed_origins) {
        return status.into_response();
    }

    // Content-Type check
    match headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    {
        Some(ct) if ct.contains("application/json") => {}
        _ => return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response(),
    }

    // Accept header parsing
    let accept_str = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let accepts_json = accept_str.is_empty()
        || accept_str.contains("application/json")
        || accept_str.contains("*/*");
    let accepts_sse = accept_str.contains("text/event-stream");
    if !accepts_json && !accepts_sse {
        return StatusCode::NOT_ACCEPTABLE.into_response();
    }

    // Session validation
    let session = resolve_session(&headers, &state, &user);
    if let SessionResult::Invalid(status) = &session {
        return status.into_response();
    }
    let session_arc = session.arc();

    // Parse message
    let msg = match parse_message(&body) {
        Ok(m) => m,
        Err(err_resp) => {
            if let Some(e) = &err_resp.error {
                state.metrics.mcp_errors_total.inc([&e.code.to_string()]);
            }
            return json_response(StatusCode::OK, &err_resp);
        }
    };

    // Build backend
    let audit_ctx = super::extract_audit_context(
        client_ip.as_ref().map(|e| &e.0),
        connect_info.as_ref().map(|e| &e.0),
    );
    let backend = ServerMcpBackend {
        state: state.clone(),
        audit_ctx,
    };

    // Dispatch
    dispatch_message(msg, session_arc, &backend, &user, &state, accepts_sse).await
}

/// GET /mcp — session-bound SSE resume/replay.
pub(crate) async fn get_mcp(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !state.mcp_enabled {
        return StatusCode::NOT_FOUND.into_response();
    }

    if let Err(status) = validate_origin(&headers, &state.mcp_allowed_origins) {
        return status.into_response();
    }

    // Accept header check: must request text/event-stream
    let accept_str = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !accept_str.contains("text/event-stream") && !accept_str.contains("*/*") {
        return StatusCode::NOT_ACCEPTABLE.into_response();
    }

    let session_id = match headers.get("mcp-session-id").and_then(|v| v.to_str().ok()) {
        Some(id) => id,
        None => return StatusCode::METHOD_NOT_ALLOWED.into_response(),
    };

    let last_event_id = match headers.get("last-event-id").and_then(|v| v.to_str().ok()) {
        Some(id) => id,
        None => return StatusCode::METHOD_NOT_ALLOWED.into_response(),
    };

    // Parse last_event_id → stream_id:seq
    let (stream_id, after_seq) = match last_event_id.rsplit_once(':') {
        Some((sid, seq_str)) => match seq_str.parse::<u64>() {
            Ok(seq) => (sid.to_string(), seq),
            Err(_) => return StatusCode::BAD_REQUEST.into_response(),
        },
        None => return StatusCode::BAD_REQUEST.into_response(),
    };

    // Validate session
    let store = state.session_store();
    let session = match store.get(session_id) {
        Some(s) if s.user.subject_id == user.subject_id => s,
        Some(_) => return StatusCode::FORBIDDEN.into_response(),
        None => return StatusCode::NOT_FOUND.into_response(),
    };
    session.touch();

    // Find stream
    let stream_rt = match session.streams.get(&stream_id) {
        Some(s) => s.value().clone(),
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    // Subscribe FIRST (before replay) to avoid gap
    let (sub_tx, mut sub_rx) = tokio::sync::mpsc::channel::<crate::session::SseEvent>(256);
    if !stream_rt
        .completed
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        stream_rt.subscribers.lock().push(sub_tx);
    }

    // Gap detection: if client is behind the oldest buffered event, resync needed
    {
        let buf = stream_rt.replay_buffer.read();
        if let Some(oldest) = buf.front() {
            let oldest_seq: u64 = oldest
                .id
                .rsplit_once(':')
                .and_then(|(_, s)| s.parse().ok())
                .unwrap_or(0);
            if after_seq < oldest_seq.saturating_sub(1) {
                // Client missed events that were already evicted from buffer
                return StatusCode::NOT_FOUND.into_response();
            }
        }
    }

    // Replay from buffer
    // Channel capacity >= replay_buffer to guarantee full replay without drops
    let replay_cap = stream_rt.replay_capacity.max(256);
    let (tx, rx) = mpsc::channel::<Event>(replay_cap);
    let mut max_replayed_seq = after_seq;
    {
        let buf = stream_rt.replay_buffer.read();
        for event in buf.iter() {
            let seq: u64 = event
                .id
                .rsplit_once(':')
                .and_then(|(_, s)| s.parse().ok())
                .unwrap_or(0);
            if seq > after_seq {
                let _ = tx.try_send(Event::default().id(&event.id).data(&event.data));
                max_replayed_seq = max_replayed_seq.max(seq);
            }
        }
    }

    // Stream live events from subscriber (deduplicated by seq)
    if !stream_rt
        .completed
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        let tx_live = tx.clone();
        tokio::spawn(async move {
            while let Some(event) = sub_rx.recv().await {
                let seq: u64 = event
                    .id
                    .rsplit_once(':')
                    .and_then(|(_, s)| s.parse().ok())
                    .unwrap_or(0);
                if seq > max_replayed_seq
                    && tx_live
                        .send(Event::default().id(&event.id).data(&event.data))
                        .await
                        .is_err()
                {
                    break;
                }
            }
        });
    }

    let stream = ReceiverStream::new(rx);
    let mut resp = Sse::new(stream.map(Ok::<_, Infallible>))
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response();
    resp.headers_mut()
        .insert("cache-control", "no-cache".parse().unwrap());
    resp.headers_mut()
        .insert("x-accel-buffering", "no".parse().unwrap());
    resp
}

/// DELETE /mcp — session termination.
pub(crate) async fn delete_mcp(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !state.mcp_enabled {
        return StatusCode::NOT_FOUND.into_response();
    }

    if let Err(status) = validate_origin(&headers, &state.mcp_allowed_origins) {
        return status.into_response();
    }

    let session_id = match headers.get("mcp-session-id").and_then(|v| v.to_str().ok()) {
        Some(id) => id,
        None => return StatusCode::NOT_FOUND.into_response(), // design doc: 404
    };

    let store = state.session_store();
    match store.get(session_id) {
        Some(session) if session.user.subject_id == user.subject_id => {
            session.shutdown();
            store.remove(session_id);
            StatusCode::OK.into_response()
        }
        Some(_) => StatusCode::FORBIDDEN.into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

enum SessionResult {
    /// Session found and validated.
    Active(Arc<SessionRuntime>),
    /// No session header — stateless mode (Phase 1 compat).
    Stateless,
    /// Invalid session — return this status.
    Invalid(StatusCode),
}

impl SessionResult {
    fn arc(&self) -> Option<Arc<SessionRuntime>> {
        match self {
            Self::Active(s) => Some(s.clone()),
            _ => None,
        }
    }
}

fn resolve_session(headers: &HeaderMap, state: &AppState, user: &AuthUser) -> SessionResult {
    let session_id = match headers.get("mcp-session-id").and_then(|v| v.to_str().ok()) {
        Some(id) => id,
        None => return SessionResult::Stateless,
    };

    let store = state.session_store();
    match store.get(session_id) {
        Some(session) => {
            if session.user.subject_id != user.subject_id {
                return SessionResult::Invalid(StatusCode::FORBIDDEN);
            }
            if session.phase() == crate::session::PHASE_CLOSING {
                return SessionResult::Invalid(StatusCode::NOT_FOUND);
            }
            session.touch();
            SessionResult::Active(session)
        }
        None => SessionResult::Invalid(StatusCode::NOT_FOUND),
    }
}

fn validate_origin(headers: &HeaderMap, allowed: &[String]) -> Result<(), StatusCode> {
    if allowed.is_empty() {
        return Ok(()); // No restriction — non-browser or CORS disabled
    }
    match headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        None => Ok(()), // Non-browser client (curl, SDK) — no Origin sent
        Some(origin) => {
            if allowed.iter().any(|a| a == origin) {
                Ok(())
            } else {
                Err(StatusCode::FORBIDDEN)
            }
        }
    }
}

async fn dispatch_message(
    msg: JsonRpcMessage,
    session: Option<Arc<SessionRuntime>>,
    backend: &ServerMcpBackend,
    user: &AuthUser,
    state: &AppState,
    accepts_sse: bool,
) -> axum::response::Response {
    match msg {
        JsonRpcMessage::Request(req) => {
            state
                .metrics
                .mcp_requests_total
                .inc([normalize_method(&req.method)]);
            // Initialize creates a new session
            if req.method == "initialize" {
                return handle_initialize_request(req, user, state).await;
            }

            // SSE path: session + accepts_sse
            if let Some(session) = session.filter(|_| accepts_sse) {
                return handle_sse_request(
                    session,
                    req,
                    backend.clone(),
                    user.clone(),
                    state.clone(),
                )
                .await;
            }

            // JSON path (Phase 1 compat)
            let elicit = NoopElicitation;
            let resp = handler::handle_request(
                req,
                backend,
                &elicit,
                user,
                &state.mcp_default_database,
                &state.mcp_default_environment,
            )
            .await;

            match resp {
                None => StatusCode::ACCEPTED.into_response(),
                Some(r) => json_response(StatusCode::OK, &r),
            }
        }

        JsonRpcMessage::Notification(notif) => {
            handle_notification(
                &notif.method,
                &notif.params,
                session.as_ref(),
                &state.metrics,
            );
            StatusCode::ACCEPTED.into_response()
        }

        JsonRpcMessage::Response(resp) => {
            let Some(ref session) = session else {
                return (StatusCode::BAD_REQUEST, "session required for responses").into_response();
            };
            route_elicitation_response(session, &resp)
        }

        JsonRpcMessage::Batch(messages) => {
            let mut responses: Vec<JsonRpcResponse> = Vec::new();
            for m in messages {
                match m {
                    JsonRpcMessage::Request(req) => {
                        state
                            .metrics
                            .mcp_requests_total
                            .inc([normalize_method(&req.method)]);
                        if req.method == "initialize" {
                            responses.push(JsonRpcResponse::error(
                                req.id,
                                INVALID_REQUEST,
                                "initialize must not be sent in a batch",
                            ));
                            continue;
                        }
                        let elicit = NoopElicitation;
                        if let Some(r) = handler::handle_request(
                            req,
                            backend,
                            &elicit,
                            user,
                            &state.mcp_default_database,
                            &state.mcp_default_environment,
                        )
                        .await
                        {
                            responses.push(r);
                        }
                    }
                    JsonRpcMessage::Notification(notif) => {
                        handle_notification(
                            &notif.method,
                            &notif.params,
                            session.as_ref(),
                            &state.metrics,
                        );
                    }
                    JsonRpcMessage::Response(resp) => {
                        if let Some(ref s) = session {
                            // Reuse shared helper (ignore HTTP response — batch returns 202)
                            route_elicitation_response(s, &resp);
                        }
                    }
                    JsonRpcMessage::Batch(_) => {
                        responses.push(JsonRpcResponse::error(
                            None,
                            INVALID_REQUEST,
                            "Nested batch not allowed",
                        ));
                    }
                }
            }
            if responses.is_empty() {
                StatusCode::ACCEPTED.into_response()
            } else {
                let bytes = serde_json::to_vec(&responses).unwrap_or_default();
                (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/json")],
                    bytes,
                )
                    .into_response()
            }
        }
    }
}

async fn handle_sse_request(
    session: Arc<SessionRuntime>,
    req: dbward_mcp::protocol::JsonRpcRequest,
    backend: ServerMcpBackend,
    user: AuthUser,
    state: AppState,
) -> axum::response::Response {
    // Per-session concurrency limit (atomic)
    let count = session
        .active_request_count
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if count >= 10 {
        session
            .active_request_count
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    let stream_id = uuid::Uuid::new_v4().to_string();
    state
        .metrics
        .mcp_sse_streams_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let (event_tx, event_rx) = mpsc::channel::<Event>(32);
    let stream_rt = Arc::new(StreamRuntime::new(
        stream_id.clone(),
        event_tx,
        state.mcp_replay_buffer_size,
    ));
    session.streams.insert(stream_id.clone(), stream_rt.clone());

    // Register in-flight request BEFORE spawn to prevent race
    let cancel_token = CancellationToken::new();
    let req_id_str = req.id.as_ref().map(request_id_key).unwrap_or_default();
    let req_id_value = req.id.clone();

    // Reject duplicate in-flight IDs to prevent orphaned tasks (atomic check+insert)
    use dashmap::mapref::entry::Entry;
    let req_entry = session.requests.entry(req_id_str.clone());
    match req_entry {
        Entry::Occupied(_) => {
            session
                .active_request_count
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            return StatusCode::CONFLICT.into_response();
        }
        Entry::Vacant(v) => {
            v.insert(RequestRuntime {
                stream_id: stream_id.clone(),
                cancel_token: cancel_token.clone(),
                abort_handle: tokio::spawn(async {}).abort_handle(), // placeholder
            });
        }
    }

    let task = tokio::spawn({
        let session = session.clone();
        let stream_rt = stream_rt.clone();
        let cancel = cancel_token.clone();
        let req_id_str = req_id_str.clone();
        async move {
            // Guard: ensures active_request_count is decremented on any exit (panic, abort, normal)
            let _guard = RequestGuard(session.clone());

            let elicit = HttpElicitation::new(
                session.clone(),
                stream_rt.clone(),
                state.mcp_elicitation_timeout_secs,
                state.metrics.clone(),
            );
            let response = tokio::select! {
                resp = handler::handle_request(
                    req, &backend, &elicit, &user,
                    &state.mcp_default_database, &state.mcp_default_environment,
                ) => resp,
                _ = cancel.cancelled() => {
                    Some(JsonRpcResponse::error(
                        req_id_value,
                        -32800,
                        "Request cancelled",
                    ))
                }
            };

            if let Some(resp) = response {
                stream_rt.emit_json(&resp).await;
            }

            session.requests.remove(&req_id_str);
            stream_rt.mark_completed();
        }
    });

    // Update abort_handle to the real task
    if let Some(mut entry) = session.requests.get_mut(&req_id_str) {
        entry.abort_handle = task.abort_handle();
    }

    // Return SSE stream with proxy-safe headers
    let stream = ReceiverStream::new(event_rx);
    let mut resp = Sse::new(stream.map(Ok::<_, Infallible>))
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response();
    resp.headers_mut()
        .insert("cache-control", "no-cache".parse().unwrap());
    resp.headers_mut()
        .insert("x-accel-buffering", "no".parse().unwrap());
    resp
}

async fn handle_initialize_request(
    req: dbward_mcp::protocol::JsonRpcRequest,
    user: &AuthUser,
    state: &AppState,
) -> axum::response::Response {
    use dbward_mcp::protocol::{InitializeParams, handle_initialize};

    // Generate initialize response first (may fail with INVALID_PARAMS)
    // Parse capabilities first (single parse)
    let supports_elicitation = serde_json::from_value::<InitializeParams>(req.params.clone())
        .map(|p| p.capabilities.elicitation.is_some())
        .unwrap_or(false);

    let resp = handle_initialize(req.id, req.params);

    // Only create session if initialize succeeded
    if resp.error.is_some() {
        return json_response(StatusCode::OK, &resp);
    }

    let store = state.session_store();
    let session = match store.create(user.clone(), supports_elicitation) {
        Some(s) => {
            state
                .metrics
                .mcp_sessions_created_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            s
        }
        None => {
            return (StatusCode::SERVICE_UNAVAILABLE, "too many sessions").into_response();
        }
    };

    let bytes = serde_json::to_vec(&resp).unwrap_or_default();

    let mut response = (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        bytes,
    )
        .into_response();
    response
        .headers_mut()
        .insert("mcp-session-id", session.id.parse().unwrap());
    response
}

fn handle_notification(
    method: &str,
    params: &serde_json::Value,
    session: Option<&Arc<SessionRuntime>>,
    metrics: &crate::metrics::Metrics,
) {
    match method {
        "notifications/initialized" => {
            if let Some(s) = session {
                use std::sync::atomic::Ordering;
                // Transition from Initializing → Active
                s.phase
                    .compare_exchange(
                        PHASE_INITIALIZING,
                        PHASE_ACTIVE,
                        Ordering::SeqCst,
                        Ordering::Relaxed,
                    )
                    .ok();
            }
        }
        "notifications/cancelled" => {
            if let Some(s) = session {
                let req_id = request_id_key(&params["requestId"]);
                if let Some(entry) = s.requests.get(&req_id) {
                    entry.value().cancel_token.cancel();
                    metrics
                        .mcp_cancel_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
        _ => {} // Other notifications: acknowledge silently
    }
}

/// Guard that decrements active_request_count on drop (handles panic/abort).
struct RequestGuard(Arc<SessionRuntime>);

impl Drop for RequestGuard {
    fn drop(&mut self) {
        self.0
            .active_request_count
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Normalize method name to prevent unbounded label cardinality.
fn normalize_method(method: &str) -> &str {
    match method {
        "initialize"
        | "ping"
        | "tools/list"
        | "tools/call"
        | "resources/list"
        | "resources/read"
        | "resources/templates/list"
        | "prompts/list"
        | "prompts/get"
        | "completions/complete"
        | "notifications/initialized"
        | "notifications/cancelled"
        | "logging/setLevel" => method,
        _ => "unknown",
    }
}

fn json_response(status: StatusCode, resp: &JsonRpcResponse) -> axum::response::Response {
    let bytes = serde_json::to_vec(resp).unwrap_or_default();
    (status, [(header::CONTENT_TYPE, "application/json")], bytes).into_response()
}

/// Normalize a JSON-RPC id value to a string key for map lookups.
/// Uses type prefix to avoid collisions (numeric 1 vs string "1").
fn request_id_key(id: &serde_json::Value) -> String {
    match id {
        serde_json::Value::String(s) => format!("s:{s}"),
        serde_json::Value::Number(n) => format!("n:{n}"),
        v => v.to_string(),
    }
}

fn parse_elicit_result(
    resp: &dbward_mcp::protocol::JsonRpcIncomingResponse,
) -> dbward_mcp::ports::ElicitResult {
    use dbward_mcp::ports::ElicitResult;

    if resp.error.is_some() {
        return ElicitResult::Cancel;
    }

    let result = match &resp.result {
        Some(r) => r,
        None => return ElicitResult::Cancel,
    };

    match result.get("action").and_then(|a| a.as_str()) {
        Some("accept") => ElicitResult::Accept {
            content: result["content"].clone(),
        },
        Some("decline") => ElicitResult::Decline,
        _ => ElicitResult::Cancel,
    }
}

/// Route an elicitation response for a session. Returns the HTTP response to send.
fn route_elicitation_response(
    session: &crate::session::SessionRuntime,
    resp: &dbward_mcp::protocol::JsonRpcIncomingResponse,
) -> axum::response::Response {
    // Elicitation IDs are always strings like "elicit-N" — use raw value, not request_id_key
    let id_str = match &resp.id {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    };

    // Validate before removing
    if resp.error.is_none() {
        match resp
            .result
            .as_ref()
            .and_then(|r| r.get("action"))
            .and_then(|a| a.as_str())
        {
            Some("accept" | "decline" | "cancel") => {}
            _ => return (StatusCode::BAD_REQUEST, "invalid elicitation response").into_response(),
        }
    }

    if let Some((_, tx)) = session.pending_elicitations.remove(&id_str) {
        let result = parse_elicit_result(resp);
        let _ = tx.send(result);
        session
            .resolved_elicitations
            .insert(id_str, std::time::Instant::now());
        StatusCode::ACCEPTED.into_response()
    } else if session.resolved_elicitations.contains_key(&id_str) {
        (StatusCode::BAD_REQUEST, "elicitation already resolved").into_response()
    } else {
        (StatusCode::BAD_REQUEST, "unknown elicitation id").into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_method_known_methods() {
        assert_eq!(normalize_method("initialize"), "initialize");
        assert_eq!(normalize_method("tools/call"), "tools/call");
        assert_eq!(normalize_method("tools/list"), "tools/list");
        assert_eq!(normalize_method("resources/list"), "resources/list");
        assert_eq!(
            normalize_method("notifications/cancelled"),
            "notifications/cancelled"
        );
    }

    #[test]
    fn normalize_method_unknown_bucketed() {
        assert_eq!(normalize_method("foo/bar"), "unknown");
        assert_eq!(normalize_method(""), "unknown");
        assert_eq!(normalize_method("DROP TABLE users"), "unknown");
    }

    #[test]
    fn request_id_key_distinguishes_types() {
        let str_id = serde_json::json!("1");
        let num_id = serde_json::json!(1);
        // Must produce different keys
        assert_ne!(request_id_key(&str_id), request_id_key(&num_id));
        assert_eq!(request_id_key(&str_id), "s:1");
        assert_eq!(request_id_key(&num_id), "n:1");
    }
}
