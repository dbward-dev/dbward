use dbward_core::Error;
use dbward_core::token::ExecutionToken;
use reqwest::Client;
use serde_json::Value;

const MAX_ERROR_BODY_PREVIEW: usize = 200;
const REQUEST_STATUS_WAIT_SECS: u64 = 30;

/// Structured HTTP error from the server.
#[derive(Debug)]
pub struct ServerError {
    pub status: u16,
    pub body: String,
    pub error_message: Option<String>,
    pub code: Option<String>,
    pub hint: Option<String>,
}

impl ServerError {
    pub fn from_response(status: u16, body: String) -> Self {
        let (error_message, code, hint) = serde_json::from_str::<Value>(&body)
            .ok()
            .map(|v| {
                (
                    v["error"].as_str().map(String::from),
                    v["code"].as_str().map(String::from),
                    v["hint"].as_str().map(String::from),
                )
            })
            .unwrap_or((None, None, None));
        Self {
            status,
            body,
            error_message,
            code,
            hint,
        }
    }

    fn fallback_message(&self) -> String {
        if self.status == 0 {
            return "request failed before receiving a server response".to_string();
        }

        let compact = self.body.split_whitespace().collect::<Vec<_>>().join(" ");
        if compact.is_empty() {
            return format!("server returned HTTP {}", self.status);
        }

        let preview: String = compact.chars().take(MAX_ERROR_BODY_PREVIEW).collect();
        if compact.chars().count() > MAX_ERROR_BODY_PREVIEW {
            format!("{preview}...")
        } else {
            preview
        }
    }

    pub fn into_core_error(self, context: &str) -> Error {
        let msg = self
            .error_message
            .clone()
            .unwrap_or_else(|| self.fallback_message());
        let mut out = format!("{context}: {msg}");
        if let Some(hint) = &self.hint {
            out.push_str(&format!("\n  Hint: {hint}"));
        }
        Error::Server(out)
    }
}

#[derive(Clone)]
pub struct ServerClient {
    base_url: String,
    api_token: String,
    client: Client,
}

pub struct CreateRequest<'a> {
    pub operation: &'a str,
    pub environment: &'a str,
    pub database: &'a str,
    pub detail: &'a str,
    pub emergency: bool,
    pub reason: Option<&'a str>,
    pub metadata: Option<&'a serde_json::Value>,
    pub idempotency_key: Option<&'a str>,
    pub share_with: Option<&'a [String]>,
    pub no_store: bool,
}

impl ServerClient {
    pub fn new(base_url: &str, api_token: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_token: api_token.to_string(),
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(600))
                .connect_timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("failed to build HTTP client"),
        }
    }

    /// Parse HTTP response: check status first, then parse JSON.
    async fn parse_response(&self, resp: reqwest::Response, context: &str) -> Result<Value, Error> {
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| Error::Server(format!("{context}: {e}")))?;
        if !status.is_success() {
            return Err(ServerError::from_response(status.as_u16(), text).into_core_error(context));
        }
        serde_json::from_str(&text)
            .map_err(|e| Error::Server(format!("{context}: invalid JSON: {e}")))
    }

    /// Parse HTTP response, returning ServerError on failure for caller to handle.
    async fn parse_response_detailed(&self, resp: reqwest::Response) -> Result<Value, ServerError> {
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|_| ServerError::from_response(0, "failed to read response".into()))?;
        if !status.is_success() {
            return Err(ServerError::from_response(status.as_u16(), text));
        }
        serde_json::from_str(&text).map_err(|_| ServerError::from_response(status.as_u16(), text))
    }

    /// Create a request and return (id, status, optional execution_token).
    pub async fn create_request(
        &self,
        req: CreateRequest<'_>,
    ) -> Result<(String, String, Option<ExecutionToken>, Vec<String>), Error> {
        let mut body = serde_json::json!({
            "operation": req.operation,
            "environment": req.environment,
            "database": req.database,
            "detail": req.detail,
        });
        if req.emergency {
            body["emergency"] = serde_json::json!(true);
        }
        if let Some(r) = req.reason {
            body["reason"] = serde_json::json!(r);
        }
        if let Some(metadata) = req.metadata {
            body["metadata"] = metadata.clone();
        }
        if let Some(idempotency_key) = req.idempotency_key {
            body["idempotency_key"] = serde_json::json!(idempotency_key);
        }
        if let Some(sw) = req.share_with {
            body["share_with"] = serde_json::json!(sw);
        }
        if req.no_store {
            body["no_store"] = serde_json::json!(true);
        }
        let resp = self
            .client
            .post(format!("{}/api/requests", self.base_url))
            .bearer_auth(&self.api_token)
            .json(&body)
            .send()
            .await
            .map_err(|_| {
                ServerError::from_response(0, "create request failed".into())
                    .into_core_error("create request")
            })?;

        let body = self.parse_response(resp, "create request").await?;

        let cr: dbward_api_types::requests::CreateRequestResponse = serde_json::from_value(body)
            .map_err(|e| Error::Server(format!("create request: invalid response: {e}")))?;
        let id = cr.id;
        let status = cr.status.as_str().to_string();
        let token = cr
            .execution_token
            .and_then(|v| serde_json::from_value(v).ok());
        let approvers = cr.approvers;

        Ok((id, status, token, approvers))
    }

    /// List all requests.
    pub async fn list_requests(
        &self,
        limit: Option<u32>,
        status: Option<&str>,
        database: Option<&str>,
        environment: Option<&str>,
        user: Option<&str>,
    ) -> Result<Value, Error> {
        let mut url = format!("{}/api/requests", self.base_url);
        let mut query_parts: Vec<String> = Vec::new();
        if let Some(l) = limit {
            query_parts.push(format!("limit={l}"));
        }
        if let Some(s) = status {
            query_parts.push(format!("status={s}"));
        }
        if let Some(database) = database {
            query_parts.push(format!("database={database}"));
        }
        if let Some(environment) = environment {
            query_parts.push(format!("environment={environment}"));
        }
        if let Some(user) = user {
            query_parts.push(format!("user={user}"));
        }
        if !query_parts.is_empty() {
            url = format!("{url}?{}", query_parts.join("&"));
        }
        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| Error::Server(format!("list requests failed: {e}")))?;

        self.parse_response(resp, "list requests").await
    }

    /// List pending requests the current user can approve.
    pub async fn list_pending_for_me(&self, limit: Option<u32>) -> Result<Value, Error> {
        let mut url = format!("{}/api/requests?pending_for_me=true", self.base_url);
        if let Some(l) = limit {
            url = format!("{url}&limit={l}");
        }
        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| Error::Server(format!("list pending-for-me failed: {e}")))?;

        self.parse_response(resp, "list pending-for-me").await
    }

    /// Get a single request by ID, optionally long-polling for status change.
    pub async fn get_request(&self, request_id: &str) -> Result<Value, Error> {
        self.get_request_with_wait(request_id, 0).await
    }

    /// Get a single request by ID with long-poll wait (seconds).
    pub async fn get_request_with_wait(&self, request_id: &str, wait: u64) -> Result<Value, Error> {
        let mut url = format!("{}/api/requests/{}", self.base_url, request_id);
        if wait > 0 {
            url = format!("{url}?wait={wait}");
        }
        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| Error::Server(format!("get request failed: {e}")))?;

        self.parse_response(resp, "get request").await
    }

    /// Dispatch a request for execution (on-demand).
    pub async fn dispatch(&self, request_id: &str) -> Result<Value, ServerError> {
        let resp = self
            .client
            .post(format!(
                "{}/api/requests/{}/dispatch",
                self.base_url, request_id
            ))
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| ServerError::from_response(0, format!("dispatch failed: {e}")))?;

        self.parse_response_detailed(resp).await
    }

    /// Wait for execution result via long poll.
    pub async fn stream_result(&self, request_id: &str) -> Result<Value, Error> {
        let resp = self
            .client
            .get(format!(
                "{}/api/requests/{}/result/stream",
                self.base_url, request_id
            ))
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| Error::Server(format!("stream result failed: {e}")))?;

        self.parse_response(resp, "stream result").await
    }

    /// Wait for execution result via the existing request lifecycle.
    pub async fn wait_for_result(&self, request_id: &str) -> Result<Value, Error> {
        eprintln!("Waiting for agent to execute...");

        // Progress display task: poll status every 3s
        let progress_client = self.clone();
        let progress_id = request_id.to_string();
        let progress_handle = tokio::spawn(async move {
            let mut last_status = String::new();
            let start = std::time::Instant::now();
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                let req = match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    progress_client.get_request(&progress_id),
                )
                .await
                {
                    Ok(Ok(r)) => r,
                    _ => continue,
                };
                let status = req["status"].as_str().unwrap_or("").to_string();
                let elapsed = start.elapsed().as_secs();
                if status != last_status {
                    match status.as_str() {
                        "dispatched" => eprintln!("  → queued (waiting for agent)  [{}s]", elapsed),
                        "executing" | "running" => {
                            let agent = req["claimed_by"].as_str().unwrap_or("agent");
                            eprintln!("  → executing by {}  [{}s]", agent, elapsed);
                        }
                        "execution_lost" => {
                            eprintln!("  → execution_lost (agent disconnected)");
                            break;
                        }
                        "approved" => {
                            eprintln!("  → dispatch expired (no agent picked up)");
                            break;
                        }
                        _ => {}
                    }
                    last_status = status;
                }
            }
        });

        let result = loop {
            let result = tokio::select! {
                result = self.stream_result(request_id) => Some(result),
                _ = tokio::signal::ctrl_c() => None,
            };

            match result {
                Some(Ok(v)) => break Ok(v),
                Some(Err(_)) => {
                    if let Some(v) = self.get_request_result_fallback(request_id).await? {
                        break Ok(v);
                    }
                }
                None => {
                    eprintln!("\nInterrupted. Request {request_id} is still in progress.");
                    eprintln!("Run: dbward request resume {request_id}");
                    break Err(Error::Server("interrupted".into()));
                }
            }
        };

        progress_handle.abort();
        result
    }

    pub async fn get_terminal_result(&self, request_id: &str) -> Result<Value, Error> {
        let req = self.get_request(request_id).await?;
        self.resolve_terminal_result(request_id, &req).await
    }

    async fn get_request_result_fallback(&self, request_id: &str) -> Result<Option<Value>, Error> {
        let mut req = self.get_request(request_id).await?;

        loop {
            let status = req["status"].as_str().unwrap_or("");
            match status {
                "executed" | "failed" => {
                    return self
                        .resolve_terminal_result(request_id, &req)
                        .await
                        .map(Some);
                }
                "dispatched" | "running" => {
                    req = self
                        .get_request_with_wait(request_id, REQUEST_STATUS_WAIT_SECS)
                        .await?;
                }
                "approved" | "auto_approved" | "break_glass" => {
                    // Auto-dispatch and continue polling
                    match self.dispatch(request_id).await {
                        Ok(_) => {
                            req = self
                                .get_request_with_wait(request_id, REQUEST_STATUS_WAIT_SECS)
                                .await?;
                        }
                        Err(e) => {
                            return Err(Error::Server(format!(
                                "request {request_id} is approved but dispatch failed: {}. Run: dbward request resume {request_id}",
                                e.body
                            )));
                        }
                    }
                }
                "pending" => {
                    return Err(Error::Server(format!(
                        "Request {request_id} requires approval. Check status: dbward request show {request_id}"
                    )));
                }
                _ => {
                    return Err(Error::Server(format!(
                        "unexpected status: {status}. Try: dbward request resume {request_id}"
                    )));
                }
            }
        }
    }

    async fn resolve_terminal_result(&self, request_id: &str, req: &Value) -> Result<Value, Error> {
        let status = req["status"].as_str().unwrap_or("");
        if let Some(payload) = Self::terminal_payload_from_request(req) {
            return Ok(payload);
        }

        match status {
            "executed" | "failed" => match self.get_result_content(request_id).await {
                Ok(result) => Ok(serde_json::json!({"success": true, "result": result})),
                Err(err) if Self::is_missing_result_content_error(&err) => {
                    Ok(Self::synthesized_terminal_payload(status, request_id))
                }
                Err(err) => Err(err),
            },
            _ => Err(Error::Server(format!(
                "unexpected status: {status}. Try: dbward request resume {request_id}"
            ))),
        }
    }

    fn terminal_payload_from_request(req: &Value) -> Option<Value> {
        let status = req["status"].as_str().unwrap_or("");

        if let Some(err) = req.get("execution_error") {
            return Some(serde_json::json!({"success": false, "error": err}));
        }
        if let Some(result) = req.get("execution_result") {
            return Some(serde_json::json!({
                "success": status != "failed",
                "result": result
            }));
        }

        None
    }

    fn is_missing_result_content_error(err: &Error) -> bool {
        match err {
            Error::Server(msg) => msg.contains("result not stored for this request"),
            _ => false,
        }
    }

    fn synthesized_terminal_payload(status: &str, request_id: &str) -> Value {
        match status {
            "failed" => serde_json::json!({
                "success": false,
                "error": format!(
                    "Request {request_id} failed. Result not available (relay expired, no storage configured). Check: dbward result {request_id}"
                )
            }),
            _ => serde_json::json!({
                "success": true,
                "error": format!(
                    "Request {request_id} executed successfully but result is no longer available. Check: dbward result {request_id}"
                ),
                "result": Value::Null
            }),
        }
    }

    /// Approve a request.
    pub async fn approve(
        &self,
        request_id: &str,
        comment: Option<&str>,
    ) -> Result<Value, ServerError> {
        let mut req = self
            .client
            .post(format!(
                "{}/api/requests/{}/approve",
                self.base_url, request_id
            ))
            .bearer_auth(&self.api_token);
        if let Some(comment) = comment {
            req = req.json(&serde_json::json!({ "comment": comment }));
        }
        let resp = req
            .send()
            .await
            .map_err(|e| ServerError::from_response(0, format!("approve failed: {e}")))?;

        self.parse_response_detailed(resp).await
    }

    /// Reject a request.
    pub async fn reject(
        &self,
        request_id: &str,
        comment: Option<&str>,
    ) -> Result<Value, ServerError> {
        let mut req = self
            .client
            .post(format!(
                "{}/api/requests/{}/reject",
                self.base_url, request_id
            ))
            .bearer_auth(&self.api_token);
        if let Some(comment) = comment {
            req = req.json(&serde_json::json!({ "comment": comment }));
        }
        let resp = req
            .send()
            .await
            .map_err(|e| ServerError::from_response(0, format!("reject failed: {e}")))?;

        self.parse_response_detailed(resp).await
    }

    /// Cancel a request.
    pub async fn cancel_request(
        &self,
        request_id: &str,
        reason: Option<&str>,
    ) -> Result<Value, ServerError> {
        let mut req = self
            .client
            .post(format!(
                "{}/api/requests/{}/cancel",
                self.base_url, request_id
            ))
            .bearer_auth(&self.api_token);
        if let Some(reason) = reason {
            req = req.json(&serde_json::json!({ "reason": reason }));
        }
        let resp = req
            .send()
            .await
            .map_err(|e| ServerError::from_response(0, format!("cancel failed: {e}")))?;

        self.parse_response_detailed(resp).await
    }

    /// List audit log entries.
    pub async fn list_audit(
        &self,
        limit: Option<u32>,
        user: Option<&str>,
        operation: Option<&str>,
        status: Option<&str>,
    ) -> Result<Value, Error> {
        let mut url = format!("{}/api/audit", self.base_url);
        let mut parts: Vec<String> = Vec::new();
        if let Some(l) = limit {
            parts.push(format!("limit={l}"));
        }
        if let Some(u) = user {
            parts.push(format!("user={u}"));
        }
        if let Some(o) = operation {
            parts.push(format!("operation={o}"));
        }
        if let Some(s) = status {
            parts.push(format!("status={s}"));
        }
        if !parts.is_empty() {
            url = format!("{url}?{}", parts.join("&"));
        }
        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| Error::Server(format!("list audit failed: {e}")))?;

        self.parse_response(resp, "list audit").await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn list_audit_events(
        &self,
        limit: Option<u32>,
        user: Option<&str>,
        _operation: Option<&str>,
        _status: Option<&str>,
        event_type: Option<&str>,
        category: Option<&str>,
        outcome: Option<&str>,
        environment: Option<&str>,
        since: Option<&str>,
        until: Option<&str>,
    ) -> Result<Value, Error> {
        let mut parts: Vec<String> = Vec::new();
        if let Some(l) = limit {
            parts.push(format!("limit={l}"));
        }
        if let Some(u) = user {
            parts.push(format!("actor_id={u}"));
        }
        if let Some(v) = event_type {
            parts.push(format!("event_type={v}"));
        }
        if let Some(v) = category {
            parts.push(format!("event_category={v}"));
        }
        if let Some(v) = outcome {
            parts.push(format!("outcome={v}"));
        }
        if let Some(v) = environment {
            parts.push(format!("environment={v}"));
        }
        if let Some(v) = since {
            parts.push(format!("since={v}"));
        }
        if let Some(v) = until {
            parts.push(format!("until={v}"));
        }
        let url = if parts.is_empty() {
            format!("{}/api/audit/events", self.base_url)
        } else {
            format!("{}/api/audit/events?{}", self.base_url, parts.join("&"))
        };
        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| Error::Server(format!("list audit events: {e}")))?;
        self.parse_response(resp, "list audit events").await
    }

    pub async fn get_json(&self, path: &str) -> Result<Value, Error> {
        let resp = self
            .client
            .get(format!("{}{}", self.base_url, path))
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| Error::Server(format!("get {path}: {e}")))?;
        self.parse_response(resp, path).await
    }

    pub async fn get_result_content(
        &self,
        request_id: &str,
    ) -> Result<serde_json::Value, dbward_core::Error> {
        let resp = self
            .client
            .get(format!(
                "{}/api/requests/{}/result/content",
                self.base_url, request_id
            ))
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| dbward_core::Error::Server(format!("get result: {e}")))?;
        self.parse_response(resp, "get result content").await
    }

    pub async fn list_results(&self) -> Result<serde_json::Value, dbward_core::Error> {
        let resp = self
            .client
            .get(format!("{}/api/results", self.base_url))
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| dbward_core::Error::Server(format!("list results: {e}")))?;
        self.parse_response(resp, "list results").await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_structured_server_error_fields() {
        let err = ServerError::from_response(
            409,
            r#"{"error":"request is already approved","code":"already_approved","hint":"Run dbward request resume"}"#.into(),
        );

        assert_eq!(
            err.error_message.as_deref(),
            Some("request is already approved")
        );
        assert_eq!(err.code.as_deref(), Some("already_approved"));
        assert_eq!(err.hint.as_deref(), Some("Run dbward request resume"));
    }

    #[test]
    fn falls_back_when_error_body_is_not_json() {
        let err = ServerError::from_response(502, "<html>bad gateway</html>".into());

        match err.into_core_error("dispatch") {
            Error::Server(msg) => assert_eq!(msg, "dispatch: <html>bad gateway</html>"),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn hides_transport_error_details_in_core_error() {
        let err = ServerError::from_response(
            0,
            "dispatch failed: error sending request for url (https://user:secret@example.com)"
                .into(),
        );

        match err.into_core_error("dispatch") {
            Error::Server(msg) => {
                assert!(
                    msg.contains("dispatch: request failed before receiving a server response")
                );
                assert!(!msg.contains("secret"));
                assert!(!msg.contains("https://"));
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn terminal_payload_prefers_embedded_execution_error() {
        let req = serde_json::json!({
            "status": "failed",
            "execution_error": "boom",
        });

        let payload = ServerClient::terminal_payload_from_request(&req).unwrap();

        assert_eq!(payload["success"], false);
        assert_eq!(payload["error"], "boom");
    }

    #[test]
    fn synthesized_terminal_payload_marks_failed_requests_unsuccessful() {
        let payload = ServerClient::synthesized_terminal_payload("failed", "req-123");

        assert_eq!(payload["success"], false);
        assert!(
            payload["error"]
                .as_str()
                .unwrap_or_default()
                .contains("req-123")
        );
    }

    #[test]
    fn synthesized_terminal_payload_marks_executed_requests_successful() {
        let payload = ServerClient::synthesized_terminal_payload("executed", "req-123");

        assert_eq!(payload["success"], true);
        assert!(payload["result"].is_null());
    }

    #[tokio::test]
    async fn wait_for_result_fallback_on_stream_failure() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 4096];
                let _ = tokio::io::AsyncReadExt::read(&mut socket, &mut buf).await;
                let req_str = String::from_utf8_lossy(&buf);

                let response = if req_str.contains("/result/stream") {
                    "HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\n\r\n"
                        .to_string()
                } else if req_str.contains("GET") && req_str.contains("/api/requests/") {
                    let body = serde_json::json!({
                        "id": "test-req", "status": "executed",
                        "operation": "execute_query", "environment": "dev",
                        "database": "app", "detail": "SELECT 1",
                        "created_by": "alice", "created_at": "2026-01-01T00:00:00Z",
                        "updated_at": "2026-01-01T00:00:00Z",
                        "resolved_at": null, "reason": null,
                        "metadata": {}, "idempotency_key": null, "expires_at": null,
                    })
                    .to_string();
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    )
                } else {
                    "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n".to_string()
                };
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        let client = ServerClient::new(&format!("http://{addr}"), "test-token");
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.wait_for_result("test-req"),
        )
        .await;

        server.abort();
        // Must complete within timeout (not hang)
        assert!(result.is_ok(), "wait_for_result should not hang on stream failure");
    }
}
