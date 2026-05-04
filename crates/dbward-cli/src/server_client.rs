use dbward_core::Error;
use dbward_core::token::ExecutionToken;
use reqwest::Client;
use serde_json::Value;

/// Structured HTTP error from the server.
#[derive(Debug)]
pub struct ServerError {
    pub status: u16,
    pub body: String,
}

impl ServerError {
    pub fn into_core_error(self, context: &str) -> Error {
        Error::Server(format!("{context} ({}): {}", self.status, self.body))
    }
}

pub struct ServerClient {
    base_url: String,
    api_token: String,
    client: Client,
}

impl ServerClient {
    pub fn new(base_url: &str, api_token: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_token: api_token.to_string(),
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(60))
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
            return Err(ServerError {
                status: status.as_u16(),
                body: text,
            }
            .into_core_error(context));
        }
        serde_json::from_str(&text)
            .map_err(|e| Error::Server(format!("{context}: invalid JSON: {e}")))
    }

    /// Parse HTTP response, returning ServerError on failure for caller to handle.
    async fn parse_response_detailed(&self, resp: reqwest::Response) -> Result<Value, ServerError> {
        let status = resp.status();
        let text = resp.text().await.map_err(|_| ServerError {
            status: 0,
            body: "failed to read response".into(),
        })?;
        if !status.is_success() {
            return Err(ServerError {
                status: status.as_u16(),
                body: text,
            });
        }
        serde_json::from_str(&text).map_err(|_| ServerError {
            status: status.as_u16(),
            body: text,
        })
    }

    /// Create a request and return (id, status, optional execution_token).
    pub async fn create_request(
        &self,
        operation: &str,
        environment: &str,
        database: &str,
        detail: &str,
        emergency: bool,
        reason: Option<&str>,
    ) -> Result<(String, String, Option<ExecutionToken>), Error> {
        let mut body = serde_json::json!({
            "operation": operation,
            "environment": environment,
            "database": database,
            "detail": detail,
        });
        if emergency {
            body["emergency"] = serde_json::json!(true);
        }
        if let Some(r) = reason {
            body["reason"] = serde_json::json!(r);
        }
        let resp = self
            .client
            .post(format!("{}/api/requests", self.base_url))
            .bearer_auth(&self.api_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Server(format!("server request failed: {e}")))?;

        let status_code = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| Error::Server(format!("server request failed: {e}")))?;

        if !status_code.is_success() {
            return Err(Error::Server(format!(
                "server returned {}: {}",
                status_code, text
            )));
        }

        let body: Value = serde_json::from_str(&text)
            .map_err(|e| Error::Server(format!("invalid server response: {e}")))?;

        let id = body["id"].as_str().unwrap_or("").to_string();
        let status = body["status"].as_str().unwrap_or("").to_string();
        let token = serde_json::from_value(body["execution_token"].clone()).ok();

        Ok((id, status, token))
    }

    /// List all requests.
    pub async fn list_requests(
        &self,
        limit: Option<u32>,
        status: Option<&str>,
    ) -> Result<Value, Error> {
        let mut url = format!("{}/api/requests", self.base_url);
        let mut query_parts: Vec<String> = Vec::new();
        if let Some(l) = limit {
            query_parts.push(format!("limit={l}"));
        }
        if let Some(s) = status {
            query_parts.push(format!("status={s}"));
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
            .map_err(|e| ServerError {
                status: 0,
                body: format!("dispatch failed: {e}"),
            })?;

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

    /// Dispatch and wait for result in one flow.
    pub async fn dispatch_and_wait(&self, request_id: &str) -> Result<Value, Error> {
        eprintln!("Dispatching request {request_id}...");
        if let Err(e) = self.dispatch(request_id).await {
            let body_lower = e.body.to_lowercase();
            if e.status == 404 {
                return Err(Error::Server(format!("Request {request_id} not found")));
            }
            if e.status == 409 {
                if body_lower.contains("wrong status") || body_lower.contains("pending") {
                    return Err(Error::Server(format!(
                        "Request is still pending approval. Ask an approver to run: dbward approve {request_id}"
                    )));
                }
                if body_lower.contains("already dispatched") || body_lower.contains("dispatched") {
                    return Err(Error::Server(format!(
                        "Request is already dispatched. Run: dbward resume {request_id}"
                    )));
                }
            }
            return Err(e.into_core_error("dispatch"));
        }
        eprintln!("Waiting for agent to execute...");

        tokio::select! {
            result = self.stream_result(request_id) => result,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\nInterrupted. Request {request_id} is dispatched.");
                eprintln!("Run: dbward resume {request_id}");
                Err(Error::Server("interrupted".into()))
            }
        }
    }

    /// Approve a request.
    pub async fn approve(&self, request_id: &str) -> Result<Value, ServerError> {
        let resp = self
            .client
            .post(format!(
                "{}/api/requests/{}/approve",
                self.base_url, request_id
            ))
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| ServerError {
                status: 0,
                body: format!("approve failed: {e}"),
            })?;

        self.parse_response_detailed(resp).await
    }

    /// Reject a request.
    pub async fn reject(&self, request_id: &str) -> Result<Value, ServerError> {
        let resp = self
            .client
            .post(format!(
                "{}/api/requests/{}/reject",
                self.base_url, request_id
            ))
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| ServerError {
                status: 0,
                body: format!("reject failed: {e}"),
            })?;

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
}
