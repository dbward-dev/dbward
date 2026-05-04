use dbward_core::Error;
use dbward_core::token::ExecutionToken;
use reqwest::Client;
use serde_json::Value;

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
            client: Client::new(),
        }
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
    pub async fn list_requests(&self, limit: Option<u32>, status: Option<&str>) -> Result<Value, Error> {
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

        resp.json()
            .await
            .map_err(|e| Error::Server(format!("invalid response: {e}")))
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

        let status_code = resp.status();
        let body: Value = resp
            .json()
            .await
            .map_err(|e| Error::Server(format!("invalid response: {e}")))?;

        if !status_code.is_success() {
            return Err(Error::Server(format!(
                "get request failed ({}): {}",
                status_code, body
            )));
        }
        Ok(body)
    }

    /// Dispatch a request for execution (on-demand).
    pub async fn dispatch(&self, request_id: &str) -> Result<Value, Error> {
        let resp = self
            .client
            .post(format!(
                "{}/api/requests/{}/dispatch",
                self.base_url, request_id
            ))
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| Error::Server(format!("dispatch failed: {e}")))?;

        let status_code = resp.status();
        let body: Value = resp
            .json()
            .await
            .map_err(|e| Error::Server(format!("dispatch parse failed: {e}")))?;

        if !status_code.is_success() {
            return Err(Error::Server(format!(
                "dispatch failed ({}): {}",
                status_code, body
            )));
        }
        Ok(body)
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

        let status_code = resp.status();
        let body: Value = resp
            .json()
            .await
            .map_err(|e| Error::Server(format!("stream result parse failed: {e}")))?;

        if !status_code.is_success() {
            return Err(Error::Server(format!(
                "stream result failed ({}): {}",
                status_code, body
            )));
        }
        Ok(body)
    }

    /// Dispatch and wait for result in one flow.
    pub async fn dispatch_and_wait(&self, request_id: &str) -> Result<Value, Error> {
        eprintln!("Dispatching request {request_id}...");
        self.dispatch(request_id).await?;
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
    pub async fn approve(&self, request_id: &str) -> Result<Value, Error> {
        let resp = self
            .client
            .post(format!(
                "{}/api/requests/{}/approve",
                self.base_url, request_id
            ))
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| Error::Server(format!("approve failed: {e}")))?;

        let status_code = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| Error::Server(format!("approve failed: {e}")))?;

        if !status_code.is_success() {
            return Err(Error::Server(format!(
                "approve failed ({}): {}",
                status_code, text
            )));
        }
        serde_json::from_str(&text).map_err(|e| Error::Server(format!("invalid response: {e}")))
    }

    /// Reject a request.
    pub async fn reject(&self, request_id: &str) -> Result<Value, Error> {
        let resp = self
            .client
            .post(format!(
                "{}/api/requests/{}/reject",
                self.base_url, request_id
            ))
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| Error::Server(format!("reject failed: {e}")))?;

        let status_code = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| Error::Server(format!("reject failed: {e}")))?;

        if !status_code.is_success() {
            return Err(Error::Server(format!(
                "reject failed ({}): {}",
                status_code, text
            )));
        }
        serde_json::from_str(&text).map_err(|e| Error::Server(format!("invalid response: {e}")))
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

        let status_code = resp.status();
        let body: Value = resp
            .json()
            .await
            .map_err(|e| Error::Server(format!("invalid response: {e}")))?;

        if !status_code.is_success() {
            return Err(Error::Server(format!(
                "list audit failed ({}): {}",
                status_code, body
            )));
        }
        Ok(body)
    }
}
