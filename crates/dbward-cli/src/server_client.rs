use dbward_core::token::ExecutionToken;
use dbward_core::Error;
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
            return Err(Error::Server(format!("server returned {}: {}", status_code, text)));
        }

        let body: Value = serde_json::from_str(&text)
            .map_err(|e| Error::Server(format!("invalid server response: {e}")))?;

        let id = body["id"].as_str().unwrap_or("").to_string();
        let status = body["status"].as_str().unwrap_or("").to_string();
        let token = serde_json::from_value(body["execution_token"].clone()).ok();

        Ok((id, status, token))
    }

    /// List all requests.
    pub async fn list_requests(&self) -> Result<Value, Error> {
        let resp = self
            .client
            .get(format!("{}/api/requests", self.base_url))
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| Error::Server(format!("list requests failed: {e}")))?;

        resp.json()
            .await
            .map_err(|e| Error::Server(format!("invalid response: {e}")))
    }

    /// Get a single request by ID.
    pub async fn get_request(&self, request_id: &str) -> Result<Value, Error> {
        let resp = self
            .client
            .get(format!("{}/api/requests/{}", self.base_url, request_id))
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
            return Err(Error::Server(format!("get request failed ({}): {}", status_code, body)));
        }
        Ok(body)
    }

    /// Poll a request until it's no longer pending. Returns (status, optional token).
    pub async fn poll_request(
        &self,
        request_id: &str,
        poll_interval: std::time::Duration,
        timeout: std::time::Duration,
    ) -> Result<(String, Option<ExecutionToken>), Error> {
        let start = std::time::Instant::now();

        loop {
            let resp = self
                .client
                .get(format!("{}/api/requests/{}", self.base_url, request_id))
                .bearer_auth(&self.api_token)
                .send()
                .await
                .map_err(|e| Error::Server(format!("poll failed: {e}")))?;

            let body: Value = resp
                .json()
                .await
                .map_err(|e| Error::Server(format!("invalid poll response: {e}")))?;

            let status = body["status"].as_str().unwrap_or("").to_string();

            match status.as_str() {
                "pending" => {
                    if start.elapsed() > timeout {
                        return Err(Error::Server(
                            "timed out waiting for approval".to_string(),
                        ));
                    }
                    eprintln!("Waiting for approval... (request: {request_id})");
                    tokio::time::sleep(poll_interval).await;
                }
                "approved" | "auto_approved" => {
                    let token = serde_json::from_value(body["execution_token"].clone()).ok();
                    return Ok((status, token));
                }
                _ => {
                    return Err(Error::Server(format!("request {status}")));
                }
            }
        }
    }

    /// Report completion of an executed request.
    pub async fn complete_request(&self, request_id: &str, success: bool) -> Result<(), Error> {
        let resp = self
            .client
            .post(format!(
                "{}/api/requests/{}/complete",
                self.base_url, request_id
            ))
            .bearer_auth(&self.api_token)
            .json(&serde_json::json!({"success": success}))
            .send()
            .await
            .map_err(|e| Error::Server(format!("complete failed: {e}")))?;

        if !resp.status().is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::Server(format!("complete failed: {text}")));
        }
        Ok(())
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
        let text = resp.text().await.map_err(|e| Error::Server(format!("approve failed: {e}")))?;

        if !status_code.is_success() {
            return Err(Error::Server(format!("approve failed ({}): {}", status_code, text)));
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
        let text = resp.text().await.map_err(|e| Error::Server(format!("reject failed: {e}")))?;

        if !status_code.is_success() {
            return Err(Error::Server(format!("reject failed ({}): {}", status_code, text)));
        }
        serde_json::from_str(&text).map_err(|e| Error::Server(format!("invalid response: {e}")))
    }

    /// Poll for execution result (agent posts result, client retrieves it).
    pub async fn poll_result(
        &self,
        request_id: &str,
        poll_interval: std::time::Duration,
        timeout: std::time::Duration,
    ) -> Result<Value, Error> {
        let start = std::time::Instant::now();
        loop {
            let resp = self.get_request(request_id).await?;
            let status = resp["status"].as_str().unwrap_or("");
            match status {
                "executed" => return Ok(resp),
                "failed" => {
                    let err = resp["execution_error"].as_str().unwrap_or("unknown error");
                    return Err(Error::Server(format!("execution failed: {err}")));
                }
                "rejected" => return Err(Error::Server("request was rejected".into())),
                "pending" | "approved" | "auto_approved" | "running" => {
                    if start.elapsed() > timeout {
                        return Err(Error::Server(format!(
                            "timed out waiting for result (status: {status})"
                        )));
                    }
                    eprintln!("Waiting for agent to execute... (request: {request_id}, status: {status})");
                    tokio::select! {
                        _ = tokio::time::sleep(poll_interval) => {}
                        _ = tokio::signal::ctrl_c() => {
                            eprintln!("\nInterrupted. Request {request_id} is still {status}.");
                            eprintln!("Run: dbward resume {request_id}");
                            return Err(Error::Server("interrupted".into()));
                        }
                    }
                }
                _ => return Err(Error::Server(format!("unexpected status: {status}"))),
            }
        }
    }
}
