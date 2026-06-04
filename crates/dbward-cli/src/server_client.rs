use crate::error::CliError;
use reqwest::Client;
use serde_json::Value;
use std::sync::OnceLock;
use std::time::Duration;

const API_TIMEOUT: Duration = Duration::from_secs(30);

const MAX_ERROR_BODY_PREVIEW: usize = 200;

/// Emit a one-time warning if the server version differs from the CLI version.
fn check_version_header(resp: &reqwest::Response) {
    static WARNED: OnceLock<()> = OnceLock::new();
    if WARNED.get().is_some() {
        return;
    }
    if let Some(sv) = resp
        .headers()
        .get("x-dbward-version")
        .and_then(|v| v.to_str().ok())
    {
        let cv = env!("CARGO_PKG_VERSION");
        if sv != cv {
            WARNED.get_or_init(|| {
                eprintln!(
                    "warning: server is v{sv}, CLI is v{cv}. Run 'dbward self-update' to update."
                );
            });
        }
    }
}

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

    pub fn into_cli_error(self, context: &str) -> CliError {
        let msg = self
            .error_message
            .clone()
            .unwrap_or_else(|| self.fallback_message());
        let mut out = format!("{context}: {msg}");
        if let Some(hint) = &self.hint {
            out.push_str(&format!("\n  Hint: {hint}"));
        }
        CliError::Server(out)
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

    async fn parse_response(
        &self,
        resp: reqwest::Response,
        context: &str,
    ) -> Result<Value, CliError> {
        check_version_header(&resp);
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| CliError::Server(format!("{context}: {e}")))?;
        if !status.is_success() {
            return Err(ServerError::from_response(status.as_u16(), text).into_cli_error(context));
        }
        serde_json::from_str(&text)
            .map_err(|e| CliError::Server(format!("{context}: invalid JSON: {e}")))
    }

    async fn parse_response_detailed(&self, resp: reqwest::Response) -> Result<Value, ServerError> {
        check_version_header(&resp);
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

    pub async fn create_request(
        &self,
        req: CreateRequest<'_>,
    ) -> Result<(String, String, Vec<String>), CliError> {
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
            .timeout(API_TIMEOUT)
            .bearer_auth(&self.api_token)
            .json(&body)
            .send()
            .await
            .map_err(|_| {
                ServerError::from_response(0, "create request failed".into())
                    .into_cli_error("create request")
            })?;

        let body = self.parse_response(resp, "create request").await?;

        let cr: dbward_api_types::requests::CreateRequestResponse = serde_json::from_value(body)
            .map_err(|e| CliError::Server(format!("create request: invalid response: {e}")))?;
        let id = cr.id;
        let status = cr.status.as_str().to_string();
        let approvers = cr.approvers;

        Ok((id, status, approvers))
    }

    pub async fn list_requests(
        &self,
        limit: Option<u32>,
        status: Option<&str>,
        database: Option<&str>,
        environment: Option<&str>,
        user: Option<&str>,
    ) -> Result<Value, CliError> {
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
            .timeout(API_TIMEOUT)
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| CliError::Server(format!("list requests failed: {e}")))?;

        self.parse_response(resp, "list requests").await
    }

    pub async fn list_pending_for_me(&self, limit: Option<u32>) -> Result<Value, CliError> {
        let mut url = format!("{}/api/requests?pending_for_me=true", self.base_url);
        if let Some(l) = limit {
            url = format!("{url}&limit={l}");
        }
        let resp = self
            .client
            .get(&url)
            .timeout(API_TIMEOUT)
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| CliError::Server(format!("list pending-for-me failed: {e}")))?;

        self.parse_response(resp, "list pending-for-me").await
    }

    pub async fn get_request(&self, request_id: &str) -> Result<Value, CliError> {
        self.get_request_with_wait(request_id, 0).await
    }

    pub async fn get_request_with_wait(
        &self,
        request_id: &str,
        wait: u64,
    ) -> Result<Value, CliError> {
        let mut url = format!("{}/api/requests/{}", self.base_url, request_id);
        if wait > 0 {
            url = format!("{url}?wait={wait}");
        }
        let timeout = if wait > 0 {
            Duration::from_secs(wait + 30)
        } else {
            API_TIMEOUT
        };
        let resp = self
            .client
            .get(&url)
            .timeout(timeout)
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| CliError::Server(format!("get request failed: {e}")))?;

        self.parse_response(resp, "get request").await
    }

    pub async fn resume(&self, request_id: &str) -> Result<Value, ServerError> {
        let resp = self
            .client
            .post(format!(
                "{}/api/requests/{}/resume",
                self.base_url, request_id
            ))
            .timeout(API_TIMEOUT)
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| ServerError::from_response(0, format!("resume failed: {e}")))?;

        self.parse_response_detailed(resp).await
    }

    pub async fn stream_result(&self, request_id: &str) -> Result<Value, CliError> {
        let resp = self
            .client
            .get(format!(
                "{}/api/requests/{}/result/stream",
                self.base_url, request_id
            ))
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| CliError::Server(format!("stream result failed: {e}")))?;

        self.parse_response(resp, "stream result").await
    }

    pub async fn approve(
        &self,
        request_id: &str,
        comment: Option<&str>,
    ) -> Result<Value, ServerError> {
        let body = match comment {
            Some(c) => serde_json::json!({ "comment": c }),
            None => serde_json::json!({}),
        };
        let resp = self
            .client
            .post(format!(
                "{}/api/requests/{}/approve",
                self.base_url, request_id
            ))
            .timeout(API_TIMEOUT)
            .bearer_auth(&self.api_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| ServerError::from_response(0, format!("approve failed: {e}")))?;

        self.parse_response_detailed(resp).await
    }

    pub async fn reject(
        &self,
        request_id: &str,
        comment: Option<&str>,
    ) -> Result<Value, ServerError> {
        let body = match comment {
            Some(c) => serde_json::json!({ "comment": c }),
            None => serde_json::json!({}),
        };
        let resp = self
            .client
            .post(format!(
                "{}/api/requests/{}/reject",
                self.base_url, request_id
            ))
            .timeout(API_TIMEOUT)
            .bearer_auth(&self.api_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| ServerError::from_response(0, format!("reject failed: {e}")))?;

        self.parse_response_detailed(resp).await
    }

    pub async fn cancel_request(
        &self,
        request_id: &str,
        reason: Option<&str>,
    ) -> Result<Value, ServerError> {
        let body = match reason {
            Some(r) => serde_json::json!({ "reason": r }),
            None => serde_json::json!({}),
        };
        let resp = self
            .client
            .post(format!(
                "{}/api/requests/{}/cancel",
                self.base_url, request_id
            ))
            .timeout(API_TIMEOUT)
            .bearer_auth(&self.api_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| ServerError::from_response(0, format!("cancel failed: {e}")))?;

        self.parse_response_detailed(resp).await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn list_audit_events(
        &self,
        limit: Option<u32>,
        user: Option<&str>,
        operation: Option<&str>,
        status: Option<&str>,
        event_type: Option<&str>,
        category: Option<&str>,
        outcome: Option<&str>,
        environment: Option<&str>,
        since: Option<&str>,
        until: Option<&str>,
    ) -> Result<Value, CliError> {
        let mut parts: Vec<String> = Vec::new();
        if let Some(l) = limit {
            parts.push(format!("limit={l}"));
        }
        if let Some(u) = user {
            parts.push(format!("actor_id={u}"));
        }
        if let Some(v) = operation {
            parts.push(format!("operation={v}"));
        }
        if let Some(v) = status {
            parts.push(format!("status={v}"));
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
            .timeout(API_TIMEOUT)
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| CliError::Server(format!("list audit events: {e}")))?;
        self.parse_response(resp, "list audit events").await
    }

    pub async fn get_json(&self, path: &str) -> Result<Value, CliError> {
        let resp = self
            .client
            .get(format!("{}{}", self.base_url, path))
            .timeout(API_TIMEOUT)
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| CliError::Server(format!("get {path}: {e}")))?;
        self.parse_response(resp, path).await
    }

    /// GET with status code for MCP tools that need granular error handling.
    pub async fn get_json_with_status(&self, path: &str) -> Result<(u16, Value), CliError> {
        let resp = self
            .client
            .get(format!("{}{}", self.base_url, path))
            .timeout(API_TIMEOUT)
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| CliError::Server(format!("get {path}: {e}")))?;
        let status = resp.status().as_u16();
        let text = resp
            .text()
            .await
            .map_err(|e| CliError::Server(format!("get {path}: failed to read body: {e}")))?;
        let body: Value = serde_json::from_str(&text).map_err(|_| {
            CliError::Server(format!(
                "get {path}: server returned non-JSON response (HTTP {status})"
            ))
        })?;
        Ok((status, body))
    }

    pub async fn get_result_content(
        &self,
        request_id: &str,
        execution_id: Option<&str>,
    ) -> Result<Value, CliError> {
        let mut url = format!(
            "{}/api/requests/{}/result/content",
            self.base_url, request_id
        );
        if let Some(eid) = execution_id {
            url.push_str(&format!("?execution_id={eid}"));
        }
        let resp = self
            .client
            .get(&url)
            .timeout(API_TIMEOUT)
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| CliError::Server(format!("get result: {e}")))?;
        check_version_header(&resp);
        self.parse_response(resp, "get result content").await
    }

    pub async fn get_executions(&self, request_id: &str, limit: u32) -> Result<Value, CliError> {
        let resp = self
            .client
            .get(format!(
                "{}/api/requests/{}/executions?limit={limit}",
                self.base_url, request_id
            ))
            .timeout(API_TIMEOUT)
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| CliError::Server(format!("get executions: {e}")))?;
        self.parse_response(resp, "get executions").await
    }

    pub async fn list_results(&self, limit: u32) -> Result<Value, CliError> {
        let resp = self
            .client
            .get(format!("{}/api/results?limit={limit}", self.base_url))
            .timeout(API_TIMEOUT)
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| CliError::Server(format!("list results: {e}")))?;
        self.parse_response(resp, "list results").await
    }

    pub async fn get(&self, path: &str) -> Result<Value, CliError> {
        let resp = self
            .client
            .get(format!("{}{path}", self.base_url))
            .timeout(API_TIMEOUT)
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| CliError::Server(format!("GET {path}: {e}")))?;
        self.parse_response(resp, path).await
    }

    pub async fn patch(
        &self,
        path: &str,
        body: &serde_json::Map<String, Value>,
    ) -> Result<Value, CliError> {
        let resp = self
            .client
            .patch(format!("{}{path}", self.base_url))
            .timeout(API_TIMEOUT)
            .bearer_auth(&self.api_token)
            .json(body)
            .send()
            .await
            .map_err(|e| CliError::Server(format!("PATCH {path}: {e}")))?;
        self.parse_response(resp, path).await
    }
    pub async fn create_token(&self, body: &Value) -> Result<Value, CliError> {
        let resp = self
            .client
            .post(format!("{}/api/tokens", self.base_url))
            .timeout(API_TIMEOUT)
            .bearer_auth(&self.api_token)
            .json(body)
            .send()
            .await
            .map_err(|e| CliError::Server(format!("request failed: {e}")))?;
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        if status == 201 {
            serde_json::from_str(&text)
                .map_err(|e| CliError::Server(format!("invalid response: {e}")))
        } else {
            Err(ServerError::from_response(status, text).into_cli_error("token create"))
        }
    }

    pub async fn list_tokens(&self) -> Result<Value, CliError> {
        self.get_json("/api/tokens").await
    }

    pub async fn revoke_token(&self, id: &str) -> Result<Value, CliError> {
        let resp = self
            .client
            .delete(format!("{}/api/tokens/{id}", self.base_url))
            .timeout(API_TIMEOUT)
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| CliError::Server(format!("request failed: {e}")))?;
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        if status == 200 {
            serde_json::from_str(&text)
                .map_err(|e| CliError::Server(format!("invalid response: {e}")))
        } else {
            Err(ServerError::from_response(status, text).into_cli_error("token revoke"))
        }
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

        match err.into_cli_error("resume") {
            CliError::Server(msg) => assert_eq!(msg, "resume: <html>bad gateway</html>"),
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn hides_transport_error_details_in_cli_error() {
        let err = ServerError::from_response(
            0,
            "resume failed: error sending request for url (https://user:secret@example.com)".into(),
        );

        match err.into_cli_error("resume") {
            CliError::Server(msg) => {
                assert!(msg.contains("resume: request failed before receiving a server response"));
                assert!(!msg.contains("secret"));
                assert!(!msg.contains("https://"));
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }
}
