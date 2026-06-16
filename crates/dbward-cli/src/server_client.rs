use std::sync::OnceLock;
use std::time::Duration;

use dbward_api_client::{ApiClient, ApiError, ResponseHook};
use serde_json::Value;

use crate::error::CliError;

const MAX_ERROR_BODY_PREVIEW: usize = 200;

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

fn version_check_hook() -> ResponseHook {
    Box::new(|resp: &reqwest::Response| {
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
    })
}

#[derive(Clone)]
pub struct ServerClient {
    api: ApiClient,
}

pub struct CreateRequest<'a> {
    pub operation: &'a str,
    pub environment: &'a str,
    pub database: &'a str,
    pub detail: &'a str,
    pub emergency: bool,
    pub allow_ddl: bool,
    pub reason: Option<&'a str>,
    pub metadata: Option<&'a serde_json::Value>,
    pub idempotency_key: Option<&'a str>,
    pub share_with: Option<&'a [String]>,
    pub no_result_store: bool,
}

impl ServerClient {
    pub fn new(base_url: &str, api_token: &str) -> Self {
        let api = ApiClient::new(
            base_url,
            api_token,
            Duration::from_secs(30),
            Duration::from_secs(10),
        )
        .expect("failed to build HTTP client")
        .with_response_hook(version_check_hook());
        Self { api }
    }

    pub async fn create_request(
        &self,
        req: CreateRequest<'_>,
    ) -> Result<
        (
            String,
            dbward_api_types::requests::RequestStatus,
            Vec<String>,
        ),
        CliError,
    > {
        let mut body = serde_json::json!({
            "operation": req.operation,
            "environment": req.environment,
            "database": req.database,
            "detail": req.detail,
        });
        if req.emergency {
            body["emergency"] = serde_json::json!(true);
        }
        if req.allow_ddl {
            body["allow_ddl"] = serde_json::json!(true);
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
        if req.no_result_store {
            body["no_result_store"] = serde_json::json!(true);
        }

        let (status, text) = self
            .api
            .post_with_status("/api/requests", &body)
            .await
            .map_err(|e| api_to_cli(e, "create request"))?;
        if status >= 400 {
            return Err(ServerError::from_response(status, text).into_cli_error("create request"));
        }
        let cr: dbward_api_types::requests::CreateRequestResponse = serde_json::from_str(&text)
            .map_err(|e| CliError::Server(format!("create request: invalid response: {e}")))?;
        Ok((cr.id, cr.status, cr.approvers))
    }

    pub async fn list_requests(
        &self,
        limit: Option<u32>,
        status: Option<&str>,
        database: Option<&str>,
        environment: Option<&str>,
        user: Option<&str>,
    ) -> Result<Value, CliError> {
        let mut url = "/api/requests".to_string();
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
        self.get_json(&url).await
    }

    pub async fn list_pending_for_me(&self, limit: Option<u32>) -> Result<Value, CliError> {
        let mut url = "/api/requests?pending_for_me=true".to_string();
        if let Some(l) = limit {
            url = format!("{url}&limit={l}");
        }
        self.get_json(&url).await
    }

    pub async fn get_request(&self, request_id: &str) -> Result<Value, CliError> {
        self.get_request_with_wait(request_id, 0).await
    }

    pub async fn get_request_with_wait(
        &self,
        request_id: &str,
        wait: u64,
    ) -> Result<Value, CliError> {
        let mut path = format!("/api/requests/{}", request_id);
        if wait > 0 {
            path = format!("{path}?wait={wait}");
        }
        if wait > 0 {
            let timeout = Duration::from_secs(wait + 30);
            self.api
                .get_with_timeout::<Value>(&path, timeout)
                .await
                .map_err(|e| api_to_cli(e, "get request"))
        } else {
            self.get_json(&path).await
        }
    }

    pub async fn resume(&self, request_id: &str) -> Result<Value, ServerError> {
        let path = format!("/api/requests/{}/resume", request_id);
        let (status, text) = self
            .api
            .post_empty_with_status(&path)
            .await
            .map_err(|e| ServerError::from_response(0, e.to_string()))?;
        if status >= 400 {
            return Err(ServerError::from_response(status, text));
        }
        serde_json::from_str(&text).map_err(|_| ServerError::from_response(status, text))
    }

    pub async fn stream_result(&self, request_id: &str) -> Result<Value, CliError> {
        let path = format!("/api/requests/{}/result/stream", request_id);
        self.api
            .get_with_timeout::<Value>(&path, Duration::from_secs(600))
            .await
            .map_err(|e| api_to_cli(e, "stream result"))
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
        let path = format!("/api/requests/{}/approve", request_id);
        let (status, text) = self
            .api
            .post_with_status(&path, &body)
            .await
            .map_err(|e| ServerError::from_response(0, e.to_string()))?;
        if status >= 400 {
            return Err(ServerError::from_response(status, text));
        }
        serde_json::from_str(&text).map_err(|_| ServerError::from_response(status, text))
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
        let path = format!("/api/requests/{}/reject", request_id);
        let (status, text) = self
            .api
            .post_with_status(&path, &body)
            .await
            .map_err(|e| ServerError::from_response(0, e.to_string()))?;
        if status >= 400 {
            return Err(ServerError::from_response(status, text));
        }
        serde_json::from_str(&text).map_err(|_| ServerError::from_response(status, text))
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
        let path = format!("/api/requests/{}/cancel", request_id);
        let (status, text) = self
            .api
            .post_with_status(&path, &body)
            .await
            .map_err(|e| ServerError::from_response(0, e.to_string()))?;
        if status >= 400 {
            return Err(ServerError::from_response(status, text));
        }
        serde_json::from_str(&text).map_err(|_| ServerError::from_response(status, text))
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
            "/api/audit/events".to_string()
        } else {
            format!("/api/audit/events?{}", parts.join("&"))
        };
        self.get_json(&url).await
    }

    pub async fn get_json(&self, path: &str) -> Result<Value, CliError> {
        self.api
            .get::<Value>(path)
            .await
            .map_err(|e| api_to_cli(e, path))
    }

    /// GET with status code for MCP tools that need granular error handling.
    pub async fn get_json_with_status(&self, path: &str) -> Result<(u16, Value), CliError> {
        let (status, text) = self
            .api
            .get_with_status(path)
            .await
            .map_err(|e| api_to_cli(e, path))?;
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
        let mut path = format!("/api/requests/{}/result/content", request_id);
        if let Some(eid) = execution_id {
            path.push_str(&format!("?execution_id={eid}"));
        }
        self.get_json(&path).await
    }

    pub async fn get_executions(&self, request_id: &str, limit: u32) -> Result<Value, CliError> {
        let path = format!("/api/requests/{}/executions?limit={limit}", request_id);
        self.get_json(&path).await
    }

    pub async fn list_results(&self, limit: u32) -> Result<Value, CliError> {
        let path = format!("/api/results?limit={limit}");
        self.get_json(&path).await
    }

    pub async fn get(&self, path: &str) -> Result<Value, CliError> {
        self.get_json(path).await
    }

    pub async fn patch(
        &self,
        path: &str,
        body: &serde_json::Map<String, Value>,
    ) -> Result<Value, CliError> {
        self.api
            .patch::<_, Value>(path, body)
            .await
            .map_err(|e| api_to_cli(e, path))
    }

    pub async fn create_token(&self, body: &Value) -> Result<Value, CliError> {
        let (status, text) = self
            .api
            .post_with_status("/api/tokens", body)
            .await
            .map_err(|e| api_to_cli(e, "token create"))?;
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
        let path = format!("/api/tokens/{id}");
        let (status, text) = self
            .api
            .delete_with_status(&path)
            .await
            .map_err(|e| api_to_cli(e, "token revoke"))?;
        if status == 200 {
            serde_json::from_str(&text)
                .map_err(|e| CliError::Server(format!("invalid response: {e}")))
        } else {
            Err(ServerError::from_response(status, text).into_cli_error("token revoke"))
        }
    }
}

fn api_to_cli(e: ApiError, context: &str) -> CliError {
    match e {
        ApiError::Http { status, body } => {
            ServerError::from_response(status, body).into_cli_error(context)
        }
        ApiError::Network(e) => CliError::Server(format!("{context}: {e}")),
        ApiError::Deserialize(msg) => CliError::Server(format!("{context}: invalid JSON: {msg}")),
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
