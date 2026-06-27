use serde_json::{Value, json};

use dbward_domain::auth::AuthUser;

use crate::ports::{ElicitationTransport, McpBackend};
use crate::protocol::{self, INVALID_PARAMS, JsonRpcRequest, JsonRpcResponse, METHOD_NOT_FOUND};
use crate::tools::ToolContext;
use crate::{defs, prompts, resources};

/// Handle a parsed JSON-RPC request and return a response.
/// Returns None for notifications (no response expected).
pub async fn handle_request(
    req: JsonRpcRequest,
    backend: &dyn McpBackend,
    elicit: &dyn ElicitationTransport,
    user: &AuthUser,
    default_database: &str,
    default_environment: &str,
) -> Option<JsonRpcResponse> {
    // Notifications: no id field → no response
    #[allow(clippy::question_mark)]
    if req.id.is_none() {
        return None;
    }
    // Method-based notification with id present: acknowledge with empty result
    if protocol::is_notification(&req.method) {
        return Some(JsonRpcResponse::success(req.id, json!(null)));
    }

    let resp = match req.method.as_str() {
        "initialize" => protocol::handle_initialize(req.id, req.params),

        "tools/list" => {
            JsonRpcResponse::success(req.id, json!({"tools": defs::tools_definitions()}))
        }

        "tools/call" => {
            handle_tools_call(
                req.id.clone(),
                &req.params,
                backend,
                elicit,
                user,
                default_database,
                default_environment,
            )
            .await
        }

        "resources/list" => {
            JsonRpcResponse::success(req.id, json!({"resources": defs::resources_definitions()}))
        }

        "resources/templates/list" => JsonRpcResponse::success(
            req.id,
            json!({"resourceTemplates": defs::resource_templates_definitions()}),
        ),

        "resources/read" => {
            handle_resources_read(
                req.id.clone(),
                &req.params,
                backend,
                user,
                default_database,
                default_environment,
            )
            .await
        }

        "prompts/list" => {
            JsonRpcResponse::success(req.id, json!({"prompts": defs::prompts_definitions()}))
        }

        "prompts/get" => handle_prompts_get(req.id.clone(), &req.params),

        _ => JsonRpcResponse::error(
            req.id,
            METHOD_NOT_FOUND,
            format!("Method not found: {}", req.method),
        ),
    };

    Some(resp)
}

async fn handle_tools_call(
    id: Option<Value>,
    params: &Value,
    backend: &dyn McpBackend,
    elicit: &dyn ElicitationTransport,
    user: &AuthUser,
    default_database: &str,
    default_environment: &str,
) -> JsonRpcResponse {
    let tool_name = match params["name"].as_str() {
        Some(n) if !n.is_empty() => n,
        _ => {
            return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing required parameter: name");
        }
    };

    let args = match &params["arguments"] {
        v if v.is_object() => v,
        v if v.is_null() => &json!({}),
        _ => {
            return JsonRpcResponse::error(
                id,
                INVALID_PARAMS,
                "Invalid params: arguments must be an object",
            );
        }
    };

    let ctx = ToolContext {
        backend,
        elicit,
        user,
        default_database,
        default_environment,
    };

    let Some((text, is_error)) = crate::tools::dispatch(&ctx, tool_name, args).await else {
        return JsonRpcResponse::error(id, METHOD_NOT_FOUND, format!("Unknown tool: {tool_name}"));
    };

    JsonRpcResponse::success(
        id,
        json!({
            "content": [{"type": "text", "text": text}],
            "isError": is_error,
        }),
    )
}

async fn handle_resources_read(
    id: Option<Value>,
    params: &Value,
    backend: &dyn McpBackend,
    user: &AuthUser,
    default_database: &str,
    default_environment: &str,
) -> JsonRpcResponse {
    let uri = match params["uri"].as_str() {
        Some(u) if !u.is_empty() => u,
        _ => {
            return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing required parameter: uri");
        }
    };

    match resources::read_resource(uri, backend, user, default_database, default_environment).await
    {
        Ok(content) => JsonRpcResponse::success(
            id,
            json!({
                "contents": [{"uri": uri, "mimeType": "application/json", "text": content}]
            }),
        ),
        Err(e) => JsonRpcResponse::error(id, e.json_rpc_code(), e.message()),
    }
}

fn handle_prompts_get(id: Option<Value>, params: &Value) -> JsonRpcResponse {
    let name = match params["name"].as_str() {
        Some(n) if !n.is_empty() => n,
        _ => {
            return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing required parameter: name");
        }
    };

    let args = if params["arguments"].is_object() {
        &params["arguments"]
    } else {
        &json!({})
    };

    match prompts::get_prompt(name, args) {
        Ok((description, messages)) => JsonRpcResponse::success(
            id,
            json!({
                "description": description,
                "messages": messages,
            }),
        ),
        Err(msg) => JsonRpcResponse::error(id, INVALID_PARAMS, msg),
    }
}

/// Parse raw JSON bytes into a JsonRpcRequest.
#[allow(clippy::result_large_err)]
pub fn parse_request(body: &[u8]) -> Result<JsonRpcRequest, JsonRpcResponse> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|_| JsonRpcResponse::error(None, protocol::PARSE_ERROR, "Parse error"))?;

    if value.is_array() {
        return Err(JsonRpcResponse::error(
            None,
            protocol::INVALID_REQUEST,
            "Batch requests are not supported",
        ));
    }

    let req: JsonRpcRequest = serde_json::from_value(value.clone()).map_err(|_| {
        let id = value.get("id").cloned();
        JsonRpcResponse::error(id, protocol::INVALID_REQUEST, "Invalid Request")
    })?;

    if req.jsonrpc != "2.0" {
        return Err(JsonRpcResponse::error(
            req.id,
            protocol::INVALID_REQUEST,
            "Invalid Request: jsonrpc must be \"2.0\"",
        ));
    }

    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::{
        CreateRequestInput, CreateRequestOutput, McpResult, NoopElicitation,
        RequestStatus as McpStatus, WaitOutput,
    };
    use async_trait::async_trait;
    use dbward_domain::auth::{AuthUser, SubjectType};

    struct MockBackend;

    #[async_trait]
    impl McpBackend for MockBackend {
        async fn create_request(
            &self,
            _: CreateRequestInput,
            _: &AuthUser,
        ) -> McpResult<CreateRequestOutput> {
            Ok(CreateRequestOutput {
                request_id: "r-1".into(),
                status: McpStatus::Pending,
            })
        }
        async fn resume_and_wait(&self, _: &str, _: u64, _: &AuthUser) -> McpResult<WaitOutput> {
            Ok(WaitOutput::Completed("done".into()))
        }
        async fn wait_request(&self, _: &str, _: u64, _: &AuthUser) -> McpResult<WaitOutput> {
            Ok(WaitOutput::Completed("done".into()))
        }
        async fn list_pending(&self, _: u32, _: &AuthUser) -> McpResult<Value> {
            Ok(json!([]))
        }
        async fn find_similar(&self, _: &str, _: u32, _: &AuthUser) -> McpResult<Value> {
            Ok(json!([]))
        }
        async fn preview_impact(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: Option<String>,
            _: &AuthUser,
        ) -> McpResult<Value> {
            Ok(json!({"plan": "Seq Scan"}))
        }
        async fn who_can_approve(&self, _: &str, _: &AuthUser) -> McpResult<Value> {
            Ok(json!({"approvers": []}))
        }
        async fn explain_policy_failure(
            &self,
            _: Option<&str>,
            _: Option<&str>,
            _: &str,
            _: &str,
            _: &AuthUser,
        ) -> McpResult<Value> {
            Ok(json!({"reason": "workflow requires approval"}))
        }
        async fn inspect_schema(
            &self,
            _: &str,
            _: Option<&str>,
            _: Option<&str>,
            _: bool,
            _: &AuthUser,
        ) -> McpResult<Value> {
            Ok(json!({"tables": []}))
        }
        async fn get_request(&self, _: &str, _: &AuthUser) -> McpResult<Value> {
            Ok(json!({"id": "r-1", "status": "pending", "sql": "SELECT 1"}))
        }
        async fn list_databases(&self, _: &AuthUser) -> McpResult<Value> {
            Ok(json!([]))
        }
        async fn migrate_status(
            &self,
            _: &str,
            _: &str,
            _: Option<String>,
            _: &AuthUser,
        ) -> McpResult<Value> {
            Ok(json!({"applied": 3, "pending": 1}))
        }
        async fn audit_recent(&self, _: u32, _: &AuthUser) -> McpResult<Value> {
            Ok(json!([]))
        }
    }

    fn user() -> AuthUser {
        AuthUser {
            subject_id: "u1".into(),
            subject_type: SubjectType::User,
            groups: vec![],
            roles: vec![],
            token_id: None,
        }
    }

    #[tokio::test]
    async fn initialize_works() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(json!(1)),
            method: "initialize".into(),
            params: json!({"protocolVersion": "2025-03-26", "capabilities": {}}),
        };
        let resp = handle_request(req, &MockBackend, &NoopElicitation, &user(), "app", "dev").await;
        let resp = resp.unwrap();
        assert!(resp.error.is_none());
    }

    #[tokio::test]
    async fn tools_list_works() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(json!(2)),
            method: "tools/list".into(),
            params: json!({}),
        };
        let resp = handle_request(req, &MockBackend, &NoopElicitation, &user(), "app", "dev").await;
        let resp = resp.unwrap();
        let tools = resp.result.unwrap()["tools"].as_array().unwrap().len();
        assert_eq!(tools, 9);
    }

    #[tokio::test]
    async fn tools_call_execute_query() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(json!(3)),
            method: "tools/call".into(),
            params: json!({"name": "dbward_execute_query", "arguments": {"sql": "SELECT 1"}}),
        };
        let resp = handle_request(req, &MockBackend, &NoopElicitation, &user(), "app", "dev").await;
        let resp = resp.unwrap();
        let result = resp.result.unwrap();
        // MockBackend returns pending → "requires approval" message
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("requires approval"));
        assert!(!result["isError"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn notification_returns_none() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: None,
            method: "notifications/initialized".into(),
            params: json!({}),
        };
        let resp = handle_request(req, &MockBackend, &NoopElicitation, &user(), "app", "dev").await;
        assert!(resp.is_none());
    }

    #[tokio::test]
    async fn unknown_method_returns_error() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(json!(5)),
            method: "foo/bar".into(),
            params: json!({}),
        };
        let resp = handle_request(req, &MockBackend, &NoopElicitation, &user(), "app", "dev").await;
        let resp = resp.unwrap();
        assert_eq!(resp.error.unwrap().code, METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn unknown_tool_returns_json_rpc_error() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(json!(6)),
            method: "tools/call".into(),
            params: json!({"name": "nonexistent_tool", "arguments": {}}),
        };
        let resp = handle_request(req, &MockBackend, &NoopElicitation, &user(), "app", "dev").await;
        let resp = resp.unwrap();
        assert_eq!(resp.error.unwrap().code, METHOD_NOT_FOUND);
    }

    #[test]
    fn parse_request_valid() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#;
        let req = parse_request(body).unwrap();
        assert_eq!(req.method, "tools/list");
    }

    #[test]
    fn parse_request_invalid_json() {
        let body = b"not json";
        let err = parse_request(body).unwrap_err();
        assert_eq!(err.error.unwrap().code, protocol::PARSE_ERROR);
    }
}
