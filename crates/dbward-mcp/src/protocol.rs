use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PROTOCOL_VERSION: &str = "2025-03-26";
pub const SERVER_NAME: &str = "dbward";
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

// --- JSON-RPC base types ---

#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcResponse {
    pub fn success(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: Option<Value>, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

// --- Error codes ---

pub const PARSE_ERROR: i32 = -32700;
pub const INVALID_REQUEST: i32 = -32600;
pub const METHOD_NOT_FOUND: i32 = -32601;
pub const INVALID_PARAMS: i32 = -32602;
pub const INTERNAL_ERROR: i32 = -32603;
pub const RESOURCE_NOT_FOUND: i32 = -32002;

// --- Initialize ---

#[derive(Debug, Deserialize)]
pub struct InitializeParams {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    #[serde(default)]
    pub capabilities: ClientCapabilities,
    #[serde(rename = "clientInfo", default)]
    pub client_info: Option<ClientInfo>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ClientCapabilities {
    #[serde(default)]
    pub elicitation: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct ClientInfo {
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct InitializeResult {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    pub capabilities: ServerCapabilities,
    #[serde(rename = "serverInfo")]
    pub server_info: ServerInfo,
}

#[derive(Debug, Serialize)]
pub struct ServerCapabilities {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompts: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

/// Handle initialize request. Returns error response if version unsupported.
pub fn handle_initialize(id: Option<Value>, params: Value) -> JsonRpcResponse {
    let parsed: InitializeParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => {
            return JsonRpcResponse::error(id, INVALID_PARAMS, format!("Invalid params: {e}"));
        }
    };

    if parsed.protocol_version != PROTOCOL_VERSION {
        return JsonRpcResponse::error(
            id,
            INVALID_PARAMS,
            format!(
                "Unsupported protocol version '{}'. Only '{}' is supported.",
                parsed.protocol_version, PROTOCOL_VERSION
            ),
        );
    }

    let result = InitializeResult {
        protocol_version: PROTOCOL_VERSION.into(),
        capabilities: ServerCapabilities {
            tools: Some(serde_json::json!({})),
            resources: Some(serde_json::json!({})),
            prompts: Some(serde_json::json!({})),
        },
        server_info: ServerInfo {
            name: SERVER_NAME.into(),
            version: SERVER_VERSION.into(),
        },
    };

    JsonRpcResponse::success(
        id,
        serde_json::to_value(&result).unwrap_or_else(
            |_| serde_json::json!({"error": "failed to serialize initialize result"}),
        ),
    )
}

/// Returns true if the method is a notification (no id expected in response).
pub fn is_notification(method: &str) -> bool {
    method.starts_with("notifications/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn initialize_success() {
        let resp = handle_initialize(
            Some(json!(1)),
            json!({"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "test"}}),
        );
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["protocolVersion"], "2025-03-26");
        assert_eq!(result["serverInfo"]["name"], "dbward");
    }

    #[test]
    fn initialize_unsupported_version() {
        let resp = handle_initialize(
            Some(json!(1)),
            json!({"protocolVersion": "2024-11-05", "capabilities": {}}),
        );
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, INVALID_PARAMS);
    }

    #[test]
    fn notification_detection() {
        assert!(is_notification("notifications/initialized"));
        assert!(is_notification("notifications/cancelled"));
        assert!(!is_notification("tools/list"));
        assert!(!is_notification("initialize"));
    }
}
