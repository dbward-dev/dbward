use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const PROTOCOL_VERSION: &str = "2025-03-26";
pub const SERVER_NAME: &str = "dbward";
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

// --- JSON-RPC message types (Phase 2) ---

/// Classified incoming JSON-RPC message.
#[derive(Debug)]
pub enum JsonRpcMessage {
    Request(JsonRpcRequest),
    Notification(JsonRpcNotification),
    Response(JsonRpcIncomingResponse),
    Batch(Vec<JsonRpcMessage>),
}

/// A JSON-RPC notification (method present, id absent).
#[derive(Debug, Deserialize)]
pub struct JsonRpcNotification {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

/// An incoming JSON-RPC response from the client (e.g. elicitation response).
#[derive(Debug, Deserialize)]
pub struct JsonRpcIncomingResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(default)]
    pub result: Option<Value>,
    #[serde(default)]
    pub error: Option<Value>,
}

/// Parse raw JSON bytes into a classified JsonRpcMessage.
pub fn parse_message(body: &[u8]) -> Result<JsonRpcMessage, Box<JsonRpcResponse>> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|_| Box::new(JsonRpcResponse::error(None, PARSE_ERROR, "Parse error")))?;

    if let Some(arr) = value.as_array() {
        if arr.is_empty() {
            return Err(Box::new(JsonRpcResponse::error(
                None,
                INVALID_REQUEST,
                "Invalid Request: empty batch",
            )));
        }
        let mut msgs = Vec::with_capacity(arr.len());
        for item in arr {
            msgs.push(classify_single(item.clone())?);
        }
        return Ok(JsonRpcMessage::Batch(msgs));
    }

    classify_single(value)
}

fn classify_single(value: Value) -> Result<JsonRpcMessage, Box<JsonRpcResponse>> {
    // Validate jsonrpc field
    match value.get("jsonrpc").and_then(|v| v.as_str()) {
        Some("2.0") => {}
        _ => {
            return Err(Box::new(JsonRpcResponse::error(
                value.get("id").cloned(),
                INVALID_REQUEST,
                "Invalid Request: jsonrpc must be \"2.0\"",
            )));
        }
    }

    let has_method = value.get("method").and_then(|v| v.as_str()).is_some();
    let id_field = value.get("id");
    let has_id = id_field.is_some();

    // Validate id field: must be string or number (not null, not object/array/bool)
    if let Some(id) = id_field {
        if id.is_null() {
            return Err(Box::new(JsonRpcResponse::error(
                None,
                INVALID_REQUEST,
                "Invalid Request: id must not be null",
            )));
        }
        if !id.is_string() && !id.is_number() {
            return Err(Box::new(JsonRpcResponse::error(
                Some(id.clone()),
                INVALID_REQUEST,
                "Invalid Request: id must be a string or number",
            )));
        }
    }

    match (has_method, has_id) {
        (true, true) => {
            let req: JsonRpcRequest = serde_json::from_value(value.clone()).map_err(|_| {
                Box::new(JsonRpcResponse::error(
                    value.get("id").cloned(),
                    INVALID_REQUEST,
                    "Invalid Request",
                ))
            })?;
            Ok(JsonRpcMessage::Request(req))
        }
        (true, false) => {
            let notif: JsonRpcNotification = serde_json::from_value(value).map_err(|_| {
                Box::new(JsonRpcResponse::error(
                    None,
                    INVALID_REQUEST,
                    "Invalid Notification",
                ))
            })?;
            Ok(JsonRpcMessage::Notification(notif))
        }
        (false, true) => {
            let resp: JsonRpcIncomingResponse =
                serde_json::from_value(value.clone()).map_err(|_| {
                    Box::new(JsonRpcResponse::error(
                        value.get("id").cloned(),
                        INVALID_REQUEST,
                        "Invalid Response",
                    ))
                })?;
            Ok(JsonRpcMessage::Response(resp))
        }
        (false, false) => Err(Box::new(JsonRpcResponse::error(
            None,
            INVALID_REQUEST,
            "Invalid JSON-RPC message",
        ))),
    }
}

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

/// Handle initialize request. Negotiates version (fallback to latest supported).
pub fn handle_initialize(id: Option<Value>, params: Value) -> JsonRpcResponse {
    const SUPPORTED: &[&str] = &["2025-03-26"];

    let parsed: InitializeParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => {
            return JsonRpcResponse::error(id, INVALID_PARAMS, format!("Invalid params: {e}"));
        }
    };

    // Negotiate: use client's version if supported, otherwise fall back to latest.
    // Per MCP spec, server returns its supported version and client decides whether to continue.
    let negotiated = SUPPORTED
        .iter()
        .find(|&&v| v == parsed.protocol_version)
        .unwrap_or(&SUPPORTED[0]);

    let result = InitializeResult {
        protocol_version: (*negotiated).into(),
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
    fn initialize_unsupported_version_falls_back() {
        let resp = handle_initialize(
            Some(json!(1)),
            json!({"protocolVersion": "2024-11-05", "capabilities": {}}),
        );
        // Should succeed with fallback to latest supported
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["protocolVersion"], "2025-03-26");
    }

    #[test]
    fn notification_detection() {
        assert!(is_notification("notifications/initialized"));
        assert!(is_notification("notifications/cancelled"));
        assert!(!is_notification("tools/list"));
        assert!(!is_notification("initialize"));
    }

    #[test]
    fn parse_message_request() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#;
        let msg = parse_message(body).unwrap();
        assert!(matches!(msg, JsonRpcMessage::Request(r) if r.method == "tools/list"));
    }

    #[test]
    fn parse_message_notification() {
        let body = br#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#;
        let msg = parse_message(body).unwrap();
        assert!(matches!(msg, JsonRpcMessage::Notification(n) if n.method == "notifications/initialized"));
    }

    #[test]
    fn parse_message_response() {
        let body = br#"{"jsonrpc":"2.0","id":"elicit-1","result":{"action":"accept","content":{}}}"#;
        let msg = parse_message(body).unwrap();
        assert!(matches!(msg, JsonRpcMessage::Response(r) if r.id == json!("elicit-1")));
    }

    #[test]
    fn parse_message_batch() {
        let body = br#"[{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}},{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}]"#;
        let msg = parse_message(body).unwrap();
        assert!(matches!(msg, JsonRpcMessage::Batch(v) if v.len() == 2));
    }

    #[test]
    fn parse_message_empty_batch() {
        let body = b"[]";
        let err = parse_message(body).unwrap_err();
        assert_eq!(err.error.unwrap().code, INVALID_REQUEST);
    }

    #[test]
    fn parse_message_invalid_json() {
        let body = b"not json";
        let err = parse_message(body).unwrap_err();
        assert_eq!(err.error.unwrap().code, PARSE_ERROR);
    }

    #[test]
    fn parse_message_no_method_no_id() {
        let body = br#"{"jsonrpc":"2.0"}"#;
        let err = parse_message(body).unwrap_err();
        assert_eq!(err.error.unwrap().code, INVALID_REQUEST);
    }

    #[test]
    fn parse_message_invalid_jsonrpc_version() {
        let body = br#"{"jsonrpc":"1.0","id":1,"method":"tools/list"}"#;
        let err = parse_message(body).unwrap_err();
        let e = err.error.unwrap();
        assert_eq!(e.code, INVALID_REQUEST);
        assert!(e.message.contains("2.0"));
    }

    #[test]
    fn parse_message_missing_jsonrpc_field() {
        let body = br#"{"id":1,"method":"tools/list"}"#;
        let err = parse_message(body).unwrap_err();
        assert_eq!(err.error.unwrap().code, INVALID_REQUEST);
    }

    #[test]
    fn parse_message_null_id_rejected() {
        let body = br#"{"jsonrpc":"2.0","id":null,"method":"tools/list"}"#;
        let err = parse_message(body).unwrap_err();
        let e = err.error.unwrap();
        assert_eq!(e.code, INVALID_REQUEST);
        assert!(e.message.contains("null"));
    }

    #[test]
    fn parse_message_object_id_rejected() {
        let body = br#"{"jsonrpc":"2.0","id":{},"method":"tools/list"}"#;
        let err = parse_message(body).unwrap_err();
        assert_eq!(err.error.unwrap().code, INVALID_REQUEST);
    }

    #[test]
    fn parse_message_array_id_rejected() {
        let body = br#"{"jsonrpc":"2.0","id":[],"method":"tools/list"}"#;
        let err = parse_message(body).unwrap_err();
        assert_eq!(err.error.unwrap().code, INVALID_REQUEST);
    }

    #[test]
    fn parse_message_bool_id_rejected() {
        let body = br#"{"jsonrpc":"2.0","id":true,"method":"tools/list"}"#;
        let err = parse_message(body).unwrap_err();
        assert_eq!(err.error.unwrap().code, INVALID_REQUEST);
    }
}
