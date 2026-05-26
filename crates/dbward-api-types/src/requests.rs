use serde::{Deserialize, Serialize};

/// Request status as returned by the API.
pub type RequestStatus = String;

/// POST /api/requests — request body
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateRequestBody {
    pub database: String,
    pub environment: String,
    pub operation: String,
    pub detail: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    #[serde(default)]
    pub emergency: bool,
    #[serde(default)]
    pub no_store: bool,
}

/// POST /api/requests — response
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateRequestResponse {
    pub id: String,
    pub status: RequestStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_token: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approvers: Vec<String>,
}

/// POST /api/requests/{id}/approve — response
#[derive(Debug, Serialize, Deserialize)]
pub struct ApproveResponse {
    pub id: String,
    pub status: RequestStatus,
    pub approved_by: String,
    pub step_completed: u32,
    pub current_step: u32,
    pub total_steps: u32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_token: Option<serde_json::Value>,
}

/// Simple status response (used by resume, reject, cancel)
#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    pub id: String,
    pub status: RequestStatus,
}

/// POST /api/requests/{id}/resume — response
pub type ResumeResponse = StatusResponse;

/// GET /api/requests — response
#[derive(Debug, Serialize, Deserialize)]
pub struct ListRequestsResponse {
    pub requests: Vec<RequestSummary>,
    pub total: u64,
    pub limit: u64,
    pub offset: u64,
}

/// Summary of a request in list responses.
#[derive(Debug, Serialize, Deserialize)]
pub struct RequestSummary {
    pub id: String,
    pub status: RequestStatus,
    pub created_by: String,
    pub database: String,
    pub environment: String,
    pub operation: String,
    pub created_at: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// GET /api/requests/{id} — response
#[derive(Debug, Serialize, Deserialize)]
pub struct RequestDetail {
    pub id: String,
    pub status: RequestStatus,
    pub created_by: String,
    pub database: String,
    pub environment: String,
    pub operation: String,
    pub detail: serde_json::Value,
    pub created_at: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claimed_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_token: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_progress: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reject_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// Execution result (from stream_result or storage)
#[derive(Debug, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub success: bool,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
