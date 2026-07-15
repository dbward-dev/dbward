use serde::{Deserialize, Serialize};

/// Request status as returned by the API.
/// Mirrors domain::RequestStatus with an additional `Unknown` variant for forward-compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestStatus {
    Pending,
    Approved,
    AutoApproved,
    BreakGlass,
    Dispatched,
    Running,
    Executed,
    Failed,
    Rejected,
    Cancelled,
    Expired,
    ExecutionLost,
    /// Forward-compatibility: unknown status from newer server version.
    #[serde(other)]
    Unknown,
}

impl RequestStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::AutoApproved => "auto_approved",
            Self::BreakGlass => "break_glass",
            Self::Dispatched => "dispatched",
            Self::Running => "running",
            Self::Executed => "executed",
            Self::Failed => "failed",
            Self::Rejected => "rejected",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::ExecutionLost => "execution_lost",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for RequestStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl RequestStatus {
    /// Parse from a JSON Value (e.g. `resp["status"]`). Returns Unknown for null/unrecognized.
    pub fn from_json(v: &serde_json::Value) -> Self {
        serde_json::from_value(v.clone()).unwrap_or(Self::Unknown)
    }
}

/// POST /api/requests — request body
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateRequestBody {
    pub database: String,
    pub environment: String,
    #[serde(default)]
    pub operation: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    #[serde(default)]
    pub emergency: bool,
    #[serde(default)]
    pub allow_ddl: bool,
    #[serde(default)]
    pub no_result_store: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub share_with: Vec<String>,
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
    #[serde(alias = "requester")]
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
    #[serde(alias = "requester")]
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
