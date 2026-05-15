use serde::{Deserialize, Serialize};

/// POST /api/agent/poll — request body
#[derive(Debug, Serialize, Deserialize)]
pub struct PollRequest {
    #[serde(default)]
    pub agent_id: Option<String>,
    pub capabilities: PollCapabilities,
    #[serde(default)]
    pub status: Option<AgentStatusReport>,
    #[serde(default = "default_limit")]
    pub limit: u32,
}

/// Capabilities declared by the agent.
#[derive(Debug, Serialize, Deserialize)]
pub struct PollCapabilities {
    pub databases: Vec<String>,
    #[serde(default)]
    pub environments: Vec<String>,
    #[serde(default)]
    pub operations: Vec<String>,
}

fn default_limit() -> u32 {
    1
}

/// POST /api/agent/poll — response
#[derive(Debug, Serialize, Deserialize)]
pub struct PollResponse {
    pub jobs: Vec<Job>,
}

/// A job returned from poll.
#[derive(Debug, Serialize, Deserialize)]
pub struct Job {
    pub id: String,
    pub database: String,
    pub environment: String,
    pub operation: String,
}

/// POST /api/agent/jobs/{id}/claim — response
#[derive(Debug, Serialize, Deserialize)]
pub struct ClaimResponse {
    pub execution_id: String,
    pub request_id: String,
    pub operation: String,
    pub environment: String,
    pub database: String,
    pub detail: String,
    pub execution_token: String,
    #[serde(default)]
    pub statement_timeout_secs: Option<u64>,
    #[serde(default)]
    pub max_rows: Option<u32>,
    #[serde(default)]
    pub lease_expires_at: Option<String>,
}

/// POST /api/agent/jobs/{id}/heartbeat — response
#[derive(Debug, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub cancelled: bool,
}

/// POST /api/agent/jobs/{id}/result — request body
#[derive(Debug, Serialize, Deserialize)]
pub struct ResultBody {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rows_affected: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_rows: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub duration_ms: Option<u64>,
}

/// Agent status report sent with each poll.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatusReport {
    pub in_flight: u32,
    pub max_concurrent: u32,
    #[serde(default)]
    pub draining: bool,
    #[serde(default)]
    pub uptime_secs: u64,
    #[serde(default)]
    pub active_jobs: Vec<ActiveJob>,
}

/// An active job reported by the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveJob {
    pub request_id: String,
    pub operation: String,
    #[serde(default)]
    pub elapsed_secs: u64,
}
