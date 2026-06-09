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
    #[serde(default)]
    pub agent_version: Option<String>,
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
    #[serde(default)]
    pub dry_run_jobs: Vec<DryRunJob>,
    #[serde(default)]
    pub server_version: Option<String>,
    #[serde(default)]
    pub min_agent_version: Option<String>,
    #[serde(default)]
    pub upgrade_required: bool,
}

/// A dry-run EXPLAIN job for the agent to execute.
#[derive(Debug, Serialize, Deserialize)]
pub struct DryRunJob {
    pub id: String,
    pub request_id: String,
    pub database: String,
    pub environment: String,
    pub sql: String,
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
    /// Parser-derived statement texts (SAFE-3). When present, agent executes
    /// these instead of raw `detail`. Old agents ignore via #[serde(default)].
    #[serde(default)]
    pub execution_plan: Option<Vec<String>>,
    /// Raw JSON string of execution_plan for hash verification (avoids re-serialization).
    #[serde(default)]
    pub execution_plan_json: Option<String>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poll_response_backward_compat_no_dry_run_jobs() {
        // Old server response without dry_run_jobs field
        let json = r#"{"jobs":[],"server_version":"0.1.2"}"#;
        let resp: PollResponse = serde_json::from_str(json).unwrap();
        assert!(resp.jobs.is_empty());
        assert!(resp.dry_run_jobs.is_empty());
        assert_eq!(resp.server_version.as_deref(), Some("0.1.2"));
    }

    #[test]
    fn poll_response_with_dry_run_jobs() {
        let json = r#"{"jobs":[],"dry_run_jobs":[{"id":"j1","request_id":"r1","database":"app","environment":"prod","sql":"SELECT 1"}]}"#;
        let resp: PollResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.dry_run_jobs.len(), 1);
        assert_eq!(resp.dry_run_jobs[0].id, "j1");
        assert_eq!(resp.dry_run_jobs[0].sql, "SELECT 1");
    }
}
