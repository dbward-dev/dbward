use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Claimed,
    Running,
    /// Internal transient state: CAS acquired, awaiting storage write + final commit.
    /// Never exposed in external APIs (mapped to "running" via `as_api_str()`).
    /// WARNING: Do not serialize `Execution` directly to API responses.
    /// Always use `status.as_api_str()` for external-facing status strings.
    Completing,
    Completed,
    Failed,
}

impl ExecutionStatus {
    /// API-safe string representation. `Completing` is mapped to `"running"`
    /// because it is an internal transient state not exposed to clients.
    pub fn as_api_str(&self) -> &'static str {
        match self {
            Self::Claimed => "claimed",
            Self::Running => "running",
            Self::Completing => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Execution {
    pub id: String,
    pub request_id: String,
    pub agent_id: String,
    pub status: ExecutionStatus,
    pub token: String,
    pub lease_expires_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
}
