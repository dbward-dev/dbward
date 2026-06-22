use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::values::{DatabaseName, Environment, Operation};

/// The lifecycle status of a Request.
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
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Executed | Self::Failed | Self::Rejected | Self::Cancelled | Self::Expired
        )
    }

    pub fn is_dispatchable(&self) -> bool {
        matches!(self, Self::Approved | Self::AutoApproved | Self::BreakGlass)
    }

    pub fn is_re_dispatchable(&self) -> bool {
        matches!(self, Self::Executed | Self::Failed | Self::ExecutionLost)
    }

    pub fn is_cancellable(&self) -> bool {
        !matches!(
            self,
            Self::Executed | Self::Failed | Self::Rejected | Self::Cancelled | Self::Expired
        )
    }
}

impl std::fmt::Display for RequestStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
/// A request for a database operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub id: String,
    pub requester: String,
    pub database: DatabaseName,
    pub environment: Environment,
    pub operation: Operation,
    pub detail: String,
    pub status: RequestStatus,
    pub emergency: bool,
    pub reason: Option<String>,
    pub idempotency_key: Option<String>,
    pub idempotency_fingerprint: Option<String>,
    pub metadata_json: String,
    pub share_with: Vec<String>,
    pub no_result_store: bool,
    pub workflow_snapshot_json: Option<String>,
    pub decision_trace_json: Option<String>,
    /// Parser-derived statement texts for execution (SAFE-3).
    /// JSON array of canonical SQL strings from sqlparser.
    /// Agent executes these instead of raw `detail`.
    pub execution_plan_json: Option<String>,
    pub cancel_reason: Option<String>,
    pub cancelled_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_states() {
        assert!(RequestStatus::Executed.is_terminal());
        assert!(RequestStatus::Rejected.is_terminal());
        assert!(!RequestStatus::Pending.is_terminal());
        assert!(!RequestStatus::Running.is_terminal());
    }

    #[test]
    fn dispatchable() {
        assert!(RequestStatus::Approved.is_dispatchable());
        assert!(RequestStatus::AutoApproved.is_dispatchable());
        assert!(!RequestStatus::Pending.is_dispatchable());
    }

    #[test]
    fn cancellable() {
        assert!(RequestStatus::Pending.is_cancellable());
        assert!(RequestStatus::Dispatched.is_cancellable());
        assert!(RequestStatus::ExecutionLost.is_cancellable());
        assert!(RequestStatus::Running.is_cancellable());
        assert!(!RequestStatus::Executed.is_cancellable());
        assert!(!RequestStatus::Failed.is_cancellable());
        assert!(!RequestStatus::Rejected.is_cancellable());
        assert!(!RequestStatus::Cancelled.is_cancellable());
        assert!(!RequestStatus::Expired.is_cancellable());
    }
}
