use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalAction {
    Approve,
    Reject,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub id: String,
    pub request_id: String,
    pub action: ApprovalAction,
    pub actor_id: String,
    /// Which selector this approval counts for (e.g. "role:admin", "group:dba-team").
    /// Needed for the "1 approval = 1 role/group count" rule.
    pub matched_selector: String,
    pub step_index: u32,
    pub comment: Option<String>,
    pub created_at: DateTime<Utc>,
}
