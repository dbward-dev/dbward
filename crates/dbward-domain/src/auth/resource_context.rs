use crate::policies::workflow::ApproverGroup;

/// Context about the resource being acted upon. Used in Layer 2 authorization.
#[derive(Debug, Clone)]
pub enum ResourceContext {
    /// No resource-level check needed (manage_* operations).
    Global,
    /// Request operations: ownership check.
    Request { requester_id: String },
    /// Approval operations: workflow approvers + constraints.
    ApprovalStep {
        requester_id: String,
        step_index: u32,
        approvers: Vec<ApproverGroup>,
        allow_self_approve: bool,
        allow_same_approver_across_steps: bool,
        previous_approver_ids: Vec<String>,
    },
    /// Agent operations: agent_id match.
    AgentExecution { agent_id: String },
    /// Result access: requester + share_with selectors.
    Result {
        requester_id: String,
        access_selectors: Vec<String>,
    },
    /// Audit query: scope restriction.
    AuditQuery { requested_actor_id: Option<String> },
    /// Token operations: ownership check.
    Token { owner_id: String },
}
