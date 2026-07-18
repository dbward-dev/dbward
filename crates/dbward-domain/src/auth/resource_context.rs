use crate::policies::workflow::ApproverGroup;

/// Context about the resource being acted upon. Used in Layer 2 authorization.
///
/// Each variant encodes the specific facts needed for the authorization decision
/// of that operation category. Use cases build the appropriate variant and pass
/// it to the Authorizer — they never perform authorization logic themselves.
#[derive(Debug, Clone)]
pub enum ResourceContext {
    /// No resource-level check needed. Layer 1 (permission gate) is sufficient.
    /// Used for: create_request, preflight, schema.read, system-plane operations,
    /// token.create, token.list, token.create_agent, token.reissue.
    Global,

    /// Request view: owner OR relationship (pending_approver / past_approver) OR ownership:Any.
    RequestView {
        requester_id: String,
        is_pending_approver: bool,
        has_approved: bool,
    },

    /// Request mutate (cancel/resume): owner OR ownership:Any.
    RequestMutate { requester_id: String },

    /// Approval/reject: workflow step selector match only (no permission gate).
    /// Called via `authorize_approval()` — Layer 1 is skipped.
    ApprovalStep {
        requester_id: String,
        step_index: u32,
        approvers: Vec<ApproverGroup>,
        allow_self_approve: bool,
        allow_same_approver_across_steps: bool,
        previous_approver_ids: Vec<String>,
    },

    /// Agent operations: agent_id must match the authenticated subject.
    AgentExecution { agent_id: String },

    /// Result access: owner OR selector match (share_with + user:{approver_id}) OR ownership:Any.
    Result {
        requester_id: String,
        access_selectors: Vec<String>,
    },

    /// Audit query: Layer 1 (audit.read) is sufficient. No further restriction.
    AuditQuery { requested_actor_id: Option<String> },

    /// Token revoke: owner OR ownership:Any.
    Token { owner_id: String },

    /// User operations: Layer 1 is sufficient. Self-access is always allowed.
    User { target_id: String },
}
