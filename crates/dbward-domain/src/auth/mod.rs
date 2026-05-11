use serde::{Deserialize, Serialize};

use crate::values::Role;

/// Authenticated principal. Constructed after token/OIDC verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthUser {
    pub subject_id: String,
    pub subject_type: SubjectType,
    pub role: Role,
    pub groups: Vec<String>,
    pub token_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectType {
    User,
    Agent,
}

/// What the user is trying to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    CreateRequest,
    ApproveRequest,
    RejectRequest,
    DispatchRequest,
    CancelRequest,
    ReadResult,
    AgentPoll,
    AgentClaim,
    AgentSubmitResult,
    ManageToken,
    ManageUsers,
    ManageWebhook,
    CreatePolicy,
    UpdatePolicy,
    DeletePolicy,
    ListAudit,
    ListRequests,
}

/// The resource being acted upon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resource {
    Global,
    Request {
        requester_id: String,
    },
    ApprovalStep {
        request_id: String,
        step_index: u32,
    },
    AgentExecution {
        agent_id: String,
    },
    Result {
        requester_id: String,
    },
    AuditQuery {
        actor_id: Option<String>,
    },
}
