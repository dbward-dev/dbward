use std::fmt;
use std::str::FromStr;

/// Fine-grained permission in the `resource.action` format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Permission {
    RequestCreate,
    RequestCreateSelect,
    RequestApprove,
    RequestDispatch,
    RequestCancel,
    RequestView,
    RequestBreakGlass,
    ResultView,
    AuditView,
    AuditViewAll,
    WorkflowManage,
    PolicyManage,
    RoleManage,
    WebhookManage,
    UserManage,
    TokenManage,
    TokenRevokeOwn,
    AgentPoll,
    AgentClaim,
    AgentHeartbeat,
    AgentSubmitResult,
    MetricsView,
    /// Wildcard: grants all permissions.
    All,
}

impl Permission {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RequestCreate => "request.create",
            Self::RequestCreateSelect => "request.create_select",
            Self::RequestApprove => "request.approve",
            Self::RequestDispatch => "request.dispatch",
            Self::RequestCancel => "request.cancel",
            Self::RequestView => "request.view",
            Self::RequestBreakGlass => "request.break_glass",
            Self::ResultView => "result.view",
            Self::AuditView => "audit.view",
            Self::AuditViewAll => "audit.view_all",
            Self::WorkflowManage => "workflow.manage",
            Self::PolicyManage => "policy.manage",
            Self::RoleManage => "role.manage",
            Self::WebhookManage => "webhook.manage",
            Self::UserManage => "user.manage",
            Self::TokenManage => "token.manage",
            Self::TokenRevokeOwn => "token.revoke_own",
            Self::AgentPoll => "agent.poll",
            Self::AgentClaim => "agent.claim",
            Self::AgentHeartbeat => "agent.heartbeat",
            Self::AgentSubmitResult => "agent.submit_result",
            Self::MetricsView => "metrics.view",
            Self::All => "*",
        }
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Permission {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "request.create" => Ok(Self::RequestCreate),
            "request.create_select" => Ok(Self::RequestCreateSelect),
            "request.approve" => Ok(Self::RequestApprove),
            "request.dispatch" => Ok(Self::RequestDispatch),
            "request.cancel" => Ok(Self::RequestCancel),
            "request.view" => Ok(Self::RequestView),
            "request.break_glass" => Ok(Self::RequestBreakGlass),
            "result.view" => Ok(Self::ResultView),
            "audit.view" => Ok(Self::AuditView),
            "audit.view_all" => Ok(Self::AuditViewAll),
            "workflow.manage" => Ok(Self::WorkflowManage),
            "policy.manage" => Ok(Self::PolicyManage),
            "role.manage" => Ok(Self::RoleManage),
            "webhook.manage" => Ok(Self::WebhookManage),
            "user.manage" => Ok(Self::UserManage),
            "token.manage" => Ok(Self::TokenManage),
            "token.revoke_own" => Ok(Self::TokenRevokeOwn),
            "agent.poll" => Ok(Self::AgentPoll),
            "agent.claim" => Ok(Self::AgentClaim),
            "agent.heartbeat" => Ok(Self::AgentHeartbeat),
            "agent.submit_result" => Ok(Self::AgentSubmitResult),
            "metrics.view" => Ok(Self::MetricsView),
            "*" => Ok(Self::All),
            other => Err(format!("unknown permission: {other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_variants() {
        let all = [
            Permission::RequestCreate,
            Permission::RequestCreateSelect,
            Permission::RequestApprove,
            Permission::RequestDispatch,
            Permission::RequestCancel,
            Permission::RequestView,
            Permission::RequestBreakGlass,
            Permission::ResultView,
            Permission::AuditView,
            Permission::AuditViewAll,
            Permission::WorkflowManage,
            Permission::PolicyManage,
            Permission::RoleManage,
            Permission::WebhookManage,
            Permission::UserManage,
            Permission::TokenManage,
            Permission::TokenRevokeOwn,
            Permission::AgentPoll,
            Permission::AgentClaim,
            Permission::AgentHeartbeat,
            Permission::AgentSubmitResult,
            Permission::MetricsView,
            Permission::All,
        ];
        for p in all {
            assert_eq!(p.as_str().parse::<Permission>().unwrap(), p, "failed for {:?}", p);
        }
    }

    #[test]
    fn unknown_returns_err() {
        assert!("foo.bar".parse::<Permission>().is_err());
    }
}
