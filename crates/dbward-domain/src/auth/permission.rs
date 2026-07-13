use std::fmt;
use std::str::FromStr;

/// Fine-grained permission in the `resource.action` format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Permission {
    RequestExecute,
    RequestQuery,
    RequestApprove,
    RequestResume,
    RequestCancel,
    RequestView,
    RequestBreakGlass,
    RequestBreakGlassDdl,
    RequestPreflight,
    RequestPreflightExplain,
    ResultView,
    AuditRead,
    WorkflowRead,
    WorkflowWrite,
    PolicyWrite,
    RoleWrite,
    WebhookWrite,
    UserWrite,
    UserRead,
    TokenCreateOwn,
    TokenRevokeOwn,
    TokenManage,
    AgentOperate,
    MetricsView,
    /// Wildcard: grants all permissions.
    All,
}

impl Permission {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RequestExecute => "request.execute",
            Self::RequestQuery => "request.query",
            Self::RequestApprove => "request.approve",
            Self::RequestResume => "request.resume",
            Self::RequestCancel => "request.cancel",
            Self::RequestView => "request.view",
            Self::RequestBreakGlass => "request.break_glass",
            Self::RequestBreakGlassDdl => "request.break_glass_ddl",
            Self::RequestPreflight => "request.preflight",
            Self::RequestPreflightExplain => "request.preflight_explain",
            Self::ResultView => "result.view",
            Self::AuditRead => "audit.read",
            Self::WorkflowRead => "workflow.read",
            Self::WorkflowWrite => "workflow.write",
            Self::PolicyWrite => "policy.write",
            Self::RoleWrite => "role.write",
            Self::WebhookWrite => "webhook.write",
            Self::UserWrite => "user.write",
            Self::UserRead => "user.read",
            Self::TokenCreateOwn => "token.create_own",
            Self::TokenRevokeOwn => "token.revoke_own",
            Self::TokenManage => "token.manage",
            Self::AgentOperate => "agent.operate",
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
            "request.execute" => Ok(Self::RequestExecute),
            "request.query" => Ok(Self::RequestQuery),
            "request.approve" => Ok(Self::RequestApprove),
            "request.resume" => Ok(Self::RequestResume),
            "request.cancel" => Ok(Self::RequestCancel),
            "request.view" => Ok(Self::RequestView),
            "request.break_glass" => Ok(Self::RequestBreakGlass),
            "request.break_glass_ddl" => Ok(Self::RequestBreakGlassDdl),
            "request.preflight" => Ok(Self::RequestPreflight),
            "request.preflight_explain" => Ok(Self::RequestPreflightExplain),
            "result.view" => Ok(Self::ResultView),
            "audit.read" => Ok(Self::AuditRead),
            "workflow.read" => Ok(Self::WorkflowRead),
            "workflow.write" => Ok(Self::WorkflowWrite),
            "policy.write" => Ok(Self::PolicyWrite),
            "role.write" => Ok(Self::RoleWrite),
            "webhook.write" => Ok(Self::WebhookWrite),
            "user.write" => Ok(Self::UserWrite),
            "user.read" => Ok(Self::UserRead),
            "token.create_own" => Ok(Self::TokenCreateOwn),
            "token.revoke_own" => Ok(Self::TokenRevokeOwn),
            "token.manage" => Ok(Self::TokenManage),
            "agent.operate" => Ok(Self::AgentOperate),
            "metrics.view" => Ok(Self::MetricsView),
            "*" => Ok(Self::All),
            other => Err(format!("unknown permission: {other}")),
        }
    }
}

impl serde::Serialize for Permission {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for Permission {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s: String = serde::Deserialize::deserialize(deserializer)?;
        Permission::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_variants() {
        let all = [
            Permission::RequestExecute,
            Permission::RequestQuery,
            Permission::RequestApprove,
            Permission::RequestResume,
            Permission::RequestCancel,
            Permission::RequestView,
            Permission::RequestBreakGlass,
            Permission::RequestBreakGlassDdl,
            Permission::RequestPreflight,
            Permission::RequestPreflightExplain,
            Permission::ResultView,
            Permission::AuditRead,
            Permission::WorkflowRead,
            Permission::WorkflowWrite,
            Permission::PolicyWrite,
            Permission::RoleWrite,
            Permission::WebhookWrite,
            Permission::UserWrite,
            Permission::UserRead,
            Permission::TokenCreateOwn,
            Permission::TokenRevokeOwn,
            Permission::TokenManage,
            Permission::AgentOperate,
            Permission::MetricsView,
            Permission::All,
        ];
        for p in all {
            assert_eq!(
                p.as_str().parse::<Permission>().unwrap(),
                p,
                "failed for {:?}",
                p
            );
        }
    }

    #[test]
    fn unknown_returns_err() {
        assert!("foo.bar".parse::<Permission>().is_err());
    }

    #[test]
    fn token_write_is_rejected() {
        assert!("token.write".parse::<Permission>().is_err());
    }
}
