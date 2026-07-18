use std::fmt;
use std::str::FromStr;

/// Fine-grained permission in the `resource.action` format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Permission {
    // --- Operation Plane ---
    RequestQuery,
    RequestDml,
    RequestDdl,
    RequestBreakGlassQuery,
    RequestBreakGlassDml,
    RequestBreakGlassDdl,
    RequestView,
    RequestCancel,
    RequestResume,
    RequestPreflight,
    RequestPreflightExplain,
    ResultView,
    SchemaRead,

    // --- System Plane ---
    WorkflowRead,
    WorkflowWrite,
    PolicyWrite,
    RoleWrite,
    UserRead,
    UserWrite,
    WebhookWrite,
    TokenCreate,
    TokenRevoke,
    TokenList,
    TokenCreateAgent,
    TokenReissue,
    AuditRead,
    MetricsView,

    // --- Infrastructure ---
    AgentOperate,

    // --- Wildcard ---
    /// Grants all permissions with ownership `Any`.
    All,
}

impl Permission {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RequestQuery => "request.query",
            Self::RequestDml => "request.dml",
            Self::RequestDdl => "request.ddl",
            Self::RequestBreakGlassQuery => "request.break_glass_query",
            Self::RequestBreakGlassDml => "request.break_glass_dml",
            Self::RequestBreakGlassDdl => "request.break_glass_ddl",
            Self::RequestView => "request.view",
            Self::RequestCancel => "request.cancel",
            Self::RequestResume => "request.resume",
            Self::RequestPreflight => "request.preflight",
            Self::RequestPreflightExplain => "request.preflight_explain",
            Self::ResultView => "result.view",
            Self::SchemaRead => "schema.read",
            Self::WorkflowRead => "workflow.read",
            Self::WorkflowWrite => "workflow.write",
            Self::PolicyWrite => "policy.write",
            Self::RoleWrite => "role.write",
            Self::UserRead => "user.read",
            Self::UserWrite => "user.write",
            Self::WebhookWrite => "webhook.write",
            Self::TokenCreate => "token.create",
            Self::TokenRevoke => "token.revoke",
            Self::TokenList => "token.list",
            Self::TokenCreateAgent => "token.create_agent",
            Self::TokenReissue => "token.reissue",
            Self::AuditRead => "audit.read",
            Self::MetricsView => "metrics.view",
            Self::AgentOperate => "agent.operate",
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
            "request.query" => Ok(Self::RequestQuery),
            "request.dml" => Ok(Self::RequestDml),
            "request.ddl" => Ok(Self::RequestDdl),
            "request.break_glass_query" => Ok(Self::RequestBreakGlassQuery),
            "request.break_glass_dml" => Ok(Self::RequestBreakGlassDml),
            "request.break_glass_ddl" => Ok(Self::RequestBreakGlassDdl),
            "request.view" => Ok(Self::RequestView),
            "request.cancel" => Ok(Self::RequestCancel),
            "request.resume" => Ok(Self::RequestResume),
            "request.preflight" => Ok(Self::RequestPreflight),
            "request.preflight_explain" => Ok(Self::RequestPreflightExplain),
            "result.view" => Ok(Self::ResultView),
            "schema.read" => Ok(Self::SchemaRead),
            "workflow.read" => Ok(Self::WorkflowRead),
            "workflow.write" => Ok(Self::WorkflowWrite),
            "policy.write" => Ok(Self::PolicyWrite),
            "role.write" => Ok(Self::RoleWrite),
            "user.read" => Ok(Self::UserRead),
            "user.write" => Ok(Self::UserWrite),
            "webhook.write" => Ok(Self::WebhookWrite),
            "token.create" => Ok(Self::TokenCreate),
            "token.revoke" => Ok(Self::TokenRevoke),
            "token.list" => Ok(Self::TokenList),
            "token.create_agent" => Ok(Self::TokenCreateAgent),
            "token.reissue" => Ok(Self::TokenReissue),
            "audit.read" => Ok(Self::AuditRead),
            "metrics.view" => Ok(Self::MetricsView),
            "agent.operate" => Ok(Self::AgentOperate),
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
            Permission::RequestQuery,
            Permission::RequestDml,
            Permission::RequestDdl,
            Permission::RequestBreakGlassQuery,
            Permission::RequestBreakGlassDml,
            Permission::RequestBreakGlassDdl,
            Permission::RequestView,
            Permission::RequestCancel,
            Permission::RequestResume,
            Permission::RequestPreflight,
            Permission::RequestPreflightExplain,
            Permission::ResultView,
            Permission::SchemaRead,
            Permission::WorkflowRead,
            Permission::WorkflowWrite,
            Permission::PolicyWrite,
            Permission::RoleWrite,
            Permission::UserRead,
            Permission::UserWrite,
            Permission::WebhookWrite,
            Permission::TokenCreate,
            Permission::TokenRevoke,
            Permission::TokenList,
            Permission::TokenCreateAgent,
            Permission::TokenReissue,
            Permission::AuditRead,
            Permission::MetricsView,
            Permission::AgentOperate,
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
    fn deprecated_permissions_are_rejected() {
        assert!("request.execute".parse::<Permission>().is_err());
        assert!("request.approve".parse::<Permission>().is_err());
        assert!("request.break_glass".parse::<Permission>().is_err());
        assert!("token.create_own".parse::<Permission>().is_err());
        assert!("token.revoke_own".parse::<Permission>().is_err());
        assert!("token.manage".parse::<Permission>().is_err());
    }
}
