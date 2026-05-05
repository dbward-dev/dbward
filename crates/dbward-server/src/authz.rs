use axum::http::StatusCode;
use casbin::function_map::OperatorFunction;
use casbin::rhai::Dynamic;
use casbin::{CoreApi, DefaultModel, Enforcer, StringAdapter};
use serde::{Deserialize, Serialize};
use tokio::sync::OnceCell;

use crate::state::AuthUser;

const MODEL: &str = r#"
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub_type, perm, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.act == p.act && authz_match(r.sub, r.obj, r.act, p.sub_type, p.perm, p.obj)
"#;

const POLICY: &str = r#"
p, user, approver, Global, ListRequests
p, user, approver, Request, ListRequests
p, user, approver, Global, GetRequest
p, user, approver, Request, GetRequest
p, user, developer, Global, CreateRequest
p, user, developer, Request, CreateRequest
p, user, approver, Global, ApproveRequest
p, user, approver, ApprovalStep, ApproveRequest
p, user, approver, Global, RejectRequest
p, user, approver, ApprovalStep, RejectRequest
p, user, approver, Global, DispatchRequest
p, user, approver, Request, DispatchRequest
p, user, approver, Global, ReadResult
p, user, approver, Result, ReadResult
p, user, developer, Global, ListAudit
p, user, developer, AuditQuery, ListAudit
p, agent, admin, Global, AgentPoll
p, agent, admin, Global, AgentClaim
p, agent, admin, AgentExecution, AgentClaim
p, agent, admin, Global, AgentSubmitResult
p, agent, admin, AgentExecution, AgentSubmitResult
p, user, admin, Global, ListPolicy
p, user, admin, PolicyObject, ListPolicy
p, user, admin, Global, GetPolicy
p, user, admin, PolicyObject, GetPolicy
p, user, admin, Global, CreatePolicy
p, user, admin, PolicyObject, CreatePolicy
p, user, admin, Global, UpdatePolicy
p, user, admin, PolicyObject, UpdatePolicy
p, user, admin, Global, DeletePolicy
p, user, admin, PolicyObject, DeletePolicy
"#;

static ENFORCER: OnceCell<Enforcer> = OnceCell::const_new();

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Action {
    ListRequests,
    CreateRequest,
    GetRequest,
    ApproveRequest,
    RejectRequest,
    DispatchRequest,
    ReadResult,
    ListAudit,
    AgentPoll,
    AgentClaim,
    AgentSubmitResult,
    ListPolicy,
    GetPolicy,
    CreatePolicy,
    UpdatePolicy,
    DeletePolicy,
}

impl Action {
    fn as_str(self) -> &'static str {
        match self {
            Self::ListRequests => "ListRequests",
            Self::CreateRequest => "CreateRequest",
            Self::GetRequest => "GetRequest",
            Self::ApproveRequest => "ApproveRequest",
            Self::RejectRequest => "RejectRequest",
            Self::DispatchRequest => "DispatchRequest",
            Self::ReadResult => "ReadResult",
            Self::ListAudit => "ListAudit",
            Self::AgentPoll => "AgentPoll",
            Self::AgentClaim => "AgentClaim",
            Self::AgentSubmitResult => "AgentSubmitResult",
            Self::ListPolicy => "ListPolicy",
            Self::GetPolicy => "GetPolicy",
            Self::CreatePolicy => "CreatePolicy",
            Self::UpdatePolicy => "UpdatePolicy",
            Self::DeletePolicy => "DeletePolicy",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(tag = "kind")]
pub enum Resource {
    Global,
    Request {
        requester_id: String,
        status: String,
        database: String,
        environment: String,
    },
    Result {
        requester_id: String,
        access_roles: Vec<String>,
    },
    AuditQuery {
        requested_user: Option<String>,
    },
    ApprovalStep {
        requester_id: String,
        allowed_roles: Vec<String>,
        allowed_groups: Vec<String>,
    },
    AgentExecution {
        agent_id: String,
    },
    PolicyObject,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
struct Principal {
    user: String,
    roles: Vec<String>,
    groups: Vec<String>,
    permission: String,
    subject_type: String,
}

impl From<&AuthUser> for Principal {
    fn from(value: &AuthUser) -> Self {
        Self {
            user: value.user.clone(),
            roles: value.roles.clone(),
            groups: value.groups.clone(),
            permission: value.effective_permission().to_string(),
            subject_type: value.subject_type.clone(),
        }
    }
}

pub async fn authorize(
    principal: &AuthUser,
    action: Action,
    resource: Resource,
) -> std::result::Result<(), (StatusCode, String)> {
    let _ = enforcer().await;
    authorize_sync(principal, action, resource)
}

pub fn authorize_sync(
    principal: &AuthUser,
    action: Action,
    resource: Resource,
) -> std::result::Result<(), (StatusCode, String)> {
    let principal = Principal::from(principal);
    let principal_json = serde_json::to_string(&principal).map_err(internal_error)?;
    let resource_json = serde_json::to_string(&resource).map_err(internal_error)?;
    let allowed = ENFORCER
        .get()
        .expect("casbin enforcer must be initialized before sync authorization")
        .enforce((principal_json, resource_json, action.as_str()))
        .map_err(internal_error)?;

    if allowed {
        Ok(())
    } else {
        Err((StatusCode::FORBIDDEN, deny_message(action)))
    }
}

pub async fn warmup() -> std::result::Result<(), (StatusCode, String)> {
    let _ = enforcer().await;
    Ok(())
}

async fn enforcer() -> &'static Enforcer {
    ENFORCER
        .get_or_init(|| async {
            let model = DefaultModel::from_str(MODEL)
                .await
                .expect("casbin model must compile");
            let adapter = StringAdapter::new(POLICY);
            let mut enforcer = Enforcer::new(model, adapter)
                .await
                .expect("casbin enforcer must initialize");
            enforcer.add_function("authz_match", OperatorFunction::Arg6(authz_match));
            enforcer
        })
        .await
}

fn authz_match(
    sub: Dynamic,
    obj: Dynamic,
    act: Dynamic,
    policy_sub_type: Dynamic,
    policy_perm: Dynamic,
    policy_obj: Dynamic,
) -> Dynamic {
    let allowed = parse_dynamic::<Principal>(&sub)
        .zip(parse_dynamic::<Resource>(&obj)).map(|(principal, resource)| (
                principal,
                resource,
                act.to_string(),
                policy_sub_type.to_string(),
                policy_perm.to_string(),
                policy_obj.to_string(),
            ))
        .map(
            |(principal, resource, act, policy_sub_type, policy_perm, policy_obj)| {
                principal.subject_type == policy_sub_type
                    && role_allows(&principal.permission, &policy_perm)
                    && resource_kind(&resource) == policy_obj
                    && resource_allows(&principal, &resource, &act)
            },
        )
        .unwrap_or(false);
    allowed.into()
}

fn parse_dynamic<T: for<'de> Deserialize<'de>>(value: &Dynamic) -> Option<T> {
    serde_json::from_str(&value.to_string()).ok()
}

fn resource_kind(resource: &Resource) -> &'static str {
    match resource {
        Resource::Global => "Global",
        Resource::Request { .. } => "Request",
        Resource::Result { .. } => "Result",
        Resource::AuditQuery { .. } => "AuditQuery",
        Resource::ApprovalStep { .. } => "ApprovalStep",
        Resource::AgentExecution { .. } => "AgentExecution",
        Resource::PolicyObject => "PolicyObject",
    }
}

fn resource_allows(principal: &Principal, resource: &Resource, action: &str) -> bool {
    match (action, resource) {
        ("ListRequests", Resource::Global) => true,
        ("GetRequest", Resource::Global) => true,
        ("ApproveRequest", Resource::Global) => true,
        ("RejectRequest", Resource::Global) => true,
        ("DispatchRequest", Resource::Global) => true,
        ("ReadResult", Resource::Global) => true,
        ("ListRequests", Resource::Request { requester_id, .. }) => {
            is_admin(principal) || principal.user == *requester_id
        }
        ("CreateRequest", Resource::Global) | ("CreateRequest", Resource::Request { .. }) => {
            role_allows(&principal.permission, "developer")
        }
        ("GetRequest", Resource::Request { requester_id, .. }) => {
            is_admin(principal) || principal.user == *requester_id
        }
        (
            "ApproveRequest",
            Resource::ApprovalStep {
                requester_id,
                allowed_roles,
                allowed_groups,
            },
        ) => {
            if principal.user == *requester_id {
                return false;
            }
            if is_admin(principal) {
                return true;
            }
            allowed_roles
                .iter()
                .any(|role| principal.roles.iter().any(|own| own == role))
                || allowed_groups
                    .iter()
                    .any(|g| principal.groups.iter().any(|own| own == g))
        }
        (
            "RejectRequest",
            Resource::ApprovalStep {
                requester_id,
                allowed_roles,
                allowed_groups,
            },
        ) => {
            is_admin(principal)
                || principal.user == *requester_id
                || allowed_roles
                    .iter()
                    .any(|role| principal.roles.iter().any(|own| own == role))
                || allowed_groups
                    .iter()
                    .any(|g| principal.groups.iter().any(|own| own == g))
        }
        ("DispatchRequest", Resource::Request { requester_id, .. }) => {
            is_admin(principal) || principal.user == *requester_id
        }
        (
            "ReadResult",
            Resource::Result {
                requester_id,
                access_roles,
            },
        ) => access_roles
            .iter()
            .any(|entry| matches_selector(principal, entry, requester_id)),
        ("ListAudit", Resource::AuditQuery { requested_user }) => {
            if is_admin(principal) {
                return true;
            }
            principal.permission == "developer"
                && requested_user
                    .as_ref()
                    .map(|requested| requested == &principal.user)
                    .unwrap_or(true)
        }
        ("AgentPoll", Resource::Global) => true,
        ("AgentClaim", Resource::Global) | ("AgentClaim", Resource::AgentExecution { .. }) => true,
        ("AgentSubmitResult", Resource::Global) => true,
        ("AgentSubmitResult", Resource::AgentExecution { agent_id }) => principal.user == *agent_id,
        ("ListPolicy", Resource::Global)
        | ("ListPolicy", Resource::PolicyObject)
        | ("GetPolicy", Resource::Global)
        | ("GetPolicy", Resource::PolicyObject)
        | ("CreatePolicy", Resource::Global)
        | ("CreatePolicy", Resource::PolicyObject)
        | ("UpdatePolicy", Resource::Global)
        | ("UpdatePolicy", Resource::PolicyObject)
        | ("DeletePolicy", Resource::Global)
        | ("DeletePolicy", Resource::PolicyObject) => true,
        _ => false,
    }
}

fn role_allows(actual: &str, required: &str) -> bool {
    permission_rank(actual) >= permission_rank(required)
}

fn permission_rank(permission: &str) -> i8 {
    match permission {
        "admin" => 3,
        "developer" => 2,
        "readonly" => 1,
        _ => 0,
    }
}

fn is_admin(principal: &Principal) -> bool {
    principal.permission == "admin"
}

/// Evaluate a principal selector entry against the given principal.
/// Supports: "requester", "role:<name>", "group:<name>", "user:<id>", bare role name.
pub fn matches_selector(principal: &Principal, selector: &str, requester_id: &str) -> bool {
    match selector {
        "requester" => principal.user == requester_id,
        s if s.starts_with("role:") => principal.roles.iter().any(|r| r == &s[5..]),
        s if s.starts_with("group:") => principal.groups.iter().any(|g| g == &s[6..]),
        s if s.starts_with("user:") => principal.user == s[5..],
        // Backward compat: bare string matches effective permission or role
        bare => bare == principal.permission || principal.roles.iter().any(|r| r == bare),
    }
}

fn deny_message(action: Action) -> String {
    match action {
        Action::CreateRequest => "request creation is not allowed".into(),
        Action::GetRequest => "request access denied".into(),
        Action::ApproveRequest => "approval is not allowed".into(),
        Action::RejectRequest => "rejection is not allowed".into(),
        Action::DispatchRequest => "dispatch is not allowed".into(),
        Action::ReadResult => "result access denied".into(),
        Action::ListAudit => "audit access denied".into(),
        Action::AgentPoll => "agent poll is not allowed".into(),
        Action::AgentClaim => "agent claim is not allowed".into(),
        Action::AgentSubmitResult => "agent result submission is not allowed".into(),
        Action::ListPolicy
        | Action::GetPolicy
        | Action::CreatePolicy
        | Action::UpdatePolicy
        | Action::DeletePolicy => "admin only".into(),
        Action::ListRequests => "request list access denied".into(),
    }
}

fn internal_error<E: std::fmt::Display>(error: E) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(name: &str, roles: &[&str], subject_type: &str) -> AuthUser {
        AuthUser {
            token_id: "t".into(),
            user: name.into(),
            roles: roles.iter().map(|role| (*role).to_string()).collect(),
            groups: vec![],
            subject_type: subject_type.into(),
        }
    }

    #[tokio::test]
    async fn developer_can_create_request() {
        let principal = user("alice", &["developer"], "user");
        let resource = Resource::Request {
            requester_id: "alice".into(),
            status: "pending".into(),
            database: "app".into(),
            environment: "staging".into(),
        };

        assert!(
            authorize(&principal, Action::CreateRequest, resource)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn approver_cannot_create_request() {
        let principal = user("alice", &["team-a"], "user");
        let resource = Resource::Request {
            requester_id: "alice".into(),
            status: "pending".into(),
            database: "app".into(),
            environment: "staging".into(),
        };

        assert_eq!(
            authorize(&principal, Action::CreateRequest, resource)
                .await
                .unwrap_err()
                .0,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn requester_cannot_approve_own_request() {
        let principal = user("alice", &["admin"], "user");
        let resource = Resource::ApprovalStep {
            requester_id: "alice".into(),
            allowed_roles: vec!["admin".into()],
            allowed_groups: vec![],
        };

        assert_eq!(
            authorize(&principal, Action::ApproveRequest, resource)
                .await
                .unwrap_err()
                .0,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn current_step_role_can_reject() {
        let principal = user("bob", &["ops"], "user");
        let resource = Resource::ApprovalStep {
            requester_id: "alice".into(),
            allowed_roles: vec!["ops".into()],
            allowed_groups: vec![],
        };

        assert!(
            authorize(&principal, Action::RejectRequest, resource)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn only_claiming_agent_can_submit_result() {
        let principal = user("agent-1", &["admin"], "agent");
        let resource = Resource::AgentExecution {
            agent_id: "agent-2".into(),
        };

        assert_eq!(
            authorize(&principal, Action::AgentSubmitResult, resource)
                .await
                .unwrap_err()
                .0,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn developer_audit_query_is_limited_to_self() {
        let principal = user("alice", &["developer"], "user");
        let allowed = Resource::AuditQuery {
            requested_user: Some("alice".into()),
        };
        let denied = Resource::AuditQuery {
            requested_user: Some("bob".into()),
        };

        assert!(
            authorize(&principal, Action::ListAudit, allowed)
                .await
                .is_ok()
        );
        assert_eq!(
            authorize(&principal, Action::ListAudit, denied)
                .await
                .unwrap_err()
                .0,
            StatusCode::FORBIDDEN
        );
    }
}
