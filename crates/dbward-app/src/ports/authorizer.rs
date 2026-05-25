use async_trait::async_trait;

use dbward_domain::auth::{AuthUser, Permission, ResolvedRole, ResourceContext, SubjectType};
use dbward_domain::policies::Workflow;
use dbward_domain::values::{DatabaseName, Environment, Operation};

use crate::error::{AppError, AuthError, AuthzError};

/// Authentication: verifies tokens and OIDC JWTs.
#[async_trait]
pub trait TokenVerifier: Send + Sync {
    /// API Token → AuthUser (roles already resolved from token record).
    async fn verify_api_token(&self, token: &str) -> Result<AuthUser, AuthError>;
    /// OIDC JWT → (subject_id, groups). Roles resolved separately by RoleResolver.
    async fn verify_oidc_token(&self, token: &str) -> Result<(String, Vec<String>), AuthError>;
}

/// Role resolution: maps groups/user_bindings to ResolvedRoles.
pub trait RoleResolver: Send + Sync {
    fn resolve(
        &self,
        subject_id: &str,
        subject_type: SubjectType,
        groups: &[String],
    ) -> Result<Vec<ResolvedRole>, AuthError>;

    /// Reverse lookup: role → subject_ids who have this role via static bindings.
    fn subjects_for_role(&self, _role: &str) -> Vec<String> {
        vec![]
    }
}

/// Authorization: 2-method design per ADR-002.
pub trait Authorizer: Send + Sync {
    /// Scoped operations (request.create, request.dispatch, etc.)
    fn authorize_scoped(
        &self,
        user: &AuthUser,
        permission: Permission,
        database: &DatabaseName,
        environment: &Environment,
        context: &ResourceContext,
    ) -> Result<(), AuthzError>;

    /// Global operations (workflow.manage, user.manage, etc. No DB scope.)
    fn authorize_global(&self, user: &AuthUser, permission: Permission) -> Result<(), AuthzError>;
}

/// Policy evaluation: workflow matching + execution policy lookup.
pub trait PolicyEvaluator: Send + Sync {
    fn evaluate_workflow(
        &self,
        db: &DatabaseName,
        env: &Environment,
        op: Operation,
    ) -> Result<Option<Workflow>, AppError>;

    fn get_execution_policy(
        &self,
        db: &DatabaseName,
        env: &Environment,
    ) -> dbward_domain::policies::ExecutionPolicy;
}
