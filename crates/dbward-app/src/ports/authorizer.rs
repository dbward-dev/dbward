use async_trait::async_trait;

use dbward_domain::auth::{AuthUser, Permission, ResolvedRole, ResourceContext, SubjectType};
use dbward_domain::entities::ScopeCeiling;
use dbward_domain::policies::Workflow;
use dbward_domain::values::{DatabaseName, Environment, Operation};

use crate::error::{AppError, AuthError, AuthzError};

/// Verified API token (no role resolution — that happens in auth middleware).
#[derive(Debug)]
pub struct VerifiedToken {
    pub id: String,
    pub subject_id: String,
    pub subject_type: SubjectType,
    pub scope_ceiling: Option<ScopeCeiling>,
}

/// Authentication: verifies tokens and OIDC JWTs.
#[async_trait]
pub trait TokenVerifier: Send + Sync {
    /// API Token → VerifiedToken (no role resolution).
    async fn verify_api_token(&self, token: &str) -> Result<VerifiedToken, AuthError>;
    /// OIDC JWT → (subject_id, groups). Roles resolved separately by RoleResolver.
    async fn verify_oidc_token(&self, token: &str) -> Result<(String, Vec<String>), AuthError>;
}

/// OIDC token verification — separated from TokenVerifier to allow commercial
/// implementations without coupling the core auth layer to a specific OIDC library.
#[async_trait]
pub trait OidcTokenVerifier: Send + Sync {
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

    /// Invalidate cached role resolution for a subject (no-op for non-caching impls).
    fn invalidate_cache(&self, _subject_id: &str) {}

    /// Reverse lookup: role → subject_ids who have this role via static bindings.
    fn subjects_for_role(&self, _role: &str) -> Vec<String> {
        vec![]
    }

    /// Get roles granted by a group (from config definition).
    fn roles_for_group(&self, _group_name: &str) -> Vec<String> {
        vec![]
    }

    /// Reverse lookup: returns all group names whose config grants the given role.
    fn groups_granting_role(&self, _role: &str) -> Vec<String> {
        vec![]
    }

    /// Reverse lookup: selector string → subject_ids.
    fn subjects_for_selector(&self, _selector: &str) -> Vec<String> {
        vec![]
    }

    /// Returns TOML-configured groups for a subject_id (for AuthUser.groups augmentation).
    fn config_groups_for(&self, _subject_id: &str) -> Option<&Vec<String>> {
        None
    }
}

/// Authorization: 2-method design per ADR-002.
pub trait Authorizer: Send + Sync {
    /// Scoped operations (request.create, request.resume, etc.)
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

    /// Filter DB/Env pairs to only those the user can submit requests to.
    fn filter_accessible(
        &self,
        user: &AuthUser,
        pairs: &[(DatabaseName, Environment)],
    ) -> Vec<(DatabaseName, Environment)> {
        pairs
            .iter()
            .filter(|(db, env)| {
                self.authorize_scoped(
                    user,
                    Permission::RequestQuery,
                    db,
                    env,
                    &ResourceContext::Global,
                )
                .is_ok()
                    || self
                        .authorize_scoped(
                            user,
                            Permission::RequestExecute,
                            db,
                            env,
                            &ResourceContext::Global,
                        )
                        .is_ok()
            })
            .cloned()
            .collect()
    }
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
    ) -> Result<dbward_domain::policies::ExecutionPolicy, AppError>;

    /// Returns the sql_review policy matching this (db, env) scope.
    /// Default impl returns builtin-default rules (block dangerous ops, warn others).
    /// This is intentionally the MOST restrictive default — not permissive.
    fn get_sql_review_policy(
        &self,
        _db: &DatabaseName,
        _env: &Environment,
    ) -> Result<dbward_domain::policies::SqlReviewPolicy, AppError> {
        Ok(dbward_domain::policies::SqlReviewPolicy::default())
    }
}
