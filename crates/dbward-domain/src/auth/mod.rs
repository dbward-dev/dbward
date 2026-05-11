pub mod permission;
pub mod resolved_role;
pub mod resource_context;

use serde::{Deserialize, Serialize};

pub use permission::Permission;
pub use resolved_role::ResolvedRole;
pub use resource_context::ResourceContext;

/// Authenticated principal. Constructed by middleware after token/OIDC verification + role resolution.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub subject_id: String,
    pub subject_type: SubjectType,
    pub roles: Vec<ResolvedRole>,
    pub groups: Vec<String>,
    pub token_id: Option<String>,
}

impl AuthUser {
    /// Whether any of the user's roles grants the given permission on the given db+env.
    pub fn has_scoped_permission(
        &self,
        perm: Permission,
        db: &crate::values::DatabaseName,
        env: &crate::values::Environment,
    ) -> bool {
        self.roles.iter().any(|r| r.allows(perm, db, env))
    }

    /// Whether any of the user's roles grants the given permission (ignoring scope).
    pub fn has_permission(&self, perm: Permission) -> bool {
        self.roles.iter().any(|r| r.has_permission(perm))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectType {
    User,
    Agent,
}
