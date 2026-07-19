pub mod permission;
pub mod resolved_role;
pub mod resource_context;
pub mod role_definition;

use serde::{Deserialize, Serialize};

pub use permission::Permission;
pub use resolved_role::{OwnershipScope, ResolvedRole};
pub use resource_context::ResourceContext;
pub use role_definition::{PermissionEntry, RoleDefinition};

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
    /// Whether any of the user's roles grants the given permission on the given db+env (Layer 1).
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

    /// Effective ownership scope across all roles for a given permission + db + env.
    /// Any > Own (most permissive wins when user holds multiple roles).
    pub fn effective_ownership(
        &self,
        perm: Permission,
        db: &crate::values::DatabaseName,
        env: &crate::values::Environment,
    ) -> OwnershipScope {
        for role in &self.roles {
            if role.allows(perm, db, env) && role.ownership_of(perm) == OwnershipScope::Any {
                return OwnershipScope::Any;
            }
        }
        OwnershipScope::Own
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectType {
    User,
    Agent,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::values::{DatabaseName, Environment};
    use std::collections::HashMap;

    fn make_user_with_roles(roles: Vec<ResolvedRole>) -> AuthUser {
        AuthUser {
            subject_id: "alice".to_string(),
            subject_type: SubjectType::User,
            roles,
            groups: vec![],
            token_id: None,
        }
    }

    #[test]
    fn effective_ownership_own_plus_any_is_any() {
        let db = DatabaseName::new("app").unwrap();
        let env = Environment::new("production").unwrap();
        let user = make_user_with_roles(vec![
            ResolvedRole {
                name: "requester".to_string(),
                permissions: HashMap::from([(Permission::RequestView, OwnershipScope::Own)]),
                databases: vec![DatabaseName::new("*").unwrap()],
                environments: vec![Environment::new("*").unwrap()],
            },
            ResolvedRole {
                name: "operator".to_string(),
                permissions: HashMap::from([(Permission::RequestView, OwnershipScope::Any)]),
                databases: vec![DatabaseName::new("*").unwrap()],
                environments: vec![Environment::new("*").unwrap()],
            },
        ]);
        assert_eq!(
            user.effective_ownership(Permission::RequestView, &db, &env),
            OwnershipScope::Any
        );
    }

    #[test]
    fn effective_ownership_only_own() {
        let db = DatabaseName::new("app").unwrap();
        let env = Environment::new("production").unwrap();
        let user = make_user_with_roles(vec![ResolvedRole {
            name: "requester".to_string(),
            permissions: HashMap::from([(Permission::RequestView, OwnershipScope::Own)]),
            databases: vec![DatabaseName::new("*").unwrap()],
            environments: vec![Environment::new("*").unwrap()],
        }]);
        assert_eq!(
            user.effective_ownership(Permission::RequestView, &db, &env),
            OwnershipScope::Own
        );
    }

    #[test]
    fn effective_ownership_scope_out_any_is_ignored() {
        let db = DatabaseName::new("app").unwrap();
        let env = Environment::new("production").unwrap();
        let user = make_user_with_roles(vec![ResolvedRole {
            name: "operator".to_string(),
            permissions: HashMap::from([(Permission::RequestView, OwnershipScope::Any)]),
            databases: vec![DatabaseName::new("other").unwrap()],
            environments: vec![Environment::new("*").unwrap()],
        }]);
        // operator has Any but only for "other" db, not "app"
        assert_eq!(
            user.effective_ownership(Permission::RequestView, &db, &env),
            OwnershipScope::Own
        );
    }

    #[test]
    fn effective_ownership_wildcard_is_any() {
        let db = DatabaseName::new("app").unwrap();
        let env = Environment::new("production").unwrap();
        let user = make_user_with_roles(vec![ResolvedRole {
            name: "super_admin".to_string(),
            permissions: HashMap::from([(Permission::All, OwnershipScope::Any)]),
            databases: vec![DatabaseName::new("*").unwrap()],
            environments: vec![Environment::new("*").unwrap()],
        }]);
        assert_eq!(
            user.effective_ownership(Permission::RequestView, &db, &env),
            OwnershipScope::Any
        );
        assert_eq!(
            user.effective_ownership(Permission::TokenRevoke, &db, &env),
            OwnershipScope::Any
        );
    }
}
