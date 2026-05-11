use serde::{Deserialize, Serialize};

use crate::values::{DatabaseName, Environment, Role};

/// Controls which users/groups can access a specific database+environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessPolicy {
    pub id: String,
    pub database: DatabaseName,
    pub environment: Environment,
    pub operation: String,
    pub allowed_roles: Vec<Role>,
    pub allowed_groups: Vec<String>,
}

impl AccessPolicy {
    /// Check if a user with the given role and groups is allowed.
    pub fn allows(&self, role: Role, groups: &[String]) -> bool {
        if self.allowed_roles.iter().any(|r| role.satisfies(*r)) {
            return true;
        }
        self.allowed_groups.iter().any(|g| groups.contains(g))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_policy(roles: Vec<Role>, groups: Vec<&str>) -> AccessPolicy {
        AccessPolicy {
            id: "ap1".into(),
            database: DatabaseName::new("app").unwrap(),
            environment: Environment::new("production").unwrap(),
            operation: "*".into(),
            allowed_roles: roles,
            allowed_groups: groups.into_iter().map(String::from).collect(),
        }
    }

    #[test]
    fn allows_by_role() {
        let p = make_policy(vec![Role::Admin], vec![]);
        assert!(p.allows(Role::Admin, &[]));
        assert!(!p.allows(Role::Developer, &[]));
    }

    #[test]
    fn allows_by_group() {
        let p = make_policy(vec![], vec!["dba-team"]);
        assert!(p.allows(Role::Readonly, &["dba-team".into()]));
        assert!(!p.allows(Role::Readonly, &["dev-team".into()]));
    }

    #[test]
    fn allows_role_hierarchy() {
        let p = make_policy(vec![Role::Developer], vec![]);
        assert!(p.allows(Role::Admin, &[]));
        assert!(p.allows(Role::Developer, &[]));
        assert!(!p.allows(Role::Readonly, &[]));
    }
}
