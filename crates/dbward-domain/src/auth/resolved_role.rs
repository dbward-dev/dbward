use std::collections::HashSet;

use crate::values::{DatabaseName, Environment};

use super::Permission;

/// A role with its permissions and scope fully resolved from config.
#[derive(Debug, Clone)]
pub struct ResolvedRole {
    pub name: String,
    pub permissions: HashSet<Permission>,
    pub databases: Vec<DatabaseName>,
    pub environments: Vec<Environment>,
}

impl ResolvedRole {
    /// Whether this role grants the given permission on the given db+env.
    pub fn allows(&self, perm: Permission, db: &DatabaseName, env: &Environment) -> bool {
        self.has_permission(perm) && self.covers_database(db) && self.covers_environment(env)
    }

    pub fn has_permission(&self, perm: Permission) -> bool {
        self.permissions.contains(&Permission::All) || self.permissions.contains(&perm)
    }

    fn covers_database(&self, db: &DatabaseName) -> bool {
        self.databases.iter().any(|d| d.as_str() == "*" || d == db)
    }

    fn covers_environment(&self, env: &Environment) -> bool {
        self.environments
            .iter()
            .any(|e| e.as_str() == "*" || e == env)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_role(perms: &[Permission], dbs: &[&str], envs: &[&str]) -> ResolvedRole {
        ResolvedRole {
            name: "test".to_string(),
            permissions: perms.iter().copied().collect(),
            databases: dbs.iter().map(|s| DatabaseName::new(*s).unwrap()).collect(),
            environments: envs.iter().map(|s| Environment::new(*s).unwrap()).collect(),
        }
    }

    #[test]
    fn wildcard_permission_grants_all() {
        let role = make_role(&[Permission::All], &["*"], &["*"]);
        let db = DatabaseName::new("app").unwrap();
        let env = Environment::new("production").unwrap();
        assert!(role.allows(Permission::RequestCreate, &db, &env));
        assert!(role.allows(Permission::AuditViewAll, &db, &env));
    }

    #[test]
    fn scoped_database() {
        let role = make_role(&[Permission::RequestCreate], &["app"], &["*"]);
        let app = DatabaseName::new("app").unwrap();
        let analytics = DatabaseName::new("analytics").unwrap();
        let env = Environment::new("production").unwrap();
        assert!(role.allows(Permission::RequestCreate, &app, &env));
        assert!(!role.allows(Permission::RequestCreate, &analytics, &env));
    }

    #[test]
    fn scoped_environment() {
        let role = make_role(&[Permission::RequestCreate], &["*"], &["development"]);
        let db = DatabaseName::new("app").unwrap();
        let dev = Environment::new("development").unwrap();
        let prod = Environment::new("production").unwrap();
        assert!(role.allows(Permission::RequestCreate, &db, &dev));
        assert!(!role.allows(Permission::RequestCreate, &db, &prod));
    }

    #[test]
    fn missing_permission() {
        let role = make_role(&[Permission::RequestView], &["*"], &["*"]);
        let db = DatabaseName::new("app").unwrap();
        let env = Environment::new("production").unwrap();
        assert!(!role.allows(Permission::RequestCreate, &db, &env));
    }
}
