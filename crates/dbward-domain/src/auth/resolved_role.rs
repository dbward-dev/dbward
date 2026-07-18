use std::collections::HashMap;

use crate::values::{DatabaseName, Environment};

use super::Permission;

/// Whether a permission applies to the user's own resources or any resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub enum OwnershipScope {
    #[default]
    Own,
    Any,
}

impl OwnershipScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Own => "own",
            Self::Any => "any",
        }
    }
}

impl std::str::FromStr for OwnershipScope {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "own" => Ok(Self::Own),
            "any" => Ok(Self::Any),
            other => Err(format!("unknown ownership scope: {other}")),
        }
    }
}

impl std::fmt::Display for OwnershipScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl serde::Serialize for OwnershipScope {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for OwnershipScope {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s: String = serde::Deserialize::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// A role with its permissions and scope fully resolved from config.
#[derive(Debug, Clone)]
pub struct ResolvedRole {
    pub name: String,
    pub permissions: HashMap<Permission, OwnershipScope>,
    pub databases: Vec<DatabaseName>,
    pub environments: Vec<Environment>,
}

impl ResolvedRole {
    /// Whether this role grants the given permission on the given db+env (Layer 1).
    pub fn allows(&self, perm: Permission, db: &DatabaseName, env: &Environment) -> bool {
        self.has_permission(perm) && self.covers_database(db) && self.covers_environment(env)
    }

    /// Whether this role grants the given permission (ignoring scope).
    pub fn has_permission(&self, perm: Permission) -> bool {
        self.permissions.contains_key(&Permission::All) || self.permissions.contains_key(&perm)
    }

    /// Ownership scope for the given permission.
    /// `*` implies Any for all permissions.
    pub fn ownership_of(&self, perm: Permission) -> OwnershipScope {
        if self.permissions.contains_key(&Permission::All) {
            return OwnershipScope::Any;
        }
        self.permissions
            .get(&perm)
            .copied()
            .unwrap_or(OwnershipScope::Own)
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

    fn make_role(
        perms: &[(Permission, OwnershipScope)],
        dbs: &[&str],
        envs: &[&str],
    ) -> ResolvedRole {
        ResolvedRole {
            name: "test".to_string(),
            permissions: perms.iter().copied().collect(),
            databases: dbs.iter().map(|s| DatabaseName::new(*s).unwrap()).collect(),
            environments: envs.iter().map(|s| Environment::new(*s).unwrap()).collect(),
        }
    }

    #[test]
    fn wildcard_permission_grants_all() {
        let role = make_role(&[(Permission::All, OwnershipScope::Any)], &["*"], &["*"]);
        let db = DatabaseName::new("app").unwrap();
        let env = Environment::new("production").unwrap();
        assert!(role.allows(Permission::RequestDml, &db, &env));
        assert!(role.allows(Permission::AuditRead, &db, &env));
    }

    #[test]
    fn wildcard_ownership_is_any() {
        let role = make_role(&[(Permission::All, OwnershipScope::Any)], &["*"], &["*"]);
        assert_eq!(
            role.ownership_of(Permission::RequestView),
            OwnershipScope::Any
        );
        assert_eq!(
            role.ownership_of(Permission::TokenRevoke),
            OwnershipScope::Any
        );
    }

    #[test]
    fn scoped_database() {
        let role = make_role(
            &[(Permission::RequestDml, OwnershipScope::Own)],
            &["app"],
            &["*"],
        );
        let app = DatabaseName::new("app").unwrap();
        let analytics = DatabaseName::new("analytics").unwrap();
        let env = Environment::new("production").unwrap();
        assert!(role.allows(Permission::RequestDml, &app, &env));
        assert!(!role.allows(Permission::RequestDml, &analytics, &env));
    }

    #[test]
    fn scoped_environment() {
        let role = make_role(
            &[(Permission::RequestDml, OwnershipScope::Own)],
            &["*"],
            &["development"],
        );
        let db = DatabaseName::new("app").unwrap();
        let dev = Environment::new("development").unwrap();
        let prod = Environment::new("production").unwrap();
        assert!(role.allows(Permission::RequestDml, &db, &dev));
        assert!(!role.allows(Permission::RequestDml, &db, &prod));
    }

    #[test]
    fn missing_permission() {
        let role = make_role(
            &[(Permission::RequestView, OwnershipScope::Own)],
            &["*"],
            &["*"],
        );
        let db = DatabaseName::new("app").unwrap();
        let env = Environment::new("production").unwrap();
        assert!(!role.allows(Permission::RequestDml, &db, &env));
    }

    #[test]
    fn ownership_own_vs_any() {
        let role = make_role(
            &[
                (Permission::RequestView, OwnershipScope::Own),
                (Permission::RequestCancel, OwnershipScope::Any),
            ],
            &["*"],
            &["*"],
        );
        assert_eq!(
            role.ownership_of(Permission::RequestView),
            OwnershipScope::Own
        );
        assert_eq!(
            role.ownership_of(Permission::RequestCancel),
            OwnershipScope::Any
        );
    }

    #[test]
    fn ownership_scope_roundtrip() {
        assert_eq!(
            "own".parse::<OwnershipScope>().unwrap(),
            OwnershipScope::Own
        );
        assert_eq!(
            "any".parse::<OwnershipScope>().unwrap(),
            OwnershipScope::Any
        );
        assert!("invalid".parse::<OwnershipScope>().is_err());
    }
}
