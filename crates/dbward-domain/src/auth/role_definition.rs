use super::{OwnershipScope, Permission};
use crate::values::{DatabaseName, Environment};
use serde::{Deserialize, Serialize};

/// A single permission entry with its ownership scope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PermissionEntry {
    pub perm: Permission,
    #[serde(default)]
    pub ownership: OwnershipScope,
}

/// A stored role definition (persisted in PolicyRepo).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleDefinition {
    pub name: String,
    pub permissions: Vec<PermissionEntry>,
    pub databases: Vec<DatabaseName>,
    pub environments: Vec<Environment>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_entry_default_ownership_is_own() {
        let json = r#"{"perm":"request.dml"}"#;
        let entry: PermissionEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.perm, Permission::RequestDml);
        assert_eq!(entry.ownership, OwnershipScope::Own);
    }

    #[test]
    fn permission_entry_explicit_ownership() {
        let json = r#"{"perm":"request.view","ownership":"any"}"#;
        let entry: PermissionEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.perm, Permission::RequestView);
        assert_eq!(entry.ownership, OwnershipScope::Any);
    }

    #[test]
    fn permission_entry_roundtrip() {
        let entry = PermissionEntry {
            perm: Permission::TokenRevoke,
            ownership: OwnershipScope::Any,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: PermissionEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.perm, entry.perm);
        assert_eq!(parsed.ownership, entry.ownership);
    }

    #[test]
    fn permission_entry_wildcard() {
        let json = r#"{"perm":"*"}"#;
        let entry: PermissionEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.perm, Permission::All);
        assert_eq!(entry.ownership, OwnershipScope::Own);
    }
}
