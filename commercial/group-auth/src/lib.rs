// Copyright (c) 2026 dbward-dev.
// Licensed under the dbward Commercial License.
// Production use requires a valid Pro or Enterprise subscription.

//! Group-based authorization layer for dbward Pro/Enterprise.
//!
//! Maps identity provider groups (OIDC, SAML, SCIM) to dbward roles.
//! This enables automatic role assignment based on organizational group membership.

use std::collections::HashMap;

/// Resolves role names from identity provider group claims.
///
/// Designed to work with multiple identity sources:
/// - OIDC groups claim
/// - SAML group attributes (future)
/// - SCIM group sync (future)
pub struct GroupRoleResolver {
    /// group_name → vec of role names
    group_bindings: HashMap<String, Vec<String>>,
}

impl GroupRoleResolver {
    pub fn new(group_bindings: HashMap<String, Vec<String>>) -> Self {
        Self { group_bindings }
    }

    /// Given a list of groups from an identity provider, return all matching role names.
    pub fn resolve_roles(&self, groups: &[String]) -> Vec<String> {
        let mut roles = Vec::new();
        for group in groups {
            if let Some(bound_roles) = self.group_bindings.get(group) {
                for role in bound_roles {
                    if !roles.contains(role) {
                        roles.push(role.clone());
                    }
                }
            }
        }
        roles
    }

    /// Returns true if any group bindings are configured.
    pub fn has_bindings(&self) -> bool {
        !self.group_bindings.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_roles_from_groups() {
        let mut bindings = HashMap::new();
        bindings.insert("engineering".to_string(), vec!["developer".to_string()]);
        bindings.insert("dba-team".to_string(), vec!["admin".to_string()]);

        let resolver = GroupRoleResolver::new(bindings);
        let roles = resolver.resolve_roles(&["engineering".to_string(), "dba-team".to_string()]);

        assert!(roles.contains(&"developer".to_string()));
        assert!(roles.contains(&"admin".to_string()));
        assert_eq!(roles.len(), 2);
    }

    #[test]
    fn no_matching_groups_returns_empty() {
        let mut bindings = HashMap::new();
        bindings.insert("engineering".to_string(), vec!["developer".to_string()]);

        let resolver = GroupRoleResolver::new(bindings);
        let roles = resolver.resolve_roles(&["marketing".to_string()]);

        assert!(roles.is_empty());
    }

    #[test]
    fn deduplicates_roles() {
        let mut bindings = HashMap::new();
        bindings.insert("group-a".to_string(), vec!["admin".to_string()]);
        bindings.insert("group-b".to_string(), vec!["admin".to_string()]);

        let resolver = GroupRoleResolver::new(bindings);
        let roles = resolver.resolve_roles(&["group-a".to_string(), "group-b".to_string()]);

        assert_eq!(roles, vec!["admin".to_string()]);
    }

    #[test]
    fn has_bindings() {
        let empty = GroupRoleResolver::new(HashMap::new());
        assert!(!empty.has_bindings());

        let mut bindings = HashMap::new();
        bindings.insert("x".to_string(), vec!["y".to_string()]);
        let with = GroupRoleResolver::new(bindings);
        assert!(with.has_bindings());
    }
}
