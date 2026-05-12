use std::collections::{HashMap, HashSet};

use dbward_app::error::AuthError;
use dbward_app::ports::RoleResolver;
use dbward_domain::auth::{Permission, ResolvedRole, RoleDefinition, SubjectType};
use dbward_domain::values::{DatabaseName, Environment};

pub struct ConfigRoleResolver {
    roles: HashMap<String, ResolvedRole>,
    role_bindings: HashMap<String, Vec<String>>,
    user_bindings: HashMap<String, Vec<String>>,
    default_role: Option<String>,
    policy_repo: Option<Arc<dyn dbward_app::ports::PolicyRepo>>,
}

use std::sync::Arc;

/// Returns built-in role definitions that are always available.
fn builtin_roles() -> Vec<(String, ResolvedRole)> {
    let wildcard_db = DatabaseName::new("*").unwrap();
    let wildcard_env = Environment::new("*").unwrap();
    vec![
        ("admin".to_string(), ResolvedRole {
            name: "admin".to_string(),
            permissions: [Permission::All].into_iter().collect(),
            databases: vec![wildcard_db.clone()],
            environments: vec![wildcard_env.clone()],
        }),
        ("developer".to_string(), ResolvedRole {
            name: "developer".to_string(),
            permissions: [
                Permission::RequestCreate,
                Permission::RequestCreateSelect,
                Permission::RequestView,
                Permission::RequestCancel,
                Permission::RequestDispatch,
                Permission::ResultView,
                Permission::TokenRevokeOwn,
            ].into_iter().collect(),
            databases: vec![wildcard_db.clone()],
            environments: vec![wildcard_env.clone()],
        }),
        ("readonly".to_string(), ResolvedRole {
            name: "readonly".to_string(),
            permissions: [
                Permission::RequestCreateSelect,
                Permission::RequestView,
                Permission::ResultView,
            ].into_iter().collect(),
            databases: vec![wildcard_db.clone()],
            environments: vec![wildcard_env.clone()],
        }),
        ("agent-default".to_string(), ResolvedRole {
            name: "agent-default".to_string(),
            permissions: [
                Permission::AgentPoll,
                Permission::AgentClaim,
                Permission::AgentHeartbeat,
                Permission::AgentSubmitResult,
            ].into_iter().collect(),
            databases: vec![wildcard_db],
            environments: vec![wildcard_env],
        }),
    ]
}

impl ConfigRoleResolver {
    pub fn new(
        role_definitions: Vec<RoleDefinition>,
        role_bindings: HashMap<String, Vec<String>>,
        user_bindings: HashMap<String, Vec<String>>,
        default_role: Option<String>,
    ) -> Self {
        Self::with_policy_repo(role_definitions, role_bindings, user_bindings, default_role, None)
    }

    pub fn with_policy_repo(
        role_definitions: Vec<RoleDefinition>,
        role_bindings: HashMap<String, Vec<String>>,
        user_bindings: HashMap<String, Vec<String>>,
        default_role: Option<String>,
        policy_repo: Option<Arc<dyn dbward_app::ports::PolicyRepo>>,
    ) -> Self {
        let mut roles = HashMap::new();
        // Insert built-in roles first (can be overridden by config)
        for (name, resolved) in builtin_roles() {
            roles.insert(name, resolved);
        }
        for def in role_definitions {
            let resolved = ResolvedRole {
                name: def.name.clone(),
                permissions: def.permissions.into_iter().collect(),
                databases: def.databases,
                environments: def.environments,
            };
            roles.insert(def.name, resolved);
        }
        Self {
            roles,
            role_bindings,
            user_bindings,
            default_role,
            policy_repo,
        }
    }
}

impl RoleResolver for ConfigRoleResolver {
    fn resolve(
        &self,
        subject_id: &str,
        subject_type: SubjectType,
        groups: &[String],
    ) -> Result<Vec<ResolvedRole>, AuthError> {
        let mut role_names = HashSet::new();

        // 1. Direct user -> role mapping
        if let Some(bindings) = self.user_bindings.get(subject_id) {
            for name in bindings {
                role_names.insert(name.clone());
            }
        }

        // 2. Group -> role mapping
        for group in groups {
            if let Some(bindings) = self.role_bindings.get(group) {
                for name in bindings {
                    role_names.insert(name.clone());
                }
            }
        }

        // 3. Agent always gets agent-default
        if subject_type == SubjectType::Agent {
            role_names.insert("agent-default".to_string());
        }

        // 4. Default role if nothing matched
        if role_names.is_empty() {
            if let Some(ref default) = self.default_role {
                role_names.insert(default.clone());
            }
        }

        // Resolve from config first, then fall back to PolicyRepo for DB-stored roles
        let mut resolved: Vec<ResolvedRole> = Vec::new();
        let mut unresolved: Vec<String> = Vec::new();
        for name in &role_names {
            if let Some(r) = self.roles.get(name) {
                resolved.push(r.clone());
            } else {
                unresolved.push(name.clone());
            }
        }

        // Query PolicyRepo for unresolved role names
        if !unresolved.is_empty() {
            if let Some(ref repo) = self.policy_repo {
                if let Ok(defs) = repo.get_roles_by_names(&unresolved) {
                    for def in defs {
                        resolved.push(ResolvedRole {
                            name: def.name.clone(),
                            permissions: def.permissions.into_iter().collect(),
                            databases: def.databases,
                            environments: def.environments,
                        });
                    }
                }
            }
        }

        Ok(resolved)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbward_domain::auth::Permission;
    use dbward_domain::values::{DatabaseName, Environment};

    fn admin_def() -> RoleDefinition {
        RoleDefinition {
            name: "admin".to_string(),
            permissions: vec![Permission::All],
            databases: vec![DatabaseName::new("*").unwrap()],
            environments: vec![Environment::new("*").unwrap()],
        }
    }

    fn developer_def() -> RoleDefinition {
        RoleDefinition {
            name: "developer".to_string(),
            permissions: vec![Permission::RequestCreate, Permission::RequestView],
            databases: vec![DatabaseName::new("app").unwrap()],
            environments: vec![Environment::new("development").unwrap()],
        }
    }

    fn readonly_def() -> RoleDefinition {
        RoleDefinition {
            name: "readonly".to_string(),
            permissions: vec![Permission::RequestView],
            databases: vec![DatabaseName::new("*").unwrap()],
            environments: vec![Environment::new("*").unwrap()],
        }
    }

    fn agent_default_def() -> RoleDefinition {
        RoleDefinition {
            name: "agent-default".to_string(),
            permissions: vec![Permission::All],
            databases: vec![DatabaseName::new("*").unwrap()],
            environments: vec![Environment::new("*").unwrap()],
        }
    }

    fn make_resolver() -> ConfigRoleResolver {
        let defs = vec![admin_def(), developer_def(), readonly_def(), agent_default_def()];
        let role_bindings = HashMap::from([
            ("engineering".to_string(), vec!["developer".to_string()]),
            ("admins".to_string(), vec!["admin".to_string()]),
        ]);
        let user_bindings = HashMap::from([(
            "alice".to_string(),
            vec!["admin".to_string()],
        )]);
        ConfigRoleResolver::new(defs, role_bindings, user_bindings, Some("readonly".to_string()))
    }

    #[test]
    fn user_binding_resolves_directly() {
        let resolver = make_resolver();
        let roles = resolver
            .resolve("alice", SubjectType::User, &[])
            .unwrap();
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].name, "admin");
    }

    #[test]
    fn group_binding_resolves() {
        let resolver = make_resolver();
        let roles = resolver
            .resolve("bob", SubjectType::User, &["engineering".to_string()])
            .unwrap();
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].name, "developer");
    }

    #[test]
    fn multiple_groups_merge_roles() {
        let resolver = make_resolver();
        let roles = resolver
            .resolve("carol", SubjectType::User, &["engineering".to_string(), "admins".to_string()])
            .unwrap();
        assert_eq!(roles.len(), 2);
        let names: HashSet<_> = roles.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains("developer"));
        assert!(names.contains("admin"));
    }

    #[test]
    fn default_role_when_no_match() {
        let resolver = make_resolver();
        let roles = resolver
            .resolve("unknown-user", SubjectType::User, &[])
            .unwrap();
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].name, "readonly");
    }

    #[test]
    fn agent_gets_agent_default() {
        let resolver = make_resolver();
        let roles = resolver
            .resolve("agent-1", SubjectType::Agent, &[])
            .unwrap();
        let names: HashSet<_> = roles.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains("agent-default"));
    }

    #[test]
    fn no_default_returns_empty() {
        let defs = vec![admin_def()];
        let resolver = ConfigRoleResolver::new(defs, HashMap::new(), HashMap::new(), None);
        let roles = resolver
            .resolve("nobody", SubjectType::User, &[])
            .unwrap();
        assert!(roles.is_empty());
    }
}
