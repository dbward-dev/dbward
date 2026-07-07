use dbward_app::error::AuthzError;
use dbward_app::ports::Authorizer;
use dbward_domain::auth::{AuthUser, Permission, ResourceContext, SubjectType};
use dbward_domain::services::approval_checker;
use dbward_domain::values::{DatabaseName, Environment, Selector};

/// Pure Rust authorizer using match expressions (replaces casbin).
pub struct RbacAuthorizer;

impl Authorizer for RbacAuthorizer {
    fn authorize_global(&self, user: &AuthUser, permission: Permission) -> Result<(), AuthzError> {
        // Agent tokens may only use agent.operate
        if user.subject_type == SubjectType::Agent && permission != Permission::AgentOperate {
            return Err(AuthzError::Forbidden {
                permission,
                reason: "agent tokens are restricted to agent.operate".into(),
            });
        }
        if user.has_permission(permission) {
            return Ok(());
        }
        // user.write implies user.read
        if permission == Permission::UserRead && user.has_permission(Permission::UserWrite) {
            return Ok(());
        }
        Err(AuthzError::Forbidden {
            permission,
            reason: format!(
                "user '{}' lacks permission '{}'",
                user.subject_id, permission
            ),
        })
    }

    fn authorize_scoped(
        &self,
        user: &AuthUser,
        permission: Permission,
        database: &DatabaseName,
        environment: &Environment,
        context: &ResourceContext,
    ) -> Result<(), AuthzError> {
        // Agent tokens may only use agent.operate
        if user.subject_type == SubjectType::Agent && permission != Permission::AgentOperate {
            return Err(AuthzError::Forbidden {
                permission,
                reason: "agent tokens are restricted to agent.operate".into(),
            });
        }
        // Layer 1: role-based scope check
        // User context: self-edit bypasses Layer 1 (no UserWrite needed)
        let skip_scope =
            matches!(context, ResourceContext::User { target_id } if *target_id == user.subject_id);
        if !skip_scope && !user.has_scoped_permission(permission, database, environment) {
            return Err(AuthzError::ScopeDenied {
                database: database.as_str().to_string(),
                environment: environment.as_str().to_string(),
            });
        }

        // Layer 2: resource context check
        self.check_context(user, permission, context)
    }
}

impl RbacAuthorizer {
    fn check_context(
        &self,
        user: &AuthUser,
        permission: Permission,
        context: &ResourceContext,
    ) -> Result<(), AuthzError> {
        match context {
            ResourceContext::Global => Ok(()),

            ResourceContext::Request { requester_id } => {
                if user.subject_id == *requester_id || user.has_permission(Permission::All) {
                    Ok(())
                } else {
                    Err(denied(permission, "not the requester"))
                }
            }

            ResourceContext::ApprovalStep {
                requester_id,
                step_index: _,
                approvers,
                allow_self_approve,
                allow_same_approver_across_steps,
                previous_approver_ids,
            } => {
                if approval_checker::is_approvable_by(
                    user,
                    approvers,
                    requester_id,
                    previous_approver_ids,
                    *allow_self_approve,
                    *allow_same_approver_across_steps,
                ) {
                    Ok(())
                } else {
                    Err(denied(permission, "not an eligible approver for this step"))
                }
            }

            ResourceContext::AgentExecution { agent_id } => {
                if user.subject_id == *agent_id {
                    Ok(())
                } else {
                    Err(denied(permission, "agent_id mismatch"))
                }
            }

            ResourceContext::Result {
                requester_id,
                access_selectors,
            } => {
                if user.subject_id == *requester_id || user.has_permission(Permission::All) {
                    return Ok(());
                }
                let role_names: Vec<String> = user.roles.iter().map(|r| r.name.clone()).collect();
                for sel_str in access_selectors {
                    if let Ok(sel) = Selector::parse(sel_str)
                        && sel.matches(&role_names, &user.groups, &user.subject_id, false)
                    {
                        return Ok(());
                    }
                }
                Err(denied(permission, "no access to this result"))
            }

            ResourceContext::AuditQuery { .. } => {
                // audit.read grants access to all audit events
                if user.has_permission(Permission::AuditRead) {
                    return Ok(());
                }
                Err(denied(permission, "audit.read required"))
            }

            ResourceContext::Token { owner_id } => {
                if permission == Permission::TokenRevokeOwn {
                    if *owner_id == user.subject_id {
                        Ok(())
                    } else {
                        Err(denied(permission, "not the token owner"))
                    }
                } else {
                    // TokenWrite: Layer 1 already passed
                    Ok(())
                }
            }

            ResourceContext::User { target_id } =>
            {
                #[allow(clippy::if_same_then_else)]
                if *target_id == user.subject_id {
                    Ok(())
                } else if user.has_permission(Permission::UserWrite) {
                    Ok(())
                } else {
                    Err(denied(
                        permission,
                        "not the target user and lacks user.write",
                    ))
                }
            }
        }
    }
}

fn denied(permission: Permission, reason: &str) -> AuthzError {
    AuthzError::Forbidden {
        permission,
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbward_domain::auth::{ResolvedRole, SubjectType};

    fn user_with(id: &str, perms: &[Permission], dbs: &[&str], envs: &[&str]) -> AuthUser {
        AuthUser {
            subject_id: id.to_string(),
            subject_type: SubjectType::User,
            roles: vec![ResolvedRole {
                name: "test".to_string(),
                permissions: perms.iter().copied().collect(),
                databases: dbs.iter().map(|s| DatabaseName::new(*s).unwrap()).collect(),
                environments: envs.iter().map(|s| Environment::new(*s).unwrap()).collect(),
            }],
            groups: vec![],
            token_id: None,
        }
    }

    #[test]
    fn global_allows_with_permission() {
        let u = user_with("alice", &[Permission::WorkflowWrite], &["*"], &["*"]);
        assert!(
            RbacAuthorizer
                .authorize_global(&u, Permission::WorkflowWrite)
                .is_ok()
        );
    }

    #[test]
    fn global_denies_without_permission() {
        let u = user_with("alice", &[Permission::RequestView], &["*"], &["*"]);
        assert!(
            RbacAuthorizer
                .authorize_global(&u, Permission::WorkflowWrite)
                .is_err()
        );
    }

    #[test]
    fn scoped_denies_wrong_db() {
        let u = user_with("alice", &[Permission::RequestExecute], &["app"], &["*"]);
        let db = DatabaseName::new("other").unwrap();
        let env = Environment::new("production").unwrap();
        let r = RbacAuthorizer.authorize_scoped(
            &u,
            Permission::RequestExecute,
            &db,
            &env,
            &ResourceContext::Global,
        );
        assert!(r.is_err());
    }

    #[test]
    fn request_context_allows_requester() {
        let u = user_with("alice", &[Permission::RequestView], &["*"], &["*"]);
        let db = DatabaseName::new("app").unwrap();
        let env = Environment::new("production").unwrap();
        let ctx = ResourceContext::Request {
            requester_id: "alice".to_string(),
        };
        assert!(
            RbacAuthorizer
                .authorize_scoped(&u, Permission::RequestView, &db, &env, &ctx)
                .is_ok()
        );
    }

    #[test]
    fn request_context_denies_other() {
        let u = user_with("bob", &[Permission::RequestView], &["*"], &["*"]);
        let db = DatabaseName::new("app").unwrap();
        let env = Environment::new("production").unwrap();
        let ctx = ResourceContext::Request {
            requester_id: "alice".to_string(),
        };
        assert!(
            RbacAuthorizer
                .authorize_scoped(&u, Permission::RequestView, &db, &env, &ctx)
                .is_err()
        );
    }

    #[test]
    fn agent_context_allows_matching_agent() {
        let u = user_with("agent-1", &[Permission::AgentOperate], &["*"], &["*"]);
        let db = DatabaseName::new("app").unwrap();
        let env = Environment::new("production").unwrap();
        let ctx = ResourceContext::AgentExecution {
            agent_id: "agent-1".to_string(),
        };
        assert!(
            RbacAuthorizer
                .authorize_scoped(&u, Permission::AgentOperate, &db, &env, &ctx)
                .is_ok()
        );
    }

    #[test]
    fn token_revoke_own_requires_ownership() {
        let u = user_with("alice", &[Permission::TokenRevokeOwn], &["*"], &["*"]);
        let db = DatabaseName::new("app").unwrap();
        let env = Environment::new("production").unwrap();
        let ctx = ResourceContext::Token {
            owner_id: "bob".to_string(),
        };
        assert!(
            RbacAuthorizer
                .authorize_scoped(&u, Permission::TokenRevokeOwn, &db, &env, &ctx)
                .is_err()
        );
    }

    #[test]
    fn audit_read_grants_full_access() {
        let u = user_with("alice", &[Permission::AuditRead], &["*"], &["*"]);
        let db = DatabaseName::new("app").unwrap();
        let env = Environment::new("production").unwrap();
        let ctx = ResourceContext::AuditQuery {
            requested_actor_id: Some("bob".to_string()),
        };
        assert!(
            RbacAuthorizer
                .authorize_scoped(&u, Permission::AuditRead, &db, &env, &ctx)
                .is_ok()
        );

        let ctx_own = ResourceContext::AuditQuery {
            requested_actor_id: Some("alice".to_string()),
        };
        assert!(
            RbacAuthorizer
                .authorize_scoped(&u, Permission::AuditRead, &db, &env, &ctx_own)
                .is_ok()
        );
    }

    #[test]
    fn result_context_allows_selector_match() {
        let mut u = user_with("bob", &[Permission::ResultView], &["*"], &["*"]);
        u.roles[0].name = "dba".to_string();
        let db = DatabaseName::new("app").unwrap();
        let env = Environment::new("production").unwrap();
        let ctx = ResourceContext::Result {
            requester_id: "alice".to_string(),
            access_selectors: vec!["role:dba".to_string()],
        };
        assert!(
            RbacAuthorizer
                .authorize_scoped(&u, Permission::ResultView, &db, &env, &ctx)
                .is_ok()
        );
    }

    #[test]
    fn user_context_allows_self_edit() {
        let u = user_with("alice", &[Permission::RequestView], &["*"], &["*"]);
        let db = DatabaseName::new("app").unwrap();
        let env = Environment::new("production").unwrap();
        let ctx = ResourceContext::User {
            target_id: "alice".to_string(),
        };
        assert!(
            RbacAuthorizer
                .authorize_scoped(&u, Permission::UserWrite, &db, &env, &ctx)
                .is_ok()
        );
    }

    #[test]
    fn user_context_allows_admin_edit_other() {
        let u = user_with("admin", &[Permission::UserWrite], &["*"], &["*"]);
        let db = DatabaseName::new("app").unwrap();
        let env = Environment::new("production").unwrap();
        let ctx = ResourceContext::User {
            target_id: "bob".to_string(),
        };
        assert!(
            RbacAuthorizer
                .authorize_scoped(&u, Permission::UserWrite, &db, &env, &ctx)
                .is_ok()
        );
    }

    #[test]
    fn user_context_denies_other_without_permission() {
        let u = user_with("alice", &[Permission::RequestView], &["*"], &["*"]);
        let db = DatabaseName::new("app").unwrap();
        let env = Environment::new("production").unwrap();
        let ctx = ResourceContext::User {
            target_id: "bob".to_string(),
        };
        assert!(
            RbacAuthorizer
                .authorize_scoped(&u, Permission::UserWrite, &db, &env, &ctx)
                .is_err()
        );
    }

    #[test]
    fn agent_denied_non_agent_permission() {
        let u = AuthUser {
            subject_id: "agent-1".to_string(),
            subject_type: SubjectType::Agent,
            roles: vec![ResolvedRole {
                name: "admin".to_string(),
                permissions: [Permission::All].into_iter().collect(),
                databases: vec![DatabaseName::new("*").unwrap()],
                environments: vec![Environment::new("*").unwrap()],
            }],
            groups: vec![],
            token_id: None,
        };
        // Even with admin role, agent is denied non-agent permissions
        assert!(
            RbacAuthorizer
                .authorize_global(&u, Permission::WorkflowWrite)
                .is_err()
        );
        assert!(
            RbacAuthorizer
                .authorize_global(&u, Permission::TokenWrite)
                .is_err()
        );
    }

    #[test]
    fn agent_allowed_agent_operate() {
        let u = AuthUser {
            subject_id: "agent-1".to_string(),
            subject_type: SubjectType::Agent,
            roles: vec![ResolvedRole {
                name: "agent-default".to_string(),
                permissions: [Permission::AgentOperate].into_iter().collect(),
                databases: vec![DatabaseName::new("*").unwrap()],
                environments: vec![Environment::new("*").unwrap()],
            }],
            groups: vec![],
            token_id: None,
        };
        assert!(
            RbacAuthorizer
                .authorize_global(&u, Permission::AgentOperate)
                .is_ok()
        );
        // Also test authorize_scoped
        let db = DatabaseName::new("app").unwrap();
        let env = Environment::new("production").unwrap();
        let ctx = ResourceContext::AgentExecution {
            agent_id: "agent-1".to_string(),
        };
        assert!(
            RbacAuthorizer
                .authorize_scoped(&u, Permission::AgentOperate, &db, &env, &ctx)
                .is_ok()
        );
    }

    #[test]
    fn agent_denied_non_agent_permission_scoped() {
        let u = AuthUser {
            subject_id: "agent-1".to_string(),
            subject_type: SubjectType::Agent,
            roles: vec![ResolvedRole {
                name: "admin".to_string(),
                permissions: [Permission::All].into_iter().collect(),
                databases: vec![DatabaseName::new("*").unwrap()],
                environments: vec![Environment::new("*").unwrap()],
            }],
            groups: vec![],
            token_id: None,
        };
        let db = DatabaseName::new("app").unwrap();
        let env = Environment::new("production").unwrap();
        assert!(
            RbacAuthorizer
                .authorize_scoped(
                    &u,
                    Permission::RequestExecute,
                    &db,
                    &env,
                    &ResourceContext::Global
                )
                .is_err()
        );
    }
}
