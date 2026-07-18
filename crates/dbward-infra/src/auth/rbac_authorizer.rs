use dbward_app::error::AuthzError;
use dbward_app::ports::Authorizer;
use dbward_domain::auth::{AuthUser, OwnershipScope, Permission, ResourceContext, SubjectType};
use dbward_domain::services::approval_checker;
use dbward_domain::values::{DatabaseName, Environment, Selector};

/// Pure Rust authorizer implementing the two-layer authorization model.
///
/// Layer 1: Permission Gate (role-based scope check)
/// Layer 2: Resource Context (ownership/relationship/selector)
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

        // Layer 1: Permission Gate
        // User context self-read bypasses Layer 1 (user.read not needed for own info)
        let skip_scope = matches!(
            (permission, context),
            (Permission::UserRead, ResourceContext::User { target_id }) if *target_id == user.subject_id
        );
        if !skip_scope && !user.has_scoped_permission(permission, database, environment) {
            return Err(AuthzError::ScopeDenied {
                database: database.as_str().to_string(),
                environment: environment.as_str().to_string(),
            });
        }

        // Layer 2: Resource Context
        self.check_context(user, permission, database, environment, context)
    }

    fn authorize_approval(
        &self,
        user: &AuthUser,
        _database: &DatabaseName,
        _environment: &Environment,
        context: &ResourceContext,
    ) -> Result<(), AuthzError> {
        // Agent tokens cannot approve
        if user.subject_type == SubjectType::Agent {
            return Err(AuthzError::ApprovalDenied {
                reason: "agent tokens cannot approve".into(),
            });
        }

        // No Layer 1 (permission gate) — approval is determined solely by selector match
        match context {
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
                    Err(denied_approval("not an eligible approver for this step"))
                }
            }
            _ => Err(denied_approval(
                "authorize_approval called with non-ApprovalStep context",
            )),
        }
    }
}

impl RbacAuthorizer {
    fn check_context(
        &self,
        user: &AuthUser,
        permission: Permission,
        database: &DatabaseName,
        environment: &Environment,
        context: &ResourceContext,
    ) -> Result<(), AuthzError> {
        match context {
            ResourceContext::Global => Ok(()),

            ResourceContext::RequestView {
                requester_id,
                is_pending_approver,
                has_approved,
            } => {
                // Owner
                if user.subject_id == *requester_id {
                    return Ok(());
                }
                // Relationship: pending approver
                if *is_pending_approver {
                    return Ok(());
                }
                // Relationship: past approver
                if *has_approved {
                    return Ok(());
                }
                // Ownership scope: Any
                if user.effective_ownership(permission, database, environment)
                    == OwnershipScope::Any
                {
                    return Ok(());
                }
                Err(denied(permission, "no access to this request"))
            }

            ResourceContext::RequestMutate { requester_id } => {
                // Owner
                if user.subject_id == *requester_id {
                    return Ok(());
                }
                // Ownership scope: Any
                if user.effective_ownership(permission, database, environment)
                    == OwnershipScope::Any
                {
                    return Ok(());
                }
                Err(denied(permission, "not the requester"))
            }

            ResourceContext::ApprovalStep { .. } => {
                // Should not be called via authorize_scoped — use authorize_approval instead
                Err(denied(
                    permission,
                    "ApprovalStep context must use authorize_approval()",
                ))
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
                // Owner
                if user.subject_id == *requester_id {
                    return Ok(());
                }
                // Selector match (share_with + user:{approver_id})
                let role_names: Vec<String> = user.roles.iter().map(|r| r.name.clone()).collect();
                for sel_str in access_selectors {
                    if let Ok(sel) = Selector::parse(sel_str)
                        && sel.matches(&role_names, &user.groups, &user.subject_id, false)
                    {
                        return Ok(());
                    }
                }
                // Ownership scope: Any
                if user.effective_ownership(permission, database, environment)
                    == OwnershipScope::Any
                {
                    return Ok(());
                }
                Err(denied(permission, "no access to this result"))
            }

            ResourceContext::AuditQuery { .. } => {
                // Layer 1 already checked audit.read — no further restriction
                Ok(())
            }

            ResourceContext::Token { owner_id } => {
                // Owner
                if user.subject_id == *owner_id {
                    return Ok(());
                }
                // Ownership scope: Any
                if user.effective_ownership(permission, database, environment)
                    == OwnershipScope::Any
                {
                    return Ok(());
                }
                Err(denied(permission, "not the token owner"))
            }

            ResourceContext::User { target_id } => {
                // Self-access is always allowed (Layer 1 was already skipped for self)
                if *target_id == user.subject_id {
                    return Ok(());
                }
                // Layer 1 already passed — if user has the permission for this scope, allow
                Ok(())
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

fn denied_approval(reason: &str) -> AuthzError {
    AuthzError::ApprovalDenied {
        reason: reason.to_string(),
    }
}
