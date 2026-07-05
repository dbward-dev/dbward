use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission};
use dbward_domain::entities::AuditContext;

use crate::error::AppError;
use crate::ports::*;

pub struct UserManage {
    pub authorizer: Arc<dyn Authorizer>,
    pub user_repo: Arc<dyn UserRepo>,
    pub group_repo: Arc<dyn GroupRepo>,
    pub token_repo: Arc<dyn TokenRepo>,
    pub uow: Arc<dyn UnitOfWork>,
    pub clock: Arc<dyn Clock>,
    pub license: Arc<dyn LicenseChecker>,
    pub role_resolver: Arc<dyn RoleResolver>,
    pub policy_repo: Arc<dyn PolicyRepo>,
    pub id_gen: Arc<dyn IdGenerator>,
    pub token_gen: Arc<dyn TokenValueGenerator>,
    pub audit_logger: Arc<dyn crate::ports::AuditLogger>,
    pub notifier: Arc<dyn crate::ports::Notifier>,
}

pub struct UserListOutput {
    pub users: Vec<dbward_domain::entities::User>,
}

pub struct UserAddInput {
    pub id: String,
    pub roles: Vec<String>,
    pub groups: Vec<String>,
}

pub struct UserAddOutput {
    pub id: String,
    pub token: String,
    pub token_prefix: String,
    pub roles: Vec<String>,
    pub groups: Vec<String>,
}

pub struct UserUpdateInput {
    pub user_id: String,
    pub set_roles: Option<Vec<String>>,
    pub add_roles: Vec<String>,
    pub rm_roles: Vec<String>,
    pub add_groups: Vec<String>,
    pub rm_groups: Vec<String>,
}

pub struct UserShowOutput {
    pub user: dbward_domain::entities::User,
    pub groups: Vec<String>,
    pub roles: Vec<String>,
}

pub struct UserSuspendInput {
    pub user_id: String,
}

pub struct UserSuspendOutput {
    pub id: String,
    pub revoked_tokens: u32,
    pub cancelled_requests: Vec<String>,
}

impl UserManage {
    pub fn add(
        &self,
        input: UserAddInput,
        user: &AuthUser,
        _ctx: &AuditContext,
    ) -> Result<UserAddOutput, AppError> {
        self.authorizer
            .authorize_global(user, Permission::UserWrite)
            .map_err(AppError::Forbidden)?;

        if input.id.is_empty() {
            return Err(AppError::Validation("user id is required".into()));
        }

        // Check for existing (including soft-deleted)
        if let Some(existing) = self.user_repo.get(&input.id)? {
            let _ = existing;
            return Err(AppError::Conflict(format!(
                "user '{}' already exists",
                input.id
            )));
        }

        // Plan limit
        let count = self.user_repo.count_active()?;
        if count >= self.license.max_users() {
            return Err(AppError::PlanLimit("user limit reached".into()));
        }

        // Validate roles exist
        let known_roles = self.policy_repo.list_roles()?;
        let known_names: std::collections::HashSet<&str> = known_roles
            .iter()
            .map(|r| r.name.as_str())
            .chain(["admin", "developer", "readonly", "agent-default"].iter().copied())
            .collect();
        for role in &input.roles {
            if !known_names.contains(role.as_str()) {
                return Err(AppError::Validation(format!("unknown role: {role}")));
            }
        }

        // Validate groups exist in DB (config-synced)
        for group in &input.groups {
            if !self.group_repo.exists(group)? {
                return Err(AppError::Validation(format!(
                    "group '{group}' is not defined in config"
                )));
            }
        }

        // Create user + token atomically via UoW
        let now = self.clock.now();
        let new_user = dbward_domain::entities::User {
            id: input.id.clone(),
            display_name: None,
            email: None,
            groups: vec![],
            roles: input.roles.clone(),
            status: dbward_domain::entities::UserStatus::Active,
            last_seen_at: None,
            created_at: now,
            updated_at: now,
        };

        // Token ceiling = direct roles only. Group-derived roles are resolved at auth time.
        let effective_roles = input.roles.clone();

        let ceiling = dbward_domain::entities::ScopeCeiling {
            roles: effective_roles.clone(),
        };

        let token_id = self.id_gen.generate();
        let raw_token = self.token_gen.generate_token_value();
        let prefix = raw_token[..8].to_string();
        let hash = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(raw_token.as_bytes()))
        };

        let token = dbward_domain::entities::Token {
            id: token_id.clone(),
            subject_type: dbward_domain::auth::SubjectType::User,
            subject_id: input.id.clone(),
            token_hash: hash,
            token_prefix: prefix.clone(),
            scope_ceiling: Some(ceiling),
            name: Some("initial".to_string()),
            status: dbward_domain::entities::TokenStatus::Active,
            expires_at: None,
            created_at: now,
            revoked_at: None,
        };

        // Atomic: INSERT user + INSERT token in single transaction
        let user_clone = new_user.clone();
        let token_clone = token.clone();
        let groups_clone = input.groups.clone();
        let id_clone = input.id.clone();
        self.uow.execute(Box::new(move |tx| {
            tx.upsert_user_tx(&user_clone)?;
            for group in &groups_clone {
                tx.add_group_member_tx(group, &id_clone, now)?;
            }
            tx.create_token_tx(&token_clone)?;
            Ok(())
        }))?;

        // Audit (group membership)
        for _group in &input.groups {
            let audit = dbward_domain::entities::AuditEvent::simple(
                "group.member_added", "identity", &user.subject_id, Some(&input.id), now, _ctx,
            );
            let _ = self.audit_logger.record(&audit);
        }
        let audit = dbward_domain::entities::AuditEvent::simple(
            "user.created",
            "identity",
            &user.subject_id,
            Some(&input.id),
            now,
            _ctx,
        );
        let _ = self.audit_logger.record(&audit);

        // Webhook
        self.notifier.dispatch(crate::ports::WebhookEvent {
            event_type: "user.created".into(),
            request_id: None,
            database: None,
            environment: None,
            actor: Some(user.subject_id.clone()),
            detail: Some(format!("user '{}' created", input.id)),
            requester: None,
            reason: None,
            redacted_detail: None,
            error_summary: None,
            approval_hint: None,
            operation: None,
            step_index: None,
            total_steps: None,
            expires_at: None,
            approvers: None,
            matched_selector: None,
        });

        self.role_resolver.invalidate_cache(&input.id);

        Ok(UserAddOutput {
            id: input.id,
            token: raw_token,
            token_prefix: prefix,
            roles: effective_roles,
            groups: input.groups,
        })
    }

    pub fn show(&self, user_id: &str, user: &AuthUser) -> Result<UserShowOutput, AppError> {
        self.authorizer
            .authorize_global(user, Permission::UserWrite)
            .map_err(AppError::Forbidden)?;

        let existing = self
            .user_repo
            .get(user_id)?
            .ok_or_else(|| AppError::NotFound("user not found".into()))?;

        let groups = self.group_repo.list_groups_for_user(user_id)?;
        let roles = self.user_repo.get_roles(user_id)?;

        Ok(UserShowOutput {
            user: existing,
            groups,
            roles,
        })
    }

    pub fn update(
        &self,
        input: UserUpdateInput,
        user: &AuthUser,
        ctx: &AuditContext,
    ) -> Result<(), AppError> {
        self.authorizer
            .authorize_global(user, Permission::UserWrite)
            .map_err(AppError::Forbidden)?;

        let _existing = self
            .user_repo
            .get(&input.user_id)?
            .ok_or_else(|| AppError::NotFound("user not found".into()))?;

        if self.user_repo.is_deleted(&input.user_id)? {
            return Err(AppError::Gone("user has been deleted".into()));
        }

        // Compute new roles
        let mut current_roles = self.user_repo.get_roles(&input.user_id)?;
        if let Some(set) = input.set_roles {
            current_roles = set;
        } else {
            for r in &input.add_roles {
                if !current_roles.contains(r) {
                    current_roles.push(r.clone());
                }
            }
            current_roles.retain(|r| !input.rm_roles.contains(r));
        }

        // Validate roles
        let known_roles = self.policy_repo.list_roles()?;
        let known_names: std::collections::HashSet<&str> = known_roles
            .iter()
            .map(|r| r.name.as_str())
            .chain(["admin", "developer", "readonly", "agent-default"].iter().copied())
            .collect();
        for role in &current_roles {
            if !known_names.contains(role.as_str()) {
                return Err(AppError::Validation(format!("unknown role: {role}")));
            }
        }

        // Last admin guard: check if this update would leave zero admins
        // Only relevant when user currently has admin and would lose it
        let user_currently_admin = self.role_resolver
            .resolve(&input.user_id, dbward_domain::auth::SubjectType::User, &[])
            .map(|roles| roles.iter().any(|r| r.name == "admin"))
            .unwrap_or(false);
        let user_will_have_admin_direct = current_roles.contains(&"admin".to_string());
        if user_currently_admin && !user_will_have_admin_direct {
            // User might lose admin (unless they keep it via a remaining group).
            // Check if other admins exist (excluding this user).
            let mut other_admins = self.role_resolver.subjects_for_role("admin");
            other_admins.retain(|s| s != &input.user_id);
            if other_admins.is_empty() {
                return Err(AppError::Validation(
                    "cannot remove admin role from the last admin".into(),
                ));
            }
        }

        // Validate groups before committing any changes
        let now = self.clock.now();
        for group in &input.add_groups {
            if !self.group_repo.exists(group)? {
                return Err(AppError::Validation(format!(
                    "group '{group}' is not defined in config"
                )));
            }
        }

        // Last-admin-via-group guard for rm_groups: only when removing a group
        // would cause this user to lose admin AND they are the last admin
        if !input.rm_groups.is_empty() && user_currently_admin {
            // After rm_groups, will user still have admin via direct roles or remaining groups?
            if !user_will_have_admin_direct {
                let mut other_admins = self.role_resolver.subjects_for_role("admin");
                other_admins.retain(|s| s != &input.user_id);
                if other_admins.is_empty() {
                    return Err(AppError::Validation(
                        "cannot remove user from group: would leave zero admins".into(),
                    ));
                }
            }
        }

        // All validation passed — commit all changes atomically
        let user_id_clone = input.user_id.clone();
        let current_roles_clone = current_roles.clone();
        let add_groups_clone = input.add_groups.clone();
        let rm_groups_clone = input.rm_groups.clone();
        self.uow.execute(Box::new(move |tx| {
            tx.set_roles_tx(&user_id_clone, &current_roles_clone)?;
            for group in &add_groups_clone {
                tx.add_group_member_tx(group, &user_id_clone, now)?;
            }
            for group in &rm_groups_clone {
                tx.remove_member_tx(group, &user_id_clone)?;
            }
            Ok(())
        }))?;

        // Audit events (after successful commit)
        for _group in &input.add_groups {
            let audit = dbward_domain::entities::AuditEvent::simple(
                "group.member_added", "identity", &user.subject_id, Some(&input.user_id), now, ctx,
            );
            let _ = self.audit_logger.record(&audit);
        }
        for _group in &input.rm_groups {
            let audit = dbward_domain::entities::AuditEvent::simple(
                "group.member_removed", "identity", &user.subject_id, Some(&input.user_id), now, ctx,
            );
            let _ = self.audit_logger.record(&audit);
        }

        let audit = dbward_domain::entities::AuditEvent::simple(
            "user.updated", "identity", &user.subject_id, Some(&input.user_id), self.clock.now(), ctx,
        );
        let _ = self.audit_logger.record(&audit);
        self.role_resolver.invalidate_cache(&input.user_id);
        Ok(())
    }

    pub fn remove(
        &self,
        user_id: &str,
        user: &AuthUser,
        ctx: &AuditContext,
    ) -> Result<(), AppError> {
        self.authorizer
            .authorize_global(user, Permission::UserWrite)
            .map_err(AppError::Forbidden)?;

        self.user_repo
            .get(user_id)?
            .ok_or_else(|| AppError::NotFound("user not found".into()))?;

        if self.user_repo.is_deleted(user_id)? {
            return Err(AppError::Gone("user already deleted".into()));
        }

        // Last admin guard (includes group-derived admin)
        // NOTE: Same TOCTOU caveat as suspend() — see comment there.
        let has_admin = self.role_resolver
            .resolve(user_id, dbward_domain::auth::SubjectType::User, &[])
            .map(|roles| roles.iter().any(|r| r.name == "admin"))
            .unwrap_or(false);
        if has_admin {
            let mut subjects_with_admin = self.role_resolver.subjects_for_role("admin");
            subjects_with_admin.retain(|s| s != user_id);
            if subjects_with_admin.is_empty() {
                return Err(AppError::Validation(
                    "cannot delete the last admin".into(),
                ));
            }
        }

        let now = self.clock.now();
        let uid = user_id.to_string();
        let actor_id = user.subject_id.clone();
        let audit_event = dbward_domain::entities::AuditEvent::simple(
            "user.deleted", "identity", &actor_id, Some(user_id), now, ctx,
        );
        crate::ports::uow_execute(&*self.uow, move |tx| {
            tx.soft_delete_tx(&uid, now)?;
            tx.remove_all_memberships_tx(&uid)?;
            tx.revoke_all_for_user(&uid, now)?;
            tx.cancel_all_for_user(&uid, &actor_id, Some("user deleted"), now)?;
            tx.record(&audit_event)?;
            Ok(())
        })?;

        self.role_resolver.invalidate_cache(user_id);
        Ok(())
    }

    pub fn list(&self, user: &AuthUser) -> Result<UserListOutput, AppError> {
        self.authorizer
            .authorize_global(user, Permission::UserWrite)
            .map_err(AppError::Forbidden)?;
        let users = self.user_repo.list()?;
        Ok(UserListOutput { users })
    }

    pub fn suspend(
        &self,
        input: UserSuspendInput,
        user: &AuthUser,
        ctx: &AuditContext,
    ) -> Result<UserSuspendOutput, AppError> {
        self.authorizer
            .authorize_global(user, Permission::UserWrite)
            .map_err(AppError::Forbidden)?;

        // Check user exists
        self.user_repo
            .get(&input.user_id)?
            .ok_or_else(|| AppError::NotFound("user not found".into()))?;

        // Last admin guard: cannot suspend the last admin (includes group-derived admin)
        // NOTE: This check runs outside the UoW. SQLite IMMEDIATE transactions serialize
        // writes, but two concurrent suspends could both pass this guard before either enters
        // the tx. For v0.1 single-server with ≤50 users this is acceptable — the worst case
        // (zero admins) is recoverable via DBWARD_EMERGENCY_BOOTSTRAP=true.
        let has_admin = self.role_resolver
            .resolve(&input.user_id, dbward_domain::auth::SubjectType::User, &[])
            .map(|roles| roles.iter().any(|r| r.name == "admin"))
            .unwrap_or(false);
        if has_admin {
            let subjects_with_admin = self.role_resolver.subjects_for_role("admin");
            let total = subjects_with_admin.len() as u32;
            if total <= 1 {
                return Err(AppError::Validation(
                    "cannot suspend the last admin".into(),
                ));
            }
        }

        let now = self.clock.now();

        // Atomic: suspend + revoke tokens + cancel requests + audit
        let user_id = input.user_id.clone();
        let actor_id = user.subject_id.clone();
        let audit_event = dbward_domain::entities::AuditEvent::simple(
            "user.suspended",
            "identity",
            &actor_id,
            Some(&user_id),
            now,
            ctx,
        );
        let result = crate::ports::uow_execute(&*self.uow, move |tx| {
            tx.suspend_user(&user_id, now)?;
            let revoked = tx.revoke_all_for_user(&user_id, now)?;
            let cancelled =
                tx.cancel_all_for_user(&user_id, &actor_id, Some("user suspended"), now)?;
            tx.record(&audit_event)?;
            Ok((revoked, cancelled))
        })?;

        self.role_resolver.invalidate_cache(&input.user_id);

        Ok(UserSuspendOutput {
            id: input.user_id,
            revoked_tokens: result.0,
            cancelled_requests: result.1,
        })
    }

    pub fn activate(
        &self,
        user_id: &str,
        user: &AuthUser,
        ctx: &AuditContext,
    ) -> Result<(), AppError> {
        self.authorizer
            .authorize_global(user, Permission::UserWrite)
            .map_err(AppError::Forbidden)?;

        let existing = self
            .user_repo
            .get(user_id)?
            .ok_or_else(|| AppError::NotFound("user not found".into()))?;

        // Only check limit when transitioning from suspended to active
        if existing.status == dbward_domain::entities::UserStatus::Suspended {
            let count = self.user_repo.count_active()?;
            if count >= self.license.max_users() {
                return Err(AppError::PlanLimit("user limit reached".into()));
            }
        }

        let now = self.clock.now();
        let uid = user_id.to_string();
        let actor_id = user.subject_id.clone();
        let audit_event = dbward_domain::entities::AuditEvent::simple(
            "user.activated",
            "identity",
            &actor_id,
            Some(user_id),
            now,
            ctx,
        );
        self.uow.execute(Box::new(move |tx| {
            tx.activate_user(&uid, now)?;
            tx.record(&audit_event)?;
            Ok(())
        }))?;

        self.role_resolver.invalidate_cache(user_id);

        Ok(())
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;
    use crate::error::AuthzError;
    use crate::test_support::NoopUnitOfWork;
    use chrono::{DateTime, Utc};
    use dbward_domain::auth::{Permission as P, ResolvedRole, ResourceContext, SubjectType};
    use dbward_domain::entities::{AuditContext, Token, User};
    use dbward_domain::values::{DatabaseName, Environment};

    struct AllowAll;
    impl Authorizer for AllowAll {
        fn authorize_global(&self, _: &AuthUser, _: Permission) -> Result<(), AuthzError> {
            Ok(())
        }
        fn authorize_scoped(
            &self,
            _: &AuthUser,
            _: Permission,
            _: &DatabaseName,
            _: &Environment,
            _: &ResourceContext,
        ) -> Result<(), AuthzError> {
            Ok(())
        }
    }
    struct DenyAll;
    impl Authorizer for DenyAll {
        fn authorize_global(&self, _: &AuthUser, _: Permission) -> Result<(), AuthzError> {
            Err(AuthzError::Forbidden {
                permission: P::UserWrite,
                reason: "denied".into(),
            })
        }
        fn authorize_scoped(
            &self,
            _: &AuthUser,
            _: Permission,
            _: &DatabaseName,
            _: &Environment,
            _: &ResourceContext,
        ) -> Result<(), AuthzError> {
            Err(AuthzError::Forbidden {
                permission: P::UserWrite,
                reason: "denied".into(),
            })
        }
    }

    struct FakeClock;
    impl Clock for FakeClock {
        fn now(&self) -> DateTime<Utc> {
            Utc::now()
        }
    }

    struct FakeGroupRepo;
    impl crate::ports::GroupRepo for FakeGroupRepo {
        fn upsert(&self, _: &str) -> Result<(), AppError> { Ok(()) }
        fn list_names(&self) -> Result<Vec<String>, AppError> { Ok(vec![]) }
        fn exists(&self, _: &str) -> Result<bool, AppError> { Ok(false) }
        fn delete_stale(&self, _: &[String]) -> Result<u64, AppError> { Ok(0) }
        fn add_member(&self, _: &str, _: &str, _: DateTime<Utc>) -> Result<(), AppError> { Ok(()) }
        fn remove_member(&self, _: &str, _: &str) -> Result<bool, AppError> { Ok(false) }
        fn list_members(&self, _: &str) -> Result<Vec<String>, AppError> { Ok(vec![]) }
        fn list_groups_for_user(&self, _: &str) -> Result<Vec<String>, AppError> { Ok(vec![]) }
        fn remove_all_memberships(&self, _: &str) -> Result<u64, AppError> { Ok(0) }
    }

    struct FakeRoleResolver;
    impl crate::ports::RoleResolver for FakeRoleResolver {
        fn resolve(&self, _: &str, _: SubjectType, _: &[String]) -> Result<Vec<ResolvedRole>, crate::error::AuthError> {
            Ok(vec![])
        }
    }

    struct FakePolicyRepo;
    impl crate::ports::PolicyRepo for FakePolicyRepo {
        fn list_roles(&self) -> Result<Vec<dbward_domain::auth::RoleDefinition>, AppError> { Ok(vec![]) }
        fn get_roles_by_names(&self, _: &[String]) -> Result<Vec<dbward_domain::auth::RoleDefinition>, AppError> { Ok(vec![]) }
        fn create_workflow(&self, _: &dbward_domain::policies::Workflow) -> Result<(), AppError> { Ok(()) }
        fn get_workflow(&self, _: &str) -> Result<Option<dbward_domain::policies::Workflow>, AppError> { Ok(None) }
        fn list_workflows(&self) -> Result<Vec<dbward_domain::policies::Workflow>, AppError> { Ok(vec![]) }
        fn delete_workflow(&self, _: &str) -> Result<bool, AppError> { Ok(false) }
        fn count_workflows(&self) -> Result<u32, AppError> { Ok(0) }
        fn create_execution_policy(&self, _: &dbward_domain::policies::ExecutionPolicy) -> Result<(), AppError> { Ok(()) }
        fn get_execution_policy(&self, _: &str) -> Result<Option<dbward_domain::policies::ExecutionPolicy>, AppError> { Ok(None) }
        fn list_execution_policies(&self) -> Result<Vec<dbward_domain::policies::ExecutionPolicy>, AppError> { Ok(vec![]) }
        fn delete_execution_policy(&self, _: &str) -> Result<bool, AppError> { Ok(false) }
        fn find_result_policy(&self, _: &dbward_domain::values::DatabaseName, _: &dbward_domain::values::Environment) -> Result<Option<dbward_domain::policies::ResultPolicy>, AppError> { Ok(None) }
        fn create_result_policy(&self, _: &dbward_domain::policies::ResultPolicy) -> Result<(), AppError> { Ok(()) }
        fn get_result_policy(&self, _: &str) -> Result<Option<dbward_domain::policies::ResultPolicy>, AppError> { Ok(None) }
        fn list_result_policies(&self) -> Result<Vec<dbward_domain::policies::ResultPolicy>, AppError> { Ok(vec![]) }
        fn update_result_policy(&self, _: &dbward_domain::policies::ResultPolicy) -> Result<bool, AppError> { Ok(false) }
        fn delete_result_policy(&self, _: &str) -> Result<bool, AppError> { Ok(false) }
        fn create_notification_policy(&self, _: &dbward_domain::policies::NotificationPolicy) -> Result<(), AppError> { Ok(()) }
        fn get_notification_policy(&self, _: &str) -> Result<Option<dbward_domain::policies::NotificationPolicy>, AppError> { Ok(None) }
        fn list_notification_policies(&self) -> Result<Vec<dbward_domain::policies::NotificationPolicy>, AppError> { Ok(vec![]) }
        fn update_notification_policy(&self, _: &dbward_domain::policies::NotificationPolicy) -> Result<bool, AppError> { Ok(false) }
        fn delete_notification_policy(&self, _: &str) -> Result<bool, AppError> { Ok(false) }
        fn create_role(&self, _: &dbward_domain::auth::RoleDefinition) -> Result<(), AppError> { Ok(()) }
        fn delete_role(&self, _: &str) -> Result<bool, AppError> { Ok(false) }
        fn count_roles(&self) -> Result<u32, AppError> { Ok(0) }
    }

    struct FakeIdGen;
    impl crate::ports::IdGenerator for FakeIdGen {
        fn generate(&self) -> String { "test-id-001".to_string() }
    }

    struct FakeTokenGen;
    impl crate::ports::TokenValueGenerator for FakeTokenGen {
        fn generate_token_value(&self) -> String { "dbw_test1234567890abcdef".to_string() }
    }

    struct FakeUserRepo {
        has_user: bool,
    }
    impl UserRepo for FakeUserRepo {
        fn upsert(&self, _: &User) -> Result<(), AppError> {
            Ok(())
        }
        fn get(&self, _: &str) -> Result<Option<User>, AppError> {
            if self.has_user {
                Ok(Some(User {
                    id: "u1".into(),
                    display_name: None,
                    email: None,
                    groups: vec![],
                    roles: vec![],
                    status: dbward_domain::entities::UserStatus::Active,
                    last_seen_at: None,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                }))
            } else {
                Ok(None)
            }
        }
        fn list(&self) -> Result<Vec<User>, AppError> {
            Ok(vec![])
        }
        fn suspend(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn is_suspended(&self, _: &str) -> Result<bool, AppError> {
            Ok(false)
        }
        fn ensure_exists(&self, _: &str) -> Result<(), AppError> {
            Ok(())
        }
        fn activate(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
    }

    struct FakeTokenRepo;
    impl TokenRepo for FakeTokenRepo {
        fn create(&self, _: &Token) -> Result<(), AppError> {
            Ok(())
        }
        fn verify(&self, _: &str, _: &str) -> Result<Option<Token>, AppError> {
            Ok(None)
        }
        fn list(&self) -> Result<Vec<Token>, AppError> {
            Ok(vec![])
        }
        fn get(&self, _: &str) -> Result<Option<Token>, AppError> {
            Ok(None)
        }
        fn revoke(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn revoke_all_for_user(&self, _: &str, _: DateTime<Utc>) -> Result<u32, AppError> {
            Ok(2)
        }
        fn count_active(&self) -> Result<u32, AppError> {
            Ok(0)
        }
        fn purge_revoked(&self, _: &str) -> Result<u32, AppError> {
            Ok(0)
        }
    }

    struct FakeRequestRepo;
    impl RequestWriter for FakeRequestRepo {
        fn insert(&self, _: &dbward_domain::entities::Request) -> Result<(), AppError> {
            Ok(())
        }
        fn create_and_dispatch(
            &self,
            _: &dbward_domain::entities::Request,
        ) -> Result<(), AppError> {
            Ok(())
        }
        fn mark_approved(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_rejected(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_cancelled(
            &self,
            _: &str,
            _: &str,
            _: Option<&str>,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_dispatched(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_running(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_executed(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_failed(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn cancel_all_for_user(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
            _: &dbward_domain::entities::AuditContext,
        ) -> Result<Vec<String>, AppError> {
            Ok(vec!["r1".into(), "r2".into(), "r3".into()])
        }
        fn mark_approved_from_dispatched(&self, _: &str, _: &str) -> Result<bool, AppError> {
            Ok(true)
        }
    }

    struct FakeLicense;
    impl LicenseChecker for FakeLicense {
        fn max_users(&self) -> u32 {
            u32::MAX
        }
        fn max_databases(&self) -> u32 {
            u32::MAX
        }
        fn max_workflows(&self) -> u32 {
            u32::MAX
        }
        fn max_webhooks(&self) -> u32 {
            u32::MAX
        }
        fn max_roles(&self) -> u32 {
            u32::MAX
        }
        fn is_enterprise(&self) -> bool {
            false
        }
        fn configured_plan(&self) -> &str {
            "free"
        }
        fn effective_plan(&self) -> &str {
            "free"
        }
        fn is_expired(&self) -> bool {
            false
        }
        fn check_expiry(&self, _: chrono::DateTime<chrono::Utc>) {}
    }

    fn admin_user() -> AuthUser {
        AuthUser {
            subject_id: "admin".into(),
            subject_type: SubjectType::User,
            roles: vec![ResolvedRole {
                name: "admin".into(),
                permissions: [P::All].into_iter().collect(),
                databases: vec![],
                environments: vec![],
            }],
            groups: vec![],
            token_id: None,
        }
    }

    fn make_uc(has_user: bool, authz: Arc<dyn Authorizer>) -> UserManage {
        UserManage {
            authorizer: authz,
            user_repo: Arc::new(FakeUserRepo { has_user }),
            group_repo: Arc::new(FakeGroupRepo),
            token_repo: Arc::new(FakeTokenRepo),
            uow: Arc::new(NoopUnitOfWork),
            clock: Arc::new(FakeClock),
            license: Arc::new(FakeLicense),
            role_resolver: Arc::new(FakeRoleResolver),
            policy_repo: Arc::new(FakePolicyRepo),
            id_gen: Arc::new(FakeIdGen),
            token_gen: Arc::new(FakeTokenGen),
            audit_logger: Arc::new(crate::test_support::NoopAuditLogger),
            notifier: Arc::new(crate::test_support::NoopNotifier),
        }
    }

    #[test]
    fn list_denied_without_permission() {
        let uc = make_uc(false, Arc::new(DenyAll));
        assert!(matches!(
            uc.list(&admin_user()),
            Err(AppError::Forbidden(_))
        ));
    }

    #[test]
    fn suspend_not_found() {
        let uc = make_uc(false, Arc::new(AllowAll));
        assert!(matches!(
            uc.suspend(
                UserSuspendInput {
                    user_id: "ghost".into()
                },
                &admin_user(),
                &AuditContext::System,
            ),
            Err(AppError::NotFound(_))
        ));
    }

    #[test]
    fn suspend_success_returns_counts() {
        let uc = make_uc(true, Arc::new(AllowAll));
        let out = uc
            .suspend(
                UserSuspendInput {
                    user_id: "u1".into(),
                },
                &admin_user(),
                &AuditContext::System,
            )
            .unwrap();
        assert_eq!(out.revoked_tokens, 0); // NoopTxScope returns 0
        assert!(out.cancelled_requests.is_empty()); // NoopTxScope returns empty
    }

    #[test]
    fn activate_not_found() {
        let uc = make_uc(false, Arc::new(AllowAll));
        assert!(matches!(
            uc.activate("ghost", &admin_user(), &AuditContext::System),
            Err(AppError::NotFound(_))
        ));
    }

    #[test]
    fn activate_blocked_at_user_limit() {
        struct ZeroLicense;
        impl LicenseChecker for ZeroLicense {
            fn max_users(&self) -> u32 {
                0
            }
            fn max_databases(&self) -> u32 {
                u32::MAX
            }
            fn max_workflows(&self) -> u32 {
                u32::MAX
            }
            fn max_webhooks(&self) -> u32 {
                u32::MAX
            }
            fn max_roles(&self) -> u32 {
                u32::MAX
            }
            fn is_enterprise(&self) -> bool {
                false
            }
            fn configured_plan(&self) -> &str {
                "free"
            }
            fn effective_plan(&self) -> &str {
                "free"
            }
            fn is_expired(&self) -> bool {
                false
            }
            fn check_expiry(&self, _: chrono::DateTime<chrono::Utc>) {}
        }
        struct SuspendedUserRepo;
        impl UserRepo for SuspendedUserRepo {
            fn get(&self, _: &str) -> Result<Option<User>, AppError> {
                Ok(Some(User {
                    id: "u1".into(),
                    display_name: None,
                    email: None,
                    groups: vec![],
                    roles: vec![],
                    status: dbward_domain::entities::UserStatus::Suspended,
                    last_seen_at: None,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                }))
            }
            fn upsert(&self, _: &User) -> Result<(), AppError> {
                Ok(())
            }
            fn list(&self) -> Result<Vec<User>, AppError> {
                Ok(vec![])
            }
            fn suspend(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
                Ok(true)
            }
            fn activate(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
                Ok(true)
            }
            fn is_suspended(&self, _: &str) -> Result<bool, AppError> {
                Ok(true)
            }
            fn ensure_exists(&self, _: &str) -> Result<(), AppError> {
                Ok(())
            }
            fn count_active(&self) -> Result<u32, AppError> {
                Ok(5)
            }
        }
        let uc = UserManage {
            authorizer: Arc::new(AllowAll),
            user_repo: Arc::new(SuspendedUserRepo),
            group_repo: Arc::new(FakeGroupRepo),
            token_repo: Arc::new(FakeTokenRepo),
            uow: Arc::new(NoopUnitOfWork),
            clock: Arc::new(FakeClock),
            license: Arc::new(ZeroLicense),
            role_resolver: Arc::new(FakeRoleResolver),
            policy_repo: Arc::new(FakePolicyRepo),
            id_gen: Arc::new(FakeIdGen),
            token_gen: Arc::new(FakeTokenGen),
            audit_logger: Arc::new(crate::test_support::NoopAuditLogger),
            notifier: Arc::new(crate::test_support::NoopNotifier),
        };
        let result = uc.activate("u1", &admin_user(), &AuditContext::System);
        assert!(matches!(result, Err(AppError::PlanLimit(_))));
    }
}
