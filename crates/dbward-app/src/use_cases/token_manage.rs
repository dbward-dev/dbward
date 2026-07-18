use std::sync::Arc;

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use dbward_domain::auth::{AuthUser, Permission, ResourceContext};
use dbward_domain::entities::ScopeCeiling;
use dbward_domain::values::{DatabaseName, Environment};

use crate::error::AppError;
use crate::ports::*;

pub struct TokenManage {
    pub authorizer: Arc<dyn Authorizer>,
    pub token_repo: Arc<dyn TokenRepo>,
    pub user_repo: Arc<dyn UserRepo>,
    pub policy_repo: Arc<dyn PolicyRepo>,
    pub role_resolver: Arc<dyn RoleResolver>,
    pub license: Arc<dyn LicenseChecker>,
    pub uow: Arc<dyn UnitOfWork>,
    pub clock: Arc<dyn Clock>,
    pub id_gen: Arc<dyn IdGenerator>,
    pub token_gen: Arc<dyn TokenValueGenerator>,
    /// 0 = unlimited
    pub max_active_tokens_per_user: u32,
}

// --- Create ---

pub struct TokenCreateInput {
    pub subject_id: String,
    pub subject_type: String,
    pub name: Option<String>,
    pub scope_ceiling: Option<ScopeCeiling>,
    pub expires_at: Option<DateTime<Utc>>,
    /// Caller identity for audit (issued_by)
    pub issued_by: Option<String>,
    /// Must be empty — token.groups is abolished. Checked for defense in depth.
    pub groups: Vec<String>,
}

pub struct TokenCreateOutput {
    pub id: String,
    pub token: String, // plaintext, shown only once
    pub prefix: String,
    pub subject_id: String,
    pub scope_ceiling: Option<ScopeCeiling>,
    pub effective_roles: Vec<String>,
    pub effective_permissions: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

// --- List ---

pub struct TokenListOutput {
    pub tokens: Vec<dbward_domain::entities::Token>,
}

// --- Revoke ---

pub struct TokenRevokeInput {
    pub token_id: String,
}

pub struct TokenRevokeOutput {
    pub id: String,
    pub revoked_at: DateTime<Utc>,
}

// --- Reissue Initial Token ---

pub struct ReissueInitialOutput {
    pub new_token_id: String,
    pub plaintext: String,
    pub old_token_id: Option<String>,
}

impl TokenManage {
    pub fn create(
        &self,
        input: TokenCreateInput,
        user: &AuthUser,
        ctx: &dbward_domain::entities::AuditContext,
    ) -> Result<TokenCreateOutput, AppError> {
        // Validation 1: subject_id required
        if input.subject_id.is_empty() {
            return Err(AppError::Validation("subject_id is required".into()));
        }

        // Validation 2: subject_type
        if !matches!(input.subject_type.as_str(), "user" | "agent") {
            return Err(AppError::Validation(
                "subject_type must be 'user' or 'agent'".into(),
            ));
        }

        // Validation 8: groups field must be empty (token.groups abolished)
        if !input.groups.is_empty() {
            return Err(AppError::Validation(
                "groups field is not allowed; use Config [[auth.groups]] instead".into(),
            ));
        }

        let subject_type = match input.subject_type.as_str() {
            "agent" => dbward_domain::auth::SubjectType::Agent,
            _ => dbward_domain::auth::SubjectType::User,
        };

        // Authorization: permission depends on subject_type and ownership
        if subject_type == dbward_domain::auth::SubjectType::Agent {
            self.authorizer
                .authorize_global(user, Permission::TokenCreateAgent)
                .map_err(AppError::Forbidden)?;
        } else if input.subject_id == user.subject_id {
            self.authorizer
                .authorize_global(user, Permission::TokenCreate)
                .map_err(AppError::Forbidden)?;
        } else {
            // Hard 403: creating tokens for other users is never allowed
            return Err(AppError::Forbidden(
                crate::error::AuthzError::Forbidden {
                    permission: Permission::TokenCreate,
                    reason: "creating tokens for other users is not allowed; use reissue-initial-token instead".into(),
                },
            ));
        }

        // Token sprawl guard: check active token count per subject.
        // Note: count + insert are not in the same TX, but SQLite's single-writer
        // lock serializes all writes, preventing TOCTOU races in practice.
        if self.max_active_tokens_per_user > 0 {
            let count = self
                .token_repo
                .count_active_for_subject(&input.subject_id, subject_type)?;
            if count >= self.max_active_tokens_per_user {
                return Err(AppError::Validation(
                    "active token limit reached; revoke unused tokens first".into(),
                ));
            }
        }

        // Validation 3: Agent ceiling constraints
        if subject_type == dbward_domain::auth::SubjectType::Agent {
            match &input.scope_ceiling {
                None => {}                                    // allowed
                Some(c) if c.roles == ["agent-default"] => {} // allowed
                _ => {
                    return Err(AppError::Validation(
                        "agent tokens must have scope_ceiling=None or {roles:[\"agent-default\"]}"
                            .into(),
                    ));
                }
            }
        }

        // Auto-ceiling: if scope_ceiling is not specified for user tokens, default to resolved roles
        let mut input = input;

        // Validation 5: ceiling roles non-empty and exist
        if let Some(ref ceiling) = input.scope_ceiling {
            if ceiling.roles.is_empty() {
                return Err(AppError::Validation(
                    "scope_ceiling.roles must not be empty".into(),
                ));
            }
            let known_roles = self.policy_repo.list_roles()?;
            let known_names: Vec<&str> = known_roles.iter().map(|r| r.name.as_str()).collect();
            for role in &ceiling.roles {
                if !known_names.contains(&role.as_str())
                    && !matches!(
                        role.as_str(),
                        "admin" | "requester" | "approver" | "operator" | "agent-default"
                    )
                {
                    return Err(AppError::Validation(format!("unknown role: {}", role)));
                }
            }
        }

        // Validation: expires_at in future
        if let Some(ref exp) = input.expires_at
            && *exp <= self.clock.now()
        {
            return Err(AppError::Validation(
                "expires_at must be in the future".into(),
            ));
        }

        // Suspended user check (agents have no user record)
        if subject_type == dbward_domain::auth::SubjectType::User
            && self.user_repo.is_suspended(&input.subject_id)?
        {
            return Err(AppError::Conflict(
                "cannot create token for suspended user".into(),
            ));
        }

        // Validation 6: subject must resolve to at least one role
        let resolved_roles = self
            .role_resolver
            .resolve(&input.subject_id, subject_type, &[])
            .map_err(|e| AppError::Internal(format!("role resolution: {e}")))?;
        if resolved_roles.is_empty() {
            return Err(AppError::Validation(format!(
                "subject '{}' resolves to no roles; assign roles/groups or set default_role",
                input.subject_id
            )));
        }

        // Auto-ceiling: default to resolved roles when not explicitly provided
        if input.scope_ceiling.is_none() && subject_type == dbward_domain::auth::SubjectType::User {
            input.scope_ceiling = Some(dbward_domain::entities::ScopeCeiling {
                roles: resolved_roles.iter().map(|r| r.name.clone()).collect(),
            });
        }

        // Validation 7: resolved ∩ ceiling must be non-empty
        let effective_roles: Vec<String> = if let Some(ref ceiling) = input.scope_ceiling {
            let filtered: Vec<String> = resolved_roles
                .iter()
                .filter(|r| ceiling.roles.contains(&r.name))
                .map(|r| r.name.clone())
                .collect();
            if filtered.is_empty() {
                return Err(AppError::Validation(format!(
                    "scope_ceiling {:?} has no overlap with resolved roles {:?}; token would always fail",
                    ceiling.roles,
                    resolved_roles.iter().map(|r| &r.name).collect::<Vec<_>>()
                )));
            }
            filtered
        } else {
            resolved_roles.iter().map(|r| r.name.clone()).collect()
        };

        // Compute effective permissions
        let effective_permissions: Vec<String> = {
            let matching: Vec<_> = resolved_roles
                .iter()
                .filter(|r| effective_roles.contains(&r.name))
                .collect();
            let mut perms = std::collections::HashSet::new();
            for r in &matching {
                for p in &r.permissions {
                    perms.insert(p.0.as_str().to_string());
                }
            }
            let mut sorted: Vec<String> = perms.into_iter().collect();
            sorted.sort();
            sorted
        };

        // Generate token
        let raw = self.token_gen.generate_token_value();
        let prefix = dbward_domain::entities::Token::extract_prefix(&raw);
        let hash = hex::encode(Sha256::digest(raw.as_bytes()));

        let now = self.clock.now();
        let id = self.id_gen.generate();

        let token = dbward_domain::entities::Token {
            id: id.clone(),
            subject_id: input.subject_id.clone(),
            subject_type,
            token_hash: hash,
            token_prefix: prefix.clone(),
            scope_ceiling: input.scope_ceiling.clone(),
            name: input.name,
            status: dbward_domain::entities::TokenStatus::Active,
            provisioning_kind: None,
            expires_at: input.expires_at,
            revoked_at: None,
            created_at: now,
        };

        // Build audit metadata
        let metadata = serde_json::json!({
            "issued_by": input.issued_by.as_deref().unwrap_or(&user.subject_id),
            "issued_for": input.subject_id,
            "scope_ceiling": input.scope_ceiling,
        });

        let mut audit_event = dbward_domain::entities::AuditEvent::simple(
            "token.created",
            "token",
            &user.subject_id,
            Some(&id),
            self.clock.now(),
            ctx,
        );
        audit_event.metadata_json = metadata.to_string();
        self.uow.execute(Box::new(move |tx| {
            tx.create_token(&token)?;
            tx.record(&audit_event)?;
            Ok(())
        }))?;

        Ok(TokenCreateOutput {
            id,
            token: raw,
            prefix,
            subject_id: input.subject_id,
            scope_ceiling: input.scope_ceiling,
            effective_roles,
            effective_permissions,
            expires_at: input.expires_at,
        })
    }

    pub fn list(&self, user: &AuthUser) -> Result<TokenListOutput, AppError> {
        self.authorizer
            .authorize_global(user, Permission::TokenList)
            .map_err(AppError::Forbidden)?;
        let tokens = self.token_repo.list()?;
        // Exclude bootstrap tokens from user-visible list
        let visible: Vec<_> = tokens
            .into_iter()
            .filter(|t| {
                t.provisioning_kind != Some(dbward_domain::entities::ProvisioningKind::Bootstrap)
            })
            .collect();
        Ok(TokenListOutput { tokens: visible })
    }

    pub fn revoke(
        &self,
        input: TokenRevokeInput,
        user: &AuthUser,
        ctx: &dbward_domain::entities::AuditContext,
    ) -> Result<TokenRevokeOutput, AppError> {
        let token = self
            .token_repo
            .get(&input.token_id)?
            .ok_or_else(|| AppError::NotFound("token not found".into()))?;

        // Bootstrap tokens are not accessible via API
        if token.provisioning_kind == Some(dbward_domain::entities::ProvisioningKind::Bootstrap) {
            return Err(AppError::NotFound("token not found".into()));
        }

        // Authorize revoke: uses ResourceContext::Token for ownership check
        self.authorizer
            .authorize_scoped(
                user,
                Permission::TokenRevoke,
                // SAFETY: "*" is always valid for DatabaseName/Environment
                &DatabaseName::wildcard(),
                &Environment::wildcard(),
                &ResourceContext::Token {
                    owner_id: token.subject_id.clone(),
                },
            )
            .map_err(AppError::Forbidden)?;

        let now = self.clock.now();
        let token_id = input.token_id.clone();
        let actor_id = user.subject_id.clone();
        let audit_event = dbward_domain::entities::AuditEvent::simple(
            "token.revoked",
            "token",
            &actor_id,
            Some(&token_id),
            now,
            ctx,
        );
        self.uow.execute(Box::new(move |tx| {
            tx.revoke_token(&token_id, now)?;
            tx.record(&audit_event)?;
            Ok(())
        }))?;

        Ok(TokenRevokeOutput {
            id: input.token_id,
            revoked_at: now,
        })
    }

    /// Reissue the initial token for a user. Revokes the existing initial token (if any)
    /// and creates a new one. Returns the plaintext for delivery.
    pub fn reissue_initial(
        &self,
        target_user_id: &str,
        user: &AuthUser,
    ) -> Result<ReissueInitialOutput, AppError> {
        // Authorization
        self.authorizer
            .authorize_global(user, Permission::TokenReissue)
            .map_err(AppError::Forbidden)?;

        // User existence check
        if self.user_repo.get(target_user_id)?.is_none() {
            return Err(AppError::NotFound(format!(
                "user '{}' not found",
                target_user_id
            )));
        }

        // User state checks
        if self.user_repo.is_deleted(target_user_id)? {
            return Err(AppError::Gone("user has been deleted".into()));
        }
        if self.user_repo.is_suspended(target_user_id)? {
            return Err(AppError::Conflict(
                "cannot reissue token for suspended user".into(),
            ));
        }

        // Target must resolve to at least one role
        let resolved_roles = self
            .role_resolver
            .resolve(target_user_id, dbward_domain::auth::SubjectType::User, &[])
            .map_err(|e| AppError::Internal(format!("role resolution: {e}")))?;
        if resolved_roles.is_empty() {
            return Err(AppError::Validation(
                "user has no resolved roles; assign roles first".into(),
            ));
        }

        // Find existing active initial token
        let old_token = self.token_repo.find_active_initial(target_user_id)?;
        let old_token_id = old_token.as_ref().map(|t| t.id.clone());

        let now = self.clock.now();

        // Create new initial token
        let scope_ceiling = dbward_domain::entities::ScopeCeiling {
            roles: resolved_roles.iter().map(|r| r.name.clone()).collect(),
        };

        let raw = self.token_gen.generate_token_value();
        let prefix = dbward_domain::entities::Token::extract_prefix(&raw);
        let hash = hex::encode(Sha256::digest(raw.as_bytes()));
        let id = self.id_gen.generate();

        let new_token = dbward_domain::entities::Token {
            id: id.clone(),
            subject_id: target_user_id.to_string(),
            subject_type: dbward_domain::auth::SubjectType::User,
            token_hash: hash,
            token_prefix: prefix,
            scope_ceiling: Some(scope_ceiling.clone()),
            name: Some("initial".to_string()),
            status: dbward_domain::entities::TokenStatus::Active,
            provisioning_kind: Some(dbward_domain::entities::ProvisioningKind::Initial),
            expires_at: None,
            revoked_at: None,
            created_at: now,
        };

        // Atomic: revoke old + create new in a single transaction
        let revoke_id = old_token_id.clone();
        let actor_id = user.subject_id.clone();
        self.uow.execute(Box::new(move |tx| {
            if let Some(ref old_id) = revoke_id {
                tx.revoke_token(old_id, now)?;
                let revoke_event = dbward_domain::entities::AuditEvent::simple(
                    "token.revoked",
                    "token",
                    &actor_id,
                    Some(old_id),
                    now,
                    &dbward_domain::entities::AuditContext::System,
                );
                tx.record(&revoke_event)?;
            }
            tx.create_token(&new_token)?;
            Ok(())
        }))?;

        Ok(ReissueInitialOutput {
            new_token_id: id,
            plaintext: raw,
            old_token_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AuthzError;
    use crate::test_support::NoopUnitOfWork;
    use dbward_domain::auth::{
        OwnershipScope, Permission, ResolvedRole, RoleDefinition, SubjectType,
    };
    use dbward_domain::entities::Token;

    struct AllowAll;
    impl Authorizer for AllowAll {
        fn authorize_scoped(
            &self,
            _: &dbward_domain::auth::AuthUser,
            _: Permission,
            _: &dbward_domain::values::DatabaseName,
            _: &dbward_domain::values::Environment,
            _: &dbward_domain::auth::ResourceContext,
        ) -> Result<(), AuthzError> {
            Ok(())
        }
        fn authorize_global(
            &self,
            _: &dbward_domain::auth::AuthUser,
            _: Permission,
        ) -> Result<(), AuthzError> {
            Ok(())
        }
        fn authorize_approval(
            &self,
            _: &dbward_domain::auth::AuthUser,
            _: &dbward_domain::values::DatabaseName,
            _: &dbward_domain::values::Environment,
            _: &dbward_domain::auth::ResourceContext,
        ) -> Result<(), AuthzError> {
            Ok(())
        }
    }
    struct FakeClock;
    impl Clock for FakeClock {
        fn now(&self) -> chrono::DateTime<chrono::Utc> {
            chrono::Utc::now()
        }
    }
    struct FakeTokenGen;
    impl TokenValueGenerator for FakeTokenGen {
        fn generate_token_value(&self) -> String {
            "dbw_a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4".into()
        }
    }
    struct FakeIdGen;
    impl IdGenerator for FakeIdGen {
        fn generate(&self) -> String {
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4".into()
        }
    }
    struct FakeTokenRepo {
        count: u32,
    }
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
        fn revoke(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn revoke_all_for_user(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<u32, AppError> {
            Ok(0)
        }
        fn count_active(&self) -> Result<u32, AppError> {
            Ok(self.count)
        }
        fn purge_revoked(&self, _: &str) -> Result<u32, AppError> {
            Ok(0)
        }
        fn find_active_initial(&self, _: &str) -> Result<Option<Token>, AppError> {
            Ok(None)
        }
        fn count_active_for_subject(
            &self,
            _: &str,
            _: dbward_domain::auth::SubjectType,
        ) -> Result<u32, AppError> {
            Ok(0)
        }
    }
    struct FakeUserRepo;
    impl UserRepo for FakeUserRepo {
        fn get(&self, _: &str) -> Result<Option<dbward_domain::entities::User>, AppError> {
            Ok(None)
        }
        fn upsert(&self, _: &dbward_domain::entities::User) -> Result<(), AppError> {
            Ok(())
        }
        fn list(&self) -> Result<Vec<dbward_domain::entities::User>, AppError> {
            Ok(vec![])
        }
        fn suspend(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn activate(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn is_suspended(&self, _: &str) -> Result<bool, AppError> {
            Ok(false)
        }
        fn ensure_exists(&self, _: &str) -> Result<(), AppError> {
            Ok(())
        }

        fn count_active(&self) -> Result<u32, AppError> {
            Ok(1)
        }
        fn get_roles(&self, _: &str) -> Result<Vec<String>, AppError> {
            Ok(vec![])
        }
        fn is_deleted(&self, _: &str) -> Result<bool, AppError> {
            Ok(false)
        }
        fn count_admins(&self) -> Result<u32, AppError> {
            Ok(1)
        }
    }
    struct FakePolicyRepo {
        roles: Vec<RoleDefinition>,
    }
    impl PolicyRepo for FakePolicyRepo {
        fn create_workflow(&self, _: &dbward_domain::policies::Workflow) -> Result<(), AppError> {
            Ok(())
        }
        fn get_workflow(
            &self,
            _: &str,
        ) -> Result<Option<dbward_domain::policies::Workflow>, AppError> {
            Ok(None)
        }
        fn list_workflows(&self) -> Result<Vec<dbward_domain::policies::Workflow>, AppError> {
            Ok(vec![])
        }
        fn delete_workflow(&self, _: &str) -> Result<bool, AppError> {
            Ok(true)
        }
        fn count_workflows(&self) -> Result<u32, AppError> {
            Ok(0)
        }
        fn create_execution_policy(
            &self,
            _: &dbward_domain::policies::ExecutionPolicy,
        ) -> Result<(), AppError> {
            Ok(())
        }
        fn get_execution_policy(
            &self,
            _: &str,
        ) -> Result<Option<dbward_domain::policies::ExecutionPolicy>, AppError> {
            Ok(None)
        }
        fn list_execution_policies(
            &self,
        ) -> Result<Vec<dbward_domain::policies::ExecutionPolicy>, AppError> {
            Ok(vec![])
        }
        fn delete_execution_policy(&self, _: &str) -> Result<bool, AppError> {
            Ok(true)
        }
        fn find_result_policy(
            &self,
            _: &dbward_domain::values::DatabaseName,
            _: &dbward_domain::values::Environment,
        ) -> Result<Option<dbward_domain::policies::ResultPolicy>, AppError> {
            Ok(None)
        }

        fn create_result_policy(
            &self,
            _: &dbward_domain::policies::ResultPolicy,
        ) -> Result<(), AppError> {
            Ok(())
        }
        fn get_result_policy(
            &self,
            _: &str,
        ) -> Result<Option<dbward_domain::policies::ResultPolicy>, AppError> {
            Ok(None)
        }
        fn list_result_policies(
            &self,
        ) -> Result<Vec<dbward_domain::policies::ResultPolicy>, AppError> {
            Ok(vec![])
        }
        fn update_result_policy(
            &self,
            _: &dbward_domain::policies::ResultPolicy,
        ) -> Result<bool, AppError> {
            Ok(false)
        }
        fn delete_result_policy(&self, _: &str) -> Result<bool, AppError> {
            Ok(false)
        }
        fn create_notification_policy(
            &self,
            _: &dbward_domain::policies::NotificationPolicy,
        ) -> Result<(), AppError> {
            Ok(())
        }
        fn get_notification_policy(
            &self,
            _: &str,
        ) -> Result<Option<dbward_domain::policies::NotificationPolicy>, AppError> {
            Ok(None)
        }
        fn list_notification_policies(
            &self,
        ) -> Result<Vec<dbward_domain::policies::NotificationPolicy>, AppError> {
            Ok(vec![])
        }
        fn update_notification_policy(
            &self,
            _: &dbward_domain::policies::NotificationPolicy,
        ) -> Result<bool, AppError> {
            Ok(false)
        }
        fn delete_notification_policy(&self, _: &str) -> Result<bool, AppError> {
            Ok(false)
        }
        fn create_role(&self, _: &RoleDefinition) -> Result<(), AppError> {
            Ok(())
        }
        fn list_roles(&self) -> Result<Vec<RoleDefinition>, AppError> {
            Ok(self.roles.clone())
        }
        fn get_roles_by_names(&self, names: &[String]) -> Result<Vec<RoleDefinition>, AppError> {
            Ok(self
                .roles
                .iter()
                .filter(|r| names.contains(&r.name))
                .cloned()
                .collect())
        }
        fn delete_role(&self, _: &str) -> Result<bool, AppError> {
            Ok(true)
        }
        fn count_roles(&self) -> Result<u32, AppError> {
            Ok(0)
        }
    }
    struct FakeLicense;
    impl LicenseChecker for FakeLicense {
        fn max_users(&self) -> u32 {
            20
        }
        fn max_databases(&self) -> u32 {
            u32::MAX
        }
        fn max_workflows(&self) -> u32 {
            5
        }
        fn max_webhooks(&self) -> u32 {
            3
        }
        fn max_roles(&self) -> u32 {
            8
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
        fn check_expiry(&self, _now: chrono::DateTime<chrono::Utc>) {}
    }

    struct FakeRoleResolver;
    impl RoleResolver for FakeRoleResolver {
        fn resolve(
            &self,
            subject_id: &str,
            subject_type: SubjectType,
            _groups: &[String],
        ) -> Result<Vec<ResolvedRole>, crate::error::AuthError> {
            if subject_type == SubjectType::Agent {
                return Ok(vec![ResolvedRole {
                    name: "agent-default".into(),
                    permissions: std::collections::HashMap::new(),
                    databases: vec![],
                    environments: vec![],
                }]);
            }
            if subject_id == "no-roles" {
                return Ok(vec![]);
            }
            Ok(vec![
                ResolvedRole {
                    name: "admin".into(),
                    permissions: [(Permission::All, OwnershipScope::Any)]
                        .into_iter()
                        .collect(),
                    databases: vec![],
                    environments: vec![],
                },
                ResolvedRole {
                    name: "requester".into(),
                    permissions: [(Permission::RequestDml, OwnershipScope::Own)]
                        .into_iter()
                        .collect(),
                    databases: vec![],
                    environments: vec![],
                },
            ])
        }
    }

    fn make_user() -> dbward_domain::auth::AuthUser {
        dbward_domain::auth::AuthUser {
            subject_id: "alice".into(),
            subject_type: SubjectType::User,
            roles: vec![],
            groups: vec![],
            token_id: None,
        }
    }

    fn make_uc(roles: Vec<RoleDefinition>) -> TokenManage {
        TokenManage {
            authorizer: Arc::new(AllowAll),
            token_repo: Arc::new(FakeTokenRepo { count: 0 }),
            user_repo: Arc::new(FakeUserRepo),
            policy_repo: Arc::new(FakePolicyRepo { roles }),
            role_resolver: Arc::new(FakeRoleResolver),
            license: Arc::new(FakeLicense),
            uow: Arc::new(NoopUnitOfWork),
            clock: Arc::new(FakeClock),
            id_gen: Arc::new(FakeIdGen),
            token_gen: Arc::new(FakeTokenGen),
            max_active_tokens_per_user: 5,
        }
    }

    #[test]
    fn create_self_user_token_auto_ceiling_from_resolve() {
        let uc = make_uc(vec![]);
        let result = uc.create(
            TokenCreateInput {
                subject_id: "alice".into(), // same as caller
                subject_type: "user".into(),
                name: None,
                scope_ceiling: None,
                expires_at: None,
                issued_by: None,
                groups: vec![],
            },
            &make_user(),
            &dbward_domain::entities::AuditContext::System,
        );
        let output = result.unwrap();
        assert!(!output.token.is_empty());
    }

    #[test]
    fn create_other_user_token_is_forbidden() {
        let uc = make_uc(vec![]);
        let result = uc.create(
            TokenCreateInput {
                subject_id: "bob".into(), // different from caller "alice"
                subject_type: "user".into(),
                name: None,
                scope_ceiling: None,
                expires_at: None,
                issued_by: None,
                groups: vec![],
            },
            &make_user(),
            &dbward_domain::entities::AuditContext::System,
        );
        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    #[test]
    fn create_rejects_empty_ceiling_roles() {
        let uc = make_uc(vec![]);
        let result = uc.create(
            TokenCreateInput {
                subject_id: "alice".into(),
                subject_type: "user".into(),
                name: None,
                scope_ceiling: Some(ScopeCeiling { roles: vec![] }),
                expires_at: None,
                issued_by: None,
                groups: vec![],
            },
            &make_user(),
            &dbward_domain::entities::AuditContext::System,
        );
        assert!(
            matches!(result, Err(AppError::Validation(ref msg)) if msg.contains("must not be empty"))
        );
    }

    #[test]
    fn create_rejects_no_roles_resolved() {
        let uc = make_uc(vec![]);
        // Use a caller whose subject_id matches the target to pass authz,
        // but the resolver returns no roles for "no-roles"
        let no_roles_user = dbward_domain::auth::AuthUser {
            subject_id: "no-roles".into(),
            subject_type: SubjectType::User,
            roles: vec![],
            groups: vec![],
            token_id: None,
        };
        let result = uc.create(
            TokenCreateInput {
                subject_id: "no-roles".into(),
                subject_type: "user".into(),
                name: None,
                scope_ceiling: Some(ScopeCeiling {
                    roles: vec!["admin".into()],
                }),
                expires_at: None,
                issued_by: None,
                groups: vec![],
            },
            &no_roles_user,
            &dbward_domain::entities::AuditContext::System,
        );
        assert!(
            matches!(result, Err(AppError::Validation(ref msg)) if msg.contains("resolves to no roles"))
        );
    }

    #[test]
    fn create_rejects_no_overlap() {
        let uc = make_uc(vec![]);
        let result = uc.create(
            TokenCreateInput {
                subject_id: "alice".into(),
                subject_type: "user".into(),
                name: None,
                scope_ceiling: Some(ScopeCeiling {
                    roles: vec!["nonexistent".into()],
                }),
                expires_at: None,
                issued_by: None,
                groups: vec![],
            },
            &make_user(),
            &dbward_domain::entities::AuditContext::System,
        );
        // Should fail on validation 5 (unknown role) before reaching validation 7
        assert!(matches!(result, Err(AppError::Validation(_))));
    }

    #[test]
    fn create_accepts_valid_user_token() {
        let uc = make_uc(vec![]);
        let result = uc.create(
            TokenCreateInput {
                subject_id: "alice".into(),
                subject_type: "user".into(),
                name: None,
                scope_ceiling: Some(ScopeCeiling {
                    roles: vec!["admin".into()],
                }),
                expires_at: None,
                issued_by: None,
                groups: vec![],
            },
            &make_user(),
            &dbward_domain::entities::AuditContext::System,
        );
        assert!(result.is_ok());
        let out = result.unwrap();
        assert_eq!(out.effective_roles, vec!["admin"]);
    }

    #[test]
    fn create_accepts_agent_with_no_ceiling() {
        let uc = make_uc(vec![]);
        let result = uc.create(
            TokenCreateInput {
                subject_id: "my-agent".into(),
                subject_type: "agent".into(),
                name: None,
                scope_ceiling: None,
                expires_at: None,
                issued_by: None,
                groups: vec![],
            },
            &make_user(),
            &dbward_domain::entities::AuditContext::System,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn create_rejects_agent_with_admin_ceiling() {
        let uc = make_uc(vec![]);
        let result = uc.create(
            TokenCreateInput {
                subject_id: "my-agent".into(),
                subject_type: "agent".into(),
                name: None,
                scope_ceiling: Some(ScopeCeiling {
                    roles: vec!["admin".into()],
                }),
                expires_at: None,
                issued_by: None,
                groups: vec![],
            },
            &make_user(),
            &dbward_domain::entities::AuditContext::System,
        );
        assert!(matches!(result, Err(AppError::Validation(ref msg)) if msg.contains("agent")));
    }

    #[test]
    fn create_rejects_ceiling_with_no_overlap_validation7() {
        // Validation 7: ceiling roles exist (builtin "approver") but resolver returns
        // only ["admin","requester"] → intersection is empty
        let uc = make_uc(vec![]);
        let result = uc.create(
            TokenCreateInput {
                subject_id: "alice".into(),
                subject_type: "user".into(),
                name: None,
                scope_ceiling: Some(ScopeCeiling {
                    roles: vec!["approver".into()],
                }),
                expires_at: None,
                issued_by: None,
                groups: vec![],
            },
            &make_user(),
            &dbward_domain::entities::AuditContext::System,
        );
        assert!(matches!(result, Err(AppError::Validation(ref msg)) if msg.contains("no overlap")));
    }

    // --- Authorization path tests (verify correct permission is checked) ---

    /// Authorizer that only allows a specific permission.
    struct AllowOnly(Permission);
    impl Authorizer for AllowOnly {
        fn authorize_scoped(
            &self,
            _: &dbward_domain::auth::AuthUser,
            _: Permission,
            _: &dbward_domain::values::DatabaseName,
            _: &dbward_domain::values::Environment,
            _: &dbward_domain::auth::ResourceContext,
        ) -> Result<(), AuthzError> {
            Ok(())
        }
        fn authorize_global(
            &self,
            _: &dbward_domain::auth::AuthUser,
            perm: Permission,
        ) -> Result<(), AuthzError> {
            if perm == self.0 || perm == Permission::All {
                Ok(())
            } else {
                Err(AuthzError::Forbidden {
                    permission: perm,
                    reason: format!("only {:?} is allowed", self.0),
                })
            }
        }
        fn authorize_approval(
            &self,
            _: &dbward_domain::auth::AuthUser,
            _: &dbward_domain::values::DatabaseName,
            _: &dbward_domain::values::Environment,
            _: &dbward_domain::auth::ResourceContext,
        ) -> Result<(), AuthzError> {
            Ok(())
        }
    }

    fn make_uc_with_authorizer(auth: Arc<dyn Authorizer>) -> TokenManage {
        TokenManage {
            authorizer: auth,
            token_repo: Arc::new(FakeTokenRepo { count: 0 }),
            user_repo: Arc::new(FakeUserRepo),
            policy_repo: Arc::new(FakePolicyRepo { roles: vec![] }),
            role_resolver: Arc::new(FakeRoleResolver),
            license: Arc::new(FakeLicense),
            uow: Arc::new(NoopUnitOfWork),
            clock: Arc::new(FakeClock),
            id_gen: Arc::new(FakeIdGen),
            token_gen: Arc::new(FakeTokenGen),
            max_active_tokens_per_user: 5,
        }
    }

    #[test]
    fn create_self_user_requires_token_create_own() {
        let uc = make_uc_with_authorizer(Arc::new(AllowOnly(Permission::TokenCreate)));
        let result = uc.create(
            TokenCreateInput {
                subject_id: "alice".into(),
                subject_type: "user".into(),
                name: None,
                scope_ceiling: None,
                expires_at: None,
                issued_by: None,
                groups: vec![],
            },
            &make_user(),
            &dbward_domain::entities::AuditContext::System,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn create_self_user_denied_without_token_create_own() {
        let uc = make_uc_with_authorizer(Arc::new(AllowOnly(Permission::TokenCreateAgent)));
        let result = uc.create(
            TokenCreateInput {
                subject_id: "alice".into(),
                subject_type: "user".into(),
                name: None,
                scope_ceiling: None,
                expires_at: None,
                issued_by: None,
                groups: vec![],
            },
            &make_user(),
            &dbward_domain::entities::AuditContext::System,
        );
        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    #[test]
    fn create_agent_requires_token_manage() {
        let uc = make_uc_with_authorizer(Arc::new(AllowOnly(Permission::TokenCreateAgent)));
        let result = uc.create(
            TokenCreateInput {
                subject_id: "my-agent".into(),
                subject_type: "agent".into(),
                name: None,
                scope_ceiling: None,
                expires_at: None,
                issued_by: None,
                groups: vec![],
            },
            &make_user(),
            &dbward_domain::entities::AuditContext::System,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn create_agent_denied_with_only_token_create_own() {
        let uc = make_uc_with_authorizer(Arc::new(AllowOnly(Permission::TokenCreate)));
        let result = uc.create(
            TokenCreateInput {
                subject_id: "my-agent".into(),
                subject_type: "agent".into(),
                name: None,
                scope_ceiling: None,
                expires_at: None,
                issued_by: None,
                groups: vec![],
            },
            &make_user(),
            &dbward_domain::entities::AuditContext::System,
        );
        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    #[test]
    fn list_requires_token_manage() {
        let uc = make_uc_with_authorizer(Arc::new(AllowOnly(Permission::TokenList)));
        assert!(uc.list(&make_user()).is_ok());
    }

    #[test]
    fn list_denied_without_token_manage() {
        let uc = make_uc_with_authorizer(Arc::new(AllowOnly(Permission::TokenCreate)));
        assert!(matches!(uc.list(&make_user()), Err(AppError::Forbidden(_))));
    }

    // --- Bootstrap token isolation tests ---

    struct FakeTokenRepoWithBootstrap;
    impl TokenRepo for FakeTokenRepoWithBootstrap {
        fn create(&self, _: &Token) -> Result<(), AppError> {
            Ok(())
        }
        fn verify(&self, _: &str, _: &str) -> Result<Option<Token>, AppError> {
            Ok(None)
        }
        fn list(&self) -> Result<Vec<Token>, AppError> {
            Ok(vec![])
        }
        fn get(&self, _id: &str) -> Result<Option<Token>, AppError> {
            Ok(Some(Token {
                id: "bootstrap-tok".into(),
                subject_id: "admin".into(),
                subject_type: dbward_domain::auth::SubjectType::User,
                token_hash: "hash".into(),
                token_prefix: "prefix".into(),
                scope_ceiling: None,
                name: Some("bootstrap-admin".into()),
                status: dbward_domain::entities::TokenStatus::Active,
                provisioning_kind: Some(dbward_domain::entities::ProvisioningKind::Bootstrap),
                expires_at: None,
                created_at: chrono::Utc::now(),
                revoked_at: None,
            }))
        }
        fn revoke(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn revoke_all_for_user(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<u32, AppError> {
            Ok(0)
        }
        fn count_active(&self) -> Result<u32, AppError> {
            Ok(0)
        }
        fn purge_revoked(&self, _: &str) -> Result<u32, AppError> {
            Ok(0)
        }
        fn find_active_initial(&self, _: &str) -> Result<Option<Token>, AppError> {
            Ok(None)
        }
        fn count_active_for_subject(
            &self,
            _: &str,
            _: dbward_domain::auth::SubjectType,
        ) -> Result<u32, AppError> {
            Ok(0)
        }
    }

    #[test]
    fn revoke_bootstrap_token_returns_not_found() {
        let uc = TokenManage {
            authorizer: Arc::new(AllowAll),
            token_repo: Arc::new(FakeTokenRepoWithBootstrap),
            user_repo: Arc::new(FakeUserRepo),
            policy_repo: Arc::new(FakePolicyRepo { roles: vec![] }),
            role_resolver: Arc::new(FakeRoleResolver),
            license: Arc::new(FakeLicense),
            uow: Arc::new(NoopUnitOfWork),
            clock: Arc::new(FakeClock),
            id_gen: Arc::new(FakeIdGen),
            token_gen: Arc::new(FakeTokenGen),
            max_active_tokens_per_user: 5,
        };
        let result = uc.revoke(
            TokenRevokeInput {
                token_id: "bootstrap-tok".into(),
            },
            &make_user(),
            &dbward_domain::entities::AuditContext::System,
        );
        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    // --- Sprawl guard tests ---

    struct FakeTokenRepoAtLimit;
    impl TokenRepo for FakeTokenRepoAtLimit {
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
        fn revoke(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn revoke_all_for_user(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<u32, AppError> {
            Ok(0)
        }
        fn count_active(&self) -> Result<u32, AppError> {
            Ok(5)
        }
        fn purge_revoked(&self, _: &str) -> Result<u32, AppError> {
            Ok(0)
        }
        fn find_active_initial(&self, _: &str) -> Result<Option<Token>, AppError> {
            Ok(None)
        }
        fn count_active_for_subject(
            &self,
            _: &str,
            _: dbward_domain::auth::SubjectType,
        ) -> Result<u32, AppError> {
            Ok(5) // at limit
        }
    }

    #[test]
    fn create_rejects_at_token_limit() {
        let uc = TokenManage {
            authorizer: Arc::new(AllowAll),
            token_repo: Arc::new(FakeTokenRepoAtLimit),
            user_repo: Arc::new(FakeUserRepo),
            policy_repo: Arc::new(FakePolicyRepo { roles: vec![] }),
            role_resolver: Arc::new(FakeRoleResolver),
            license: Arc::new(FakeLicense),
            uow: Arc::new(NoopUnitOfWork),
            clock: Arc::new(FakeClock),
            id_gen: Arc::new(FakeIdGen),
            token_gen: Arc::new(FakeTokenGen),
            max_active_tokens_per_user: 5,
        };
        let result = uc.create(
            TokenCreateInput {
                subject_id: "alice".into(),
                subject_type: "user".into(),
                name: None,
                scope_ceiling: None,
                expires_at: None,
                issued_by: None,
                groups: vec![],
            },
            &make_user(),
            &dbward_domain::entities::AuditContext::System,
        );
        assert!(
            matches!(result, Err(AppError::Validation(ref msg)) if msg.contains("token limit"))
        );
    }

    #[test]
    fn create_allows_when_limit_is_zero_unlimited() {
        let uc = TokenManage {
            authorizer: Arc::new(AllowAll),
            token_repo: Arc::new(FakeTokenRepoAtLimit), // returns count=5
            user_repo: Arc::new(FakeUserRepo),
            policy_repo: Arc::new(FakePolicyRepo { roles: vec![] }),
            role_resolver: Arc::new(FakeRoleResolver),
            license: Arc::new(FakeLicense),
            uow: Arc::new(NoopUnitOfWork),
            clock: Arc::new(FakeClock),
            id_gen: Arc::new(FakeIdGen),
            token_gen: Arc::new(FakeTokenGen),
            max_active_tokens_per_user: 0, // unlimited
        };
        let result = uc.create(
            TokenCreateInput {
                subject_id: "alice".into(),
                subject_type: "user".into(),
                name: None,
                scope_ceiling: None,
                expires_at: None,
                issued_by: None,
                groups: vec![],
            },
            &make_user(),
            &dbward_domain::entities::AuditContext::System,
        );
        assert!(result.is_ok());
    }
}
