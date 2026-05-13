use std::sync::Arc;

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use dbward_domain::auth::{AuthUser, Permission};

use crate::error::AppError;
use crate::ports::*;

pub struct TokenManage {
    pub authorizer: Arc<dyn Authorizer>,
    pub token_repo: Arc<dyn TokenRepo>,
    pub user_repo: Arc<dyn UserRepo>,
    pub policy_repo: Arc<dyn PolicyRepo>,
    pub license: Arc<dyn LicenseChecker>,
    pub audit: Arc<dyn AuditLogger>,
    pub clock: Arc<dyn Clock>,
    pub id_gen: Arc<dyn IdGenerator>,
    pub token_gen: Arc<dyn TokenValueGenerator>,
}

// --- Create ---

pub struct TokenCreateInput {
    pub subject_id: String,
    pub subject_type: String,
    pub name: Option<String>,
    pub roles: Vec<String>,
    pub groups: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

pub struct TokenCreateOutput {
    pub id: String,
    pub token: String, // plaintext, shown only once
    pub prefix: String,
    pub subject_id: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub permissions: Vec<String>,
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

impl TokenManage {
    pub fn create(
        &self,
        input: TokenCreateInput,
        user: &AuthUser,
    ) -> Result<TokenCreateOutput, AppError> {
        self.authorizer
            .authorize_global(user, Permission::TokenManage)
            .map_err(AppError::Forbidden)?;

        // Validation
        if input.subject_id.is_empty() {
            return Err(AppError::Validation("subject_id is required".into()));
        }
        if !matches!(input.subject_type.as_str(), "user" | "agent") {
            return Err(AppError::Validation(
                "subject_type must be 'user' or 'agent'".into(),
            ));
        }
        if let Some(ref exp) = input.expires_at {
            if *exp <= self.clock.now() {
                return Err(AppError::Validation(
                    "expires_at must be in the future".into(),
                ));
            }
        }

        // Suspended user check
        if self.user_repo.is_suspended(&input.subject_id)? {
            return Err(AppError::Conflict(
                "cannot create token for suspended user".into(),
            ));
        }

        // Validate roles exist
        if !input.roles.is_empty() {
            let known_roles = self.policy_repo.list_roles()?;
            let known_names: Vec<&str> = known_roles.iter().map(|r| r.name.as_str()).collect();
            for role in &input.roles {
                if !known_names.contains(&role.as_str())
                    && !matches!(role.as_str(), "admin" | "agent-default")
                {
                    return Err(AppError::Validation(format!("unknown role: {}", role)));
                }
            }
        }

        // Free tier limit
        let count = self.token_repo.count_active()?;
        if count >= self.license.max_tokens() {
            return Err(AppError::PlanLimit("token limit reached".into()));
        }

        // Generate token
        let raw = format!("dbw_{}", self.id_gen.generate().replace('-', ""));
        let prefix = if raw.len() >= 12 { raw[4..12].to_string() } else { raw.chars().take(8).collect() };
        let hash = hex::encode(Sha256::digest(raw.as_bytes()));

        let now = self.clock.now();
        let id = self.id_gen.generate();

        let token = dbward_domain::entities::Token {
            id: id.clone(),
            subject_id: input.subject_id.clone(),
            subject_type: match input.subject_type.as_str() {
                "agent" => dbward_domain::auth::SubjectType::Agent,
                _ => dbward_domain::auth::SubjectType::User,
            },
            token_hash: hash,
            token_prefix: prefix.clone(),
            name: input.name,
            roles: input.roles,
            groups: input.groups,
            status: dbward_domain::entities::TokenStatus::Active,
            expires_at: input.expires_at,
            revoked_at: None,
            created_at: now,
        };
        self.token_repo.create(&token)?;

        // Audit
        self.audit
            .record(&dbward_domain::entities::AuditEvent::simple(
                "token_created",
                "token",
                &user.subject_id,
                Some(&id),
                self.clock.now(),
            ))?;

        // Resolve permissions from assigned roles
        let permissions: Vec<String> = if !token.roles.is_empty() {
            self.policy_repo
                .get_roles_by_names(&token.roles)?
                .iter()
                .flat_map(|r| r.permissions.iter())
                .map(|p| p.as_str().to_string())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect()
        } else {
            vec![]
        };

        Ok(TokenCreateOutput {
            id,
            token: raw,
            prefix,
            subject_id: input.subject_id,
            expires_at: input.expires_at,
            permissions,
        })
    }

    pub fn list(&self, user: &AuthUser) -> Result<TokenListOutput, AppError> {
        self.authorizer
            .authorize_global(user, Permission::TokenManage)
            .map_err(AppError::Forbidden)?;
        let tokens = self.token_repo.list()?;
        Ok(TokenListOutput { tokens })
    }

    pub fn revoke(
        &self,
        input: TokenRevokeInput,
        user: &AuthUser,
    ) -> Result<TokenRevokeOutput, AppError> {
        let token = self
            .token_repo
            .get(&input.token_id)?
            .ok_or_else(|| AppError::NotFound("token not found".into()))?;

        // Owner can revoke own token with token.revoke_own; otherwise need TokenManage
        if token.subject_id == user.subject_id {
            self.authorizer
                .authorize_global(user, Permission::TokenRevokeOwn)
                .map_err(AppError::Forbidden)?;
        } else {
            self.authorizer
                .authorize_global(user, Permission::TokenManage)
                .map_err(AppError::Forbidden)?;
        }

        let now = self.clock.now();
        self.token_repo.revoke(&input.token_id, now)?;

        // Audit
        self.audit
            .record(&dbward_domain::entities::AuditEvent::simple(
                "token_revoked",
                "token",
                &user.subject_id,
                Some(&input.token_id),
                self.clock.now(),
            ))?;

        Ok(TokenRevokeOutput {
            id: input.token_id,
            revoked_at: now,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AuthzError;
    use dbward_domain::auth::{Permission, RoleDefinition, SubjectType};
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
        fn max_tokens(&self) -> u32 {
            10
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
        fn max_agents(&self) -> u32 {
            3
        }
        fn is_pro(&self) -> bool {
            false
        }
    }
    struct FakeAudit;
    impl AuditLogger for FakeAudit {
        fn record(&self, _: &dbward_domain::entities::AuditEvent) -> Result<(), AppError> {
            Ok(())
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

    fn make_uc(roles: Vec<RoleDefinition>, token_count: u32) -> TokenManage {
        TokenManage {
            authorizer: Arc::new(AllowAll),
            token_repo: Arc::new(FakeTokenRepo { count: token_count }),
            user_repo: Arc::new(FakeUserRepo),
            policy_repo: Arc::new(FakePolicyRepo { roles }),
            license: Arc::new(FakeLicense),
            audit: Arc::new(FakeAudit),
            clock: Arc::new(FakeClock),
            id_gen: Arc::new(FakeIdGen),
            token_gen: Arc::new(FakeTokenGen),
        }
    }

    #[test]
    fn create_rejects_unknown_role() {
        let uc = make_uc(
            vec![RoleDefinition {
                name: "dba".into(),
                permissions: vec![],
                databases: vec![],
                environments: vec![],
            }],
            0,
        );
        let result = uc.create(
            TokenCreateInput {
                subject_id: "bob".into(),
                subject_type: "user".into(),
                name: None,
                roles: vec!["nonexistent".into()],
                groups: vec![],
                expires_at: None,
            },
            &make_user(),
        );
        assert!(matches!(result, Err(AppError::Validation(_))));
    }

    #[test]
    fn create_accepts_known_role() {
        let uc = make_uc(
            vec![RoleDefinition {
                name: "dba".into(),
                permissions: vec![],
                databases: vec![],
                environments: vec![],
            }],
            0,
        );
        let result = uc.create(
            TokenCreateInput {
                subject_id: "bob".into(),
                subject_type: "user".into(),
                name: None,
                roles: vec!["dba".into()],
                groups: vec![],
                expires_at: None,
            },
            &make_user(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn create_rejects_at_free_limit() {
        let uc = make_uc(vec![], 10); // already at limit
        let result = uc.create(
            TokenCreateInput {
                subject_id: "bob".into(),
                subject_type: "user".into(),
                name: None,
                roles: vec![],
                groups: vec![],
                expires_at: None,
            },
            &make_user(),
        );
        assert!(matches!(result, Err(AppError::PlanLimit(_))));
    }
}
