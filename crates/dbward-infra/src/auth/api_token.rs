use std::sync::Arc;

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use dbward_app::error::AuthError;
use dbward_app::ports::{PolicyRepo, TokenRepo, TokenVerifier, UserRepo};
use dbward_domain::auth::{AuthUser, ResolvedRole};

pub struct ApiTokenVerifier {
    token_repo: Arc<dyn TokenRepo>,
    user_repo: Arc<dyn UserRepo>,
    policy_repo: Arc<dyn PolicyRepo>,
    oidc: Option<Arc<super::OidcVerifier>>,
}

impl ApiTokenVerifier {
    pub fn new(
        token_repo: Arc<dyn TokenRepo>,
        user_repo: Arc<dyn UserRepo>,
        policy_repo: Arc<dyn PolicyRepo>,
    ) -> Self {
        Self {
            token_repo,
            user_repo,
            policy_repo,
            oidc: None,
        }
    }

    pub fn with_oidc(mut self, oidc: super::OidcVerifier) -> Self {
        self.oidc = Some(Arc::new(oidc));
        self
    }
}

#[async_trait]
impl TokenVerifier for ApiTokenVerifier {
    async fn verify_api_token(&self, raw_token: &str) -> Result<AuthUser, AuthError> {
        if !raw_token.starts_with("dbw_") || raw_token.len() < 12 {
            return Err(AuthError::InvalidToken);
        }

        let without_prefix = &raw_token[4..];
        let prefix = &without_prefix[..8];
        let hash = hex::encode(Sha256::digest(raw_token.as_bytes()));

        let token = self
            .token_repo
            .verify(prefix, &hash)
            .map_err(|e| AuthError::Internal(e.to_string()))?
            .ok_or(AuthError::InvalidToken)?;

        // Check expiration
        if let Some(expires_at) = token.expires_at
            && expires_at < chrono::Utc::now()
        {
            return Err(AuthError::TokenExpired);
        }

        // fail-closed: propagate DB errors
        let suspended = self
            .user_repo
            .is_suspended(&token.subject_id)
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        if suspended {
            return Err(AuthError::UserSuspended);
        }

        // Resolve roles from token.roles by looking up role definitions
        // Token.roles stores role NAMES fixed at creation time (source of truth)
        let matched_roles = self
            .policy_repo
            .get_roles_by_names(&token.roles)
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        let roles: Vec<ResolvedRole> = matched_roles
            .into_iter()
            .map(|rd| ResolvedRole {
                name: rd.name,
                permissions: rd.permissions.into_iter().collect(),
                databases: rd.databases,
                environments: rd.environments,
            })
            .collect();

        if roles.is_empty() {
            return Err(AuthError::Internal(format!(
                "no matching role definitions for token roles: {:?}",
                token.roles
            )));
        }

        // Auto-create user on first auth
        self.user_repo
            .ensure_exists(&token.subject_id)
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(AuthUser {
            subject_id: token.subject_id,
            subject_type: token.subject_type,
            roles,
            groups: token.groups,
            token_id: Some(token.id),
        })
    }

    async fn verify_oidc_token(&self, token: &str) -> Result<(String, Vec<String>), AuthError> {
        match &self.oidc {
            Some(oidc) => oidc.verify_oidc_token(token).await,
            None => Err(AuthError::OidcNotConfigured),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use dbward_app::error::AppError;
    use dbward_domain::auth::{Permission, RoleDefinition, SubjectType};
    use dbward_domain::entities::{Token, TokenStatus, User};
    use dbward_domain::values::{DatabaseName, Environment};
    use std::sync::Mutex;

    // --- Fake repos ---

    struct FakeTokenRepo {
        token: Mutex<Option<Token>>,
    }
    impl FakeTokenRepo {
        fn with(token: Token) -> Self {
            Self { token: Mutex::new(Some(token)) }
        }
        fn empty() -> Self {
            Self { token: Mutex::new(None) }
        }
    }
    impl TokenRepo for FakeTokenRepo {
        fn verify(&self, _prefix: &str, _hash: &str) -> Result<Option<Token>, AppError> {
            Ok(self.token.lock().unwrap().clone())
        }
        fn create(&self, _: &Token) -> Result<(), AppError> { Ok(()) }
        fn list(&self) -> Result<Vec<Token>, AppError> { Ok(vec![]) }
        fn get(&self, _: &str) -> Result<Option<Token>, AppError> { Ok(None) }
        fn revoke(&self, _: &str, _: chrono::DateTime<Utc>) -> Result<bool, AppError> { Ok(true) }
        fn revoke_all_for_user(&self, _: &str, _: chrono::DateTime<Utc>) -> Result<u32, AppError> { Ok(0) }
        fn count_active(&self) -> Result<u32, AppError> { Ok(0) }
        fn purge_revoked(&self, _: &str) -> Result<u32, AppError> { Ok(0) }
    }

    struct FakeUserRepo {
        suspended: bool,
        ensure_exists_err: bool,
    }
    impl FakeUserRepo {
        fn ok() -> Self { Self { suspended: false, ensure_exists_err: false } }
        fn suspended() -> Self { Self { suspended: true, ensure_exists_err: false } }
        fn ensure_err() -> Self { Self { suspended: false, ensure_exists_err: true } }
    }
    impl UserRepo for FakeUserRepo {
        fn get(&self, _: &str) -> Result<Option<User>, AppError> { Ok(None) }
        fn upsert(&self, _: &User) -> Result<(), AppError> { Ok(()) }
        fn list(&self) -> Result<Vec<User>, AppError> { Ok(vec![]) }
        fn suspend(&self, _: &str, _: chrono::DateTime<Utc>) -> Result<bool, AppError> { Ok(true) }
        fn activate(&self, _: &str, _: chrono::DateTime<Utc>) -> Result<bool, AppError> { Ok(true) }
        fn is_suspended(&self, _: &str) -> Result<bool, AppError> { Ok(self.suspended) }
        fn ensure_exists(&self, _: &str) -> Result<(), AppError> {
            if self.ensure_exists_err {
                Err(AppError::Internal("db error".into()))
            } else {
                Ok(())
            }
        }
    }

    struct FakePolicyRepo {
        roles: Vec<RoleDefinition>,
    }
    impl FakePolicyRepo {
        fn with_admin() -> Self {
            Self {
                roles: vec![RoleDefinition {
                    name: "admin".into(),
                    permissions: vec![Permission::All],
                    databases: vec![DatabaseName::wildcard()],
                    environments: vec![Environment::wildcard()],
                }],
            }
        }
        fn empty() -> Self { Self { roles: vec![] } }
    }
    impl PolicyRepo for FakePolicyRepo {
        fn get_roles_by_names(&self, _: &[String]) -> Result<Vec<RoleDefinition>, AppError> {
            Ok(self.roles.clone())
        }
        fn create_workflow(&self, _: &dbward_domain::policies::Workflow) -> Result<(), AppError> { Ok(()) }
        fn get_workflow(&self, _: &str) -> Result<Option<dbward_domain::policies::Workflow>, AppError> { Ok(None) }
        fn list_workflows(&self) -> Result<Vec<dbward_domain::policies::Workflow>, AppError> { Ok(vec![]) }
        fn delete_workflow(&self, _: &str) -> Result<bool, AppError> { Ok(true) }
        fn count_workflows(&self) -> Result<u32, AppError> { Ok(0) }
        fn create_execution_policy(&self, _: &dbward_domain::policies::ExecutionPolicy) -> Result<(), AppError> { Ok(()) }
        fn get_execution_policy(&self, _: &str) -> Result<Option<dbward_domain::policies::ExecutionPolicy>, AppError> { Ok(None) }
        fn list_execution_policies(&self) -> Result<Vec<dbward_domain::policies::ExecutionPolicy>, AppError> { Ok(vec![]) }
        fn delete_execution_policy(&self, _: &str) -> Result<bool, AppError> { Ok(true) }
        fn find_result_policy(&self, _: &DatabaseName, _: &Environment) -> Result<Option<dbward_domain::policies::ResultPolicy>, AppError> { Ok(None) }
        fn create_result_policy(&self, _: &dbward_domain::policies::ResultPolicy) -> Result<(), AppError> { Ok(()) }
        fn get_result_policy(&self, _: &str) -> Result<Option<dbward_domain::policies::ResultPolicy>, AppError> { Ok(None) }
        fn list_result_policies(&self) -> Result<Vec<dbward_domain::policies::ResultPolicy>, AppError> { Ok(vec![]) }
        fn update_result_policy(&self, _: &dbward_domain::policies::ResultPolicy) -> Result<bool, AppError> { Ok(true) }
        fn delete_result_policy(&self, _: &str) -> Result<bool, AppError> { Ok(true) }
        fn create_notification_policy(&self, _: &dbward_domain::policies::NotificationPolicy) -> Result<(), AppError> { Ok(()) }
        fn get_notification_policy(&self, _: &str) -> Result<Option<dbward_domain::policies::NotificationPolicy>, AppError> { Ok(None) }
        fn list_notification_policies(&self) -> Result<Vec<dbward_domain::policies::NotificationPolicy>, AppError> { Ok(vec![]) }
        fn update_notification_policy(&self, _: &dbward_domain::policies::NotificationPolicy) -> Result<bool, AppError> { Ok(true) }
        fn delete_notification_policy(&self, _: &str) -> Result<bool, AppError> { Ok(true) }
        fn create_role(&self, _: &RoleDefinition) -> Result<(), AppError> { Ok(()) }
        fn list_roles(&self) -> Result<Vec<RoleDefinition>, AppError> { Ok(vec![]) }
        fn delete_role(&self, _: &str) -> Result<bool, AppError> { Ok(true) }
        fn count_roles(&self) -> Result<u32, AppError> { Ok(0) }
    }

    fn valid_token() -> Token {
        // raw token: "dbw_ABCDEFGH_rest_of_token" (≥12 chars, starts with dbw_)
        Token {
            id: "tok-1".into(),
            subject_type: SubjectType::User,
            subject_id: "user-1".into(),
            token_hash: hex::encode(Sha256::digest(b"dbw_ABCDEFGHextra")),
            token_prefix: "ABCDEFGH".into(),
            roles: vec!["admin".into()],
            groups: vec![],
            name: None,
            status: TokenStatus::Active,
            expires_at: None,
            created_at: Utc::now(),
            revoked_at: None,
        }
    }

    fn verifier(token_repo: impl TokenRepo + 'static, user_repo: impl UserRepo + 'static, policy_repo: impl PolicyRepo + 'static) -> ApiTokenVerifier {
        ApiTokenVerifier::new(Arc::new(token_repo), Arc::new(user_repo), Arc::new(policy_repo))
    }

    #[tokio::test]
    async fn missing_prefix_returns_invalid() {
        let v = verifier(FakeTokenRepo::empty(), FakeUserRepo::ok(), FakePolicyRepo::empty());
        let err = v.verify_api_token("no_prefix_here").await.unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken));
    }

    #[tokio::test]
    async fn too_short_returns_invalid() {
        let v = verifier(FakeTokenRepo::empty(), FakeUserRepo::ok(), FakePolicyRepo::empty());
        let err = v.verify_api_token("dbw_short").await.unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken));
    }

    #[tokio::test]
    async fn hash_mismatch_returns_invalid() {
        let v = verifier(FakeTokenRepo::empty(), FakeUserRepo::ok(), FakePolicyRepo::empty());
        let err = v.verify_api_token("dbw_ABCDEFGHextra").await.unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken));
    }

    #[tokio::test]
    async fn expired_token_returns_token_expired() {
        let mut token = valid_token();
        token.expires_at = Some(Utc::now() - Duration::hours(1));
        let v = verifier(FakeTokenRepo::with(token), FakeUserRepo::ok(), FakePolicyRepo::with_admin());
        let err = v.verify_api_token("dbw_ABCDEFGHextra").await.unwrap_err();
        assert!(matches!(err, AuthError::TokenExpired));
    }

    #[tokio::test]
    async fn suspended_user_returns_user_suspended() {
        let v = verifier(FakeTokenRepo::with(valid_token()), FakeUserRepo::suspended(), FakePolicyRepo::with_admin());
        let err = v.verify_api_token("dbw_ABCDEFGHextra").await.unwrap_err();
        assert!(matches!(err, AuthError::UserSuspended));
    }

    #[tokio::test]
    async fn no_matching_roles_returns_internal() {
        let v = verifier(FakeTokenRepo::with(valid_token()), FakeUserRepo::ok(), FakePolicyRepo::empty());
        let err = v.verify_api_token("dbw_ABCDEFGHextra").await.unwrap_err();
        assert!(matches!(err, AuthError::Internal(_)));
    }

    #[tokio::test]
    async fn ensure_exists_failure_returns_internal() {
        let v = verifier(FakeTokenRepo::with(valid_token()), FakeUserRepo::ensure_err(), FakePolicyRepo::with_admin());
        let err = v.verify_api_token("dbw_ABCDEFGHextra").await.unwrap_err();
        assert!(matches!(err, AuthError::Internal(_)));
    }

    #[tokio::test]
    async fn valid_token_returns_auth_user() {
        let v = verifier(FakeTokenRepo::with(valid_token()), FakeUserRepo::ok(), FakePolicyRepo::with_admin());
        let user = v.verify_api_token("dbw_ABCDEFGHextra").await.unwrap();
        assert_eq!(user.subject_id, "user-1");
        assert_eq!(user.roles.len(), 1);
        assert_eq!(user.roles[0].name, "admin");
        assert_eq!(user.token_id, Some("tok-1".into()));
    }
}
