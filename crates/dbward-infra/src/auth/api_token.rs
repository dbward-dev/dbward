use std::sync::Arc;

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use dbward_app::error::AuthError;
use dbward_app::ports::{OidcTokenVerifier, TokenRepo, TokenVerifier, VerifiedToken};

pub struct ApiTokenVerifier {
    token_repo: Arc<dyn TokenRepo>,
    oidc: Option<Arc<dyn OidcTokenVerifier>>,
}

impl ApiTokenVerifier {
    pub fn new(token_repo: Arc<dyn TokenRepo>) -> Self {
        Self {
            token_repo,
            oidc: None,
        }
    }

    pub fn with_oidc(mut self, oidc: Arc<dyn OidcTokenVerifier>) -> Self {
        self.oidc = Some(oidc);
        self
    }
}

#[async_trait]
impl TokenVerifier for ApiTokenVerifier {
    async fn verify_api_token(&self, raw_token: &str) -> Result<VerifiedToken, AuthError> {
        if !raw_token.starts_with("dbw_") || raw_token.len() < 12 || raw_token.len() > 256 {
            return Err(AuthError::InvalidToken);
        }

        if !raw_token.is_ascii() {
            tracing::debug!(token_len = raw_token.len(), "rejected non-ASCII API token");
            return Err(AuthError::InvalidToken);
        }

        let without_prefix = raw_token.get(4..).ok_or(AuthError::InvalidToken)?;
        let prefix = without_prefix.get(..8).ok_or(AuthError::InvalidToken)?;
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

        Ok(VerifiedToken {
            id: token.id,
            subject_id: token.subject_id,
            subject_type: token.subject_type,
            scope_ceiling: token.scope_ceiling,
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
    use dbward_domain::auth::SubjectType;
    use dbward_domain::entities::{ScopeCeiling, Token, TokenStatus};
    use std::sync::Mutex;

    struct FakeTokenRepo {
        token: Mutex<Option<Token>>,
    }
    impl FakeTokenRepo {
        fn with(token: Token) -> Self {
            Self {
                token: Mutex::new(Some(token)),
            }
        }
        fn empty() -> Self {
            Self {
                token: Mutex::new(None),
            }
        }
    }
    impl TokenRepo for FakeTokenRepo {
        fn verify(&self, _prefix: &str, _hash: &str) -> Result<Option<Token>, AppError> {
            Ok(self.token.lock().unwrap().clone())
        }
        fn create(&self, _: &Token) -> Result<(), AppError> {
            Ok(())
        }
        fn list(&self) -> Result<Vec<Token>, AppError> {
            Ok(vec![])
        }
        fn get(&self, _: &str) -> Result<Option<Token>, AppError> {
            Ok(None)
        }
        fn revoke(&self, _: &str, _: chrono::DateTime<Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn revoke_all_for_user(&self, _: &str, _: chrono::DateTime<Utc>) -> Result<u32, AppError> {
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

    fn valid_token() -> Token {
        Token {
            id: "tok-1".into(),
            subject_type: SubjectType::User,
            subject_id: "user-1".into(),
            token_hash: hex::encode(Sha256::digest(b"dbw_ABCDEFGHextra")),
            token_prefix: "ABCDEFGH".into(),
            scope_ceiling: Some(ScopeCeiling {
                roles: vec!["admin".into()],
            }),
            name: None,
            status: TokenStatus::Active,
            provisioning_kind: None,
            expires_at: None,
            created_at: Utc::now(),
            revoked_at: None,
        }
    }

    fn verifier(token_repo: impl TokenRepo + 'static) -> ApiTokenVerifier {
        ApiTokenVerifier::new(Arc::new(token_repo))
    }

    #[tokio::test]
    async fn missing_prefix_returns_invalid() {
        let v = verifier(FakeTokenRepo::empty());
        let err = v.verify_api_token("no_prefix_here").await.unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken));
    }

    #[tokio::test]
    async fn too_short_returns_invalid() {
        let v = verifier(FakeTokenRepo::empty());
        let err = v.verify_api_token("dbw_short").await.unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken));
    }

    #[tokio::test]
    async fn hash_mismatch_returns_invalid() {
        let v = verifier(FakeTokenRepo::empty());
        let err = v.verify_api_token("dbw_ABCDEFGHextra").await.unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken));
    }

    #[tokio::test]
    async fn expired_token_returns_token_expired() {
        let mut token = valid_token();
        token.expires_at = Some(Utc::now() - Duration::hours(1));
        let v = verifier(FakeTokenRepo::with(token));
        let err = v.verify_api_token("dbw_ABCDEFGHextra").await.unwrap_err();
        assert!(matches!(err, AuthError::TokenExpired));
    }

    #[tokio::test]
    async fn valid_token_returns_verified_token() {
        let v = verifier(FakeTokenRepo::with(valid_token()));
        let vt = v.verify_api_token("dbw_ABCDEFGHextra").await.unwrap();
        assert_eq!(vt.subject_id, "user-1");
        assert_eq!(vt.id, "tok-1");
        assert!(vt.scope_ceiling.is_some());
    }

    #[tokio::test]
    async fn non_ascii_returns_invalid() {
        let v = verifier(FakeTokenRepo::empty());
        let err = v.verify_api_token("dbw_abcdef8Ю*20").await.unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken));
    }

    #[tokio::test]
    async fn empty_string_returns_invalid() {
        let v = verifier(FakeTokenRepo::empty());
        let err = v.verify_api_token("").await.unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken));
    }

    #[tokio::test]
    async fn oversized_token_returns_invalid() {
        let v = verifier(FakeTokenRepo::empty());
        let long = format!("dbw_{}", "a".repeat(300));
        let err = v.verify_api_token(&long).await.unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken));
    }
}
