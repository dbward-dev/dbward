use std::sync::Arc;

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use dbward_app::error::AuthError;
use dbward_app::ports::{RoleResolver, TokenRepo, TokenVerifier, UserRepo};
use dbward_domain::auth::AuthUser;

pub struct ApiTokenVerifier {
    token_repo: Arc<dyn TokenRepo>,
    user_repo: Arc<dyn UserRepo>,
    role_resolver: Arc<dyn RoleResolver>,
}

impl ApiTokenVerifier {
    pub fn new(
        token_repo: Arc<dyn TokenRepo>,
        user_repo: Arc<dyn UserRepo>,
        role_resolver: Arc<dyn RoleResolver>,
    ) -> Self {
        Self { token_repo, user_repo, role_resolver }
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

        let token = self.token_repo.verify(prefix, &hash)
            .map_err(|e| AuthError::Internal(e.to_string()))?
            .ok_or(AuthError::InvalidToken)?;

        // Check expiration
        if let Some(expires_at) = token.expires_at {
            if expires_at < chrono::Utc::now() {
                return Err(AuthError::TokenExpired);
            }
        }

        // fail-closed: propagate DB errors (not unwrap_or)
        let suspended = self.user_repo.is_suspended(&token.subject_id)
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        if suspended {
            return Err(AuthError::UserSuspended);
        }

        // Resolve roles using token.roles directly (not RoleResolver).
        // API tokens have fixed roles at creation time — this is the source of truth.
        let roles = self.role_resolver
            .resolve(&token.subject_id, token.subject_type, &token.roles)
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        if roles.is_empty() {
            return Err(AuthError::Internal("no roles resolved for token".into()));
        }

        Ok(AuthUser {
            subject_id: token.subject_id,
            subject_type: token.subject_type,
            roles,
            groups: token.groups,
            token_id: Some(token.id),
        })
    }

    async fn verify_oidc_token(&self, _token: &str) -> Result<(String, Vec<String>), AuthError> {
        Err(AuthError::OidcNotConfigured)
    }
}
