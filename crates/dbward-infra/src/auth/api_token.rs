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
}

impl ApiTokenVerifier {
    pub fn new(
        token_repo: Arc<dyn TokenRepo>,
        user_repo: Arc<dyn UserRepo>,
        policy_repo: Arc<dyn PolicyRepo>,
    ) -> Self {
        Self { token_repo, user_repo, policy_repo }
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

        // fail-closed: propagate DB errors
        let suspended = self.user_repo.is_suspended(&token.subject_id)
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        if suspended {
            return Err(AuthError::UserSuspended);
        }

        // Resolve roles from token.roles by looking up role definitions
        // Token.roles stores role NAMES fixed at creation time (source of truth)
        let matched_roles = self.policy_repo.get_roles_by_names(&token.roles)
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        let roles: Vec<ResolvedRole> = matched_roles.into_iter().map(|rd| {
            ResolvedRole {
                name: rd.name,
                permissions: rd.permissions.into_iter().collect(),
                databases: rd.databases,
                environments: rd.environments,
            }
        }).collect();

        if roles.is_empty() {
            return Err(AuthError::Internal(
                format!("no matching role definitions for token roles: {:?}", token.roles)
            ));
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
