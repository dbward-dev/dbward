use std::sync::Arc;

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use dbward_domain::auth::{AuthUser, Permission};

use crate::error::AppError;
use crate::ports::*;

pub struct TokenManage {
    pub authorizer: Arc<dyn Authorizer>,
    pub token_repo: Arc<dyn TokenRepo>,
    pub user_repo: Arc<dyn UserRepo>,
    pub license: Arc<dyn LicenseChecker>,
    pub audit: Arc<dyn AuditLogger>,
    pub clock: Arc<dyn Clock>,
    pub id_gen: Arc<dyn IdGenerator>,
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
    pub fn create(&self, input: TokenCreateInput, user: &AuthUser) -> Result<TokenCreateOutput, AppError> {
        self.authorizer.authorize_global(user, Permission::TokenManage)
            .map_err(AppError::Forbidden)?;

        // Validation
        if input.subject_id.is_empty() {
            return Err(AppError::Validation("subject_id is required".into()));
        }
        if !matches!(input.subject_type.as_str(), "user" | "agent") {
            return Err(AppError::Validation("subject_type must be 'user' or 'agent'".into()));
        }
        if let Some(ref exp) = input.expires_at {
            if *exp <= self.clock.now() {
                return Err(AppError::Validation("expires_at must be in the future".into()));
            }
        }

        // Suspended user check
        if self.user_repo.is_suspended(&input.subject_id)? {
            return Err(AppError::Conflict("cannot create token for suspended user".into()));
        }

        // Free tier limit
        let count = self.token_repo.count_active()?;
        if count >= self.license.max_tokens() {
            return Err(AppError::PlanLimit("token limit reached".into()));
        }

        // Generate token
        let raw = format!("dbw_{}", Uuid::new_v4().simple());
        let prefix = raw[..8].to_string();
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
        self.audit.record(&dbward_domain::entities::AuditEvent::simple(
            "token_created", "token", &user.subject_id, Some(&id),
        ))?;

        Ok(TokenCreateOutput { id, token: raw, prefix, subject_id: input.subject_id })
    }

    pub fn list(&self, user: &AuthUser) -> Result<TokenListOutput, AppError> {
        self.authorizer.authorize_global(user, Permission::TokenManage)
            .map_err(AppError::Forbidden)?;
        let tokens = self.token_repo.list()?;
        Ok(TokenListOutput { tokens })
    }

    pub fn revoke(&self, input: TokenRevokeInput, user: &AuthUser) -> Result<TokenRevokeOutput, AppError> {
        let token = self.token_repo.get(&input.token_id)?
            .ok_or_else(|| AppError::NotFound("token not found".into()))?;

        // Owner can revoke own token with token.revoke_own; otherwise need TokenManage
        if token.subject_id == user.subject_id {
            self.authorizer.authorize_global(user, Permission::TokenRevokeOwn)
                .map_err(AppError::Forbidden)?;
        } else {
            self.authorizer.authorize_global(user, Permission::TokenManage)
                .map_err(AppError::Forbidden)?;
        }

        let now = self.clock.now();
        self.token_repo.revoke(&input.token_id, now)?;

        // Audit
        self.audit.record(&dbward_domain::entities::AuditEvent::simple(
            "token_revoked", "token", &user.subject_id, Some(&input.token_id),
        ))?;

        Ok(TokenRevokeOutput { id: input.token_id, revoked_at: now })
    }
}
