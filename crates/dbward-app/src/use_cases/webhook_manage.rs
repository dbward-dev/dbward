use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission};
use dbward_domain::entities::Webhook;

use crate::error::AppError;
use crate::ports::*;

pub struct WebhookManage {
    pub authorizer: Arc<dyn Authorizer>,
    pub webhook_repo: Arc<dyn WebhookRepo>,
    pub license: Arc<dyn LicenseChecker>,
    pub audit: Arc<dyn AuditLogger>,
    pub clock: Arc<dyn Clock>,
    pub id_gen: Arc<dyn IdGenerator>,
}

pub struct WebhookCreateInput {
    pub url: String,
    pub events: Vec<String>,
    pub format: String,
    pub secret: Option<String>,
}

pub struct WebhookDeleteInput {
    pub id: String,
}

impl WebhookManage {
    pub fn create(&self, input: WebhookCreateInput, user: &AuthUser) -> Result<Webhook, AppError> {
        self.authorizer.authorize_global(user, Permission::WebhookManage)
            .map_err(AppError::Forbidden)?;

        // Validation
        if input.url.is_empty() {
            return Err(AppError::Validation("url is required".into()));
        }
        if !matches!(input.format.as_str(), "generic" | "slack") {
            return Err(AppError::Validation("format must be 'generic' or 'slack'".into()));
        }
        if let Some(ref s) = input.secret {
            if s.is_empty() {
                return Err(AppError::Validation("secret must not be empty".into()));
            }
        }

        // Free tier limit
        let existing = self.webhook_repo.list()?;
        if existing.len() as u32 >= self.license.max_webhooks() {
            return Err(AppError::PlanLimit("webhook limit reached".into()));
        }

        let now = self.clock.now();
        let webhook = Webhook {
            id: self.id_gen.generate(),
            url: input.url,
            events: input.events,
            format: match input.format.as_str() {
                "slack" => dbward_domain::entities::WebhookFormat::Slack,
                _ => dbward_domain::entities::WebhookFormat::Generic,
            },
            secret: input.secret,
            status: dbward_domain::entities::WebhookStatus::Active,
        };
        self.webhook_repo.create(&webhook)?;
        Ok(webhook)
    }

    pub fn list(&self, user: &AuthUser) -> Result<Vec<Webhook>, AppError> {
        self.authorizer.authorize_global(user, Permission::WebhookManage)
            .map_err(AppError::Forbidden)?;
        self.webhook_repo.list()
    }

    pub fn delete(&self, input: WebhookDeleteInput, user: &AuthUser) -> Result<(), AppError> {
        self.authorizer.authorize_global(user, Permission::WebhookManage)
            .map_err(AppError::Forbidden)?;
        self.webhook_repo.get(&input.id)?
            .ok_or_else(|| AppError::NotFound("webhook not found".into()))?;
        self.webhook_repo.delete(&input.id)?;
        Ok(())
    }
}
