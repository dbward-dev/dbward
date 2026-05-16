use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission};
use dbward_domain::entities::{AuditContext, AuditEvent, Webhook};

use crate::error::AppError;
use crate::ports::*;

pub struct WebhookManage {
    pub authorizer: Arc<dyn Authorizer>,
    pub webhook_repo: Arc<dyn WebhookRepo>,
    pub ssrf_validator: Arc<dyn SsrfValidator>,
    pub license: Arc<dyn LicenseChecker>,
    pub audit: Arc<dyn AuditLogger>,
    pub notifier: Arc<dyn Notifier>,
    pub clock: Arc<dyn Clock>,
    pub id_gen: Arc<dyn IdGenerator>,
}

pub struct WebhookCreateInput {
    pub url: String,
    pub events: Vec<String>,
    pub format: String,
    pub secret: Option<String>,
}

pub struct WebhookUpdateInput {
    pub id: String,
    pub url: Option<String>,
    pub events: Option<Vec<String>>,
    pub format: Option<String>,
    pub secret: Option<Option<String>>, // None=no change, Some(None)=remove, Some(Some(v))=set
}

pub struct WebhookDeleteInput {
    pub id: String,
}

impl WebhookManage {
    pub fn create(
        &self,
        input: WebhookCreateInput,
        user: &AuthUser,
        ctx: &AuditContext,
    ) -> Result<Webhook, AppError> {
        self.authorizer
            .authorize_global(user, Permission::WebhookManage)
            .map_err(AppError::Forbidden)?;

        if input.url.is_empty() {
            return Err(AppError::Validation("url is required".into()));
        }
        if !matches!(input.format.as_str(), "generic" | "slack") {
            return Err(AppError::Validation(
                "format must be 'generic' or 'slack'".into(),
            ));
        }
        if let Some(ref s) = input.secret {
            if s.is_empty() {
                return Err(AppError::Validation("secret must not be empty".into()));
            }
        }

        // SSRF validation
        self.ssrf_validator.validate_url(&input.url)?;

        // Free tier limit
        let existing = self.webhook_repo.list()?;
        if existing.len() as u32 >= self.license.max_webhooks() {
            return Err(AppError::PlanLimit("webhook limit reached".into()));
        }

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
            created_at: None,
            updated_at: None,
        };
        self.webhook_repo.create(&webhook)?;

        // Audit
        self.audit.record(&AuditEvent::simple(
            "webhook_created",
            "policy",
            &user.subject_id,
            Some(&webhook.id),
            self.clock.now(),
            ctx,
        ))?;

        // Reload dispatcher config
        let _ = self.notifier.reload();

        Ok(webhook)
    }

    pub fn update(
        &self,
        input: WebhookUpdateInput,
        user: &AuthUser,
        ctx: &AuditContext,
    ) -> Result<Webhook, AppError> {
        self.authorizer
            .authorize_global(user, Permission::WebhookManage)
            .map_err(AppError::Forbidden)?;

        let mut webhook = self
            .webhook_repo
            .get(&input.id)?
            .ok_or_else(|| AppError::NotFound("webhook not found".into()))?;

        if let Some(url) = input.url {
            self.ssrf_validator.validate_url(&url)?;
            webhook.url = url;
        }
        if let Some(events) = input.events {
            webhook.events = events;
        }
        if let Some(ref format) = input.format {
            if !matches!(format.as_str(), "generic" | "slack") {
                return Err(AppError::Validation(
                    "format must be 'generic' or 'slack'".into(),
                ));
            }
            webhook.format = match format.as_str() {
                "slack" => dbward_domain::entities::WebhookFormat::Slack,
                _ => dbward_domain::entities::WebhookFormat::Generic,
            };
        }
        if let Some(secret_opt) = input.secret {
            if let Some(ref s) = secret_opt {
                if s.is_empty() {
                    return Err(AppError::Validation("secret must not be empty".into()));
                }
            }
            webhook.secret = secret_opt;
        }

        self.webhook_repo.update(&webhook)?;
        self.audit.record(&AuditEvent::simple(
            "webhook_updated",
            "policy",
            &user.subject_id,
            Some(&webhook.id),
            self.clock.now(),
            ctx,
        ))?;

        // Reload dispatcher config
        let _ = self.notifier.reload();

        Ok(webhook)
    }

    pub fn list(&self, user: &AuthUser) -> Result<Vec<Webhook>, AppError> {
        self.authorizer
            .authorize_global(user, Permission::WebhookManage)
            .map_err(AppError::Forbidden)?;
        self.webhook_repo.list()
    }

    pub fn get(&self, id: &str, user: &AuthUser) -> Result<Webhook, AppError> {
        self.authorizer
            .authorize_global(user, Permission::WebhookManage)
            .map_err(AppError::Forbidden)?;
        self.webhook_repo
            .get(id)?
            .ok_or_else(|| AppError::NotFound("webhook not found".into()))
    }

    pub fn delete(
        &self,
        input: WebhookDeleteInput,
        user: &AuthUser,
        ctx: &AuditContext,
    ) -> Result<(), AppError> {
        self.authorizer
            .authorize_global(user, Permission::WebhookManage)
            .map_err(AppError::Forbidden)?;
        self.webhook_repo
            .get(&input.id)?
            .ok_or_else(|| AppError::NotFound("webhook not found".into()))?;
        self.webhook_repo.delete(&input.id)?;
        self.audit.record(&AuditEvent::simple(
            "webhook_deleted",
            "policy",
            &user.subject_id,
            Some(&input.id),
            self.clock.now(),
            ctx,
        ))?;

        // Reload dispatcher config
        let _ = self.notifier.reload();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AuthzError;
    use dbward_domain::auth::{Permission, SubjectType};
    use dbward_domain::entities::{Webhook, WebhookFormat, WebhookStatus};

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
    struct FakeIdGen;
    impl IdGenerator for FakeIdGen {
        fn generate(&self) -> String {
            "wh-1".into()
        }
    }
    struct AllowSsrf;
    impl SsrfValidator for AllowSsrf {
        fn validate_url(&self, _: &str) -> Result<(), AppError> {
            Ok(())
        }
    }
    struct FakeLicense;
    impl LicenseChecker for FakeLicense {
        fn max_tokens(&self) -> u32 {
            10
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
    }
    struct FakeAudit;
    impl AuditLogger for FakeAudit {
        fn record(&self, _: &dbward_domain::entities::AuditEvent) -> Result<(), AppError> {
            Ok(())
        }
    }
    struct FakeNotifier;
    impl Notifier for FakeNotifier {
        fn dispatch(&self, _: WebhookEvent) {}
    }
    struct FakeWebhookRepo;
    impl WebhookRepo for FakeWebhookRepo {
        fn create(&self, _: &Webhook) -> Result<(), AppError> {
            Ok(())
        }
        fn get(&self, _: &str) -> Result<Option<Webhook>, AppError> {
            Ok(Some(Webhook {
                id: "wh-1".into(),
                url: "https://example.com".into(),
                events: vec![],
                format: WebhookFormat::Generic,
                secret: None,
                status: WebhookStatus::Active,
                created_at: None,
                updated_at: None,
            }))
        }
        fn list(&self) -> Result<Vec<Webhook>, AppError> {
            Ok(vec![])
        }
        fn update(&self, _: &Webhook) -> Result<(), AppError> {
            Ok(())
        }
        fn delete(&self, _: &str) -> Result<(), AppError> {
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

    fn make_uc() -> WebhookManage {
        WebhookManage {
            authorizer: Arc::new(AllowAll),
            webhook_repo: Arc::new(FakeWebhookRepo),
            ssrf_validator: Arc::new(AllowSsrf),
            license: Arc::new(FakeLicense),
            audit: Arc::new(FakeAudit),
            notifier: Arc::new(FakeNotifier),
            clock: Arc::new(FakeClock),
            id_gen: Arc::new(FakeIdGen),
        }
    }

    #[test]
    fn update_rejects_invalid_format() {
        let uc = make_uc();
        let result = uc.update(
            WebhookUpdateInput {
                id: "wh-1".into(),
                url: None,
                events: None,
                format: Some("xml".into()),
                secret: None,
            },
            &make_user(),
            &dbward_domain::entities::AuditContext::System,
        );
        assert!(matches!(result, Err(AppError::Validation(_))));
    }

    #[test]
    fn update_rejects_empty_secret() {
        let uc = make_uc();
        let result = uc.update(
            WebhookUpdateInput {
                id: "wh-1".into(),
                url: None,
                events: None,
                format: None,
                secret: Some(Some("".into())),
            },
            &make_user(),
            &dbward_domain::entities::AuditContext::System,
        );
        assert!(matches!(result, Err(AppError::Validation(_))));
    }

    #[test]
    fn create_rejects_empty_secret() {
        let uc = make_uc();
        let result = uc.create(
            WebhookCreateInput {
                url: "https://example.com/hook".into(),
                events: vec![],
                format: "generic".into(),
                secret: Some("".into()),
            },
            &make_user(),
            &dbward_domain::entities::AuditContext::System,
        );
        assert!(matches!(result, Err(AppError::Validation(_))));
    }
}
