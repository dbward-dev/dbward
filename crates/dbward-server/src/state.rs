use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use dbward_app::ports::{
    AgentRepo, AuditLogger, AuditRepo, Authorizer, Clock, DatabaseRegistry, EventDispatcher,
    IdGenerator, LicenseChecker, Notifier, PolicyEvaluator, PolicyRepo, RequestRepo, ResultChannel,
    ResultStore, RoleResolver, SsrfValidator, TokenRepo, TokenSigner, TokenVerifier, UserRepo,
    WebhookRepo,
};

use crate::metrics::Metrics;

#[derive(Clone)]
pub struct AppState {
    // Auth
    pub token_verifier: Arc<dyn TokenVerifier>,
    pub role_resolver: Arc<dyn RoleResolver>,
    pub authorizer: Arc<dyn Authorizer>,
    // Repos
    pub request_repo: Arc<dyn RequestRepo>,
    pub agent_repo: Arc<dyn AgentRepo>,
    pub user_repo: Arc<dyn UserRepo>,
    pub token_repo: Arc<dyn TokenRepo>,
    pub webhook_repo: Arc<dyn WebhookRepo>,
    pub policy_repo: Arc<dyn PolicyRepo>,
    pub database_registry: Arc<dyn DatabaseRegistry>,
    pub audit_logger: Arc<dyn AuditLogger>,
    pub audit_repo: Arc<dyn AuditRepo>,
    // Services
    pub policy_evaluator: Arc<dyn PolicyEvaluator>,
    pub result_store: Arc<dyn ResultStore>,
    pub result_channel: Arc<dyn ResultChannel>,
    pub token_signer: Arc<dyn TokenSigner>,
    pub notifier: Arc<dyn Notifier>,
    pub event_dispatcher: Arc<dyn EventDispatcher>,
    pub ssrf_validator: Arc<dyn SsrfValidator>,
    pub license_checker: Arc<dyn LicenseChecker>,
    pub clock: Arc<dyn Clock>,
    pub id_generator: Arc<dyn IdGenerator>,
    // Metrics
    pub metrics: Arc<Metrics>,
    // Config
    pub default_approval_ttl_secs: Option<u64>,
    pub auth_mode: String,
    // Shutdown
    pub draining: Arc<AtomicBool>,
}
