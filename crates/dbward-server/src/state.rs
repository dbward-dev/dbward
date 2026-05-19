use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use dbward_app::ports::{
    AgentRepo, ApprovalRepo, AuditLogger, AuditRepo, Authorizer, BackgroundTaskRepo, Clock,
    DatabaseRegistry, DryRunRepo, EventDispatcher, IdGenerator, LicenseChecker, Notifier,
    PolicyEvaluator, PolicyRepo, RequestReader, RequestWriter, ResultChannel, ResultStore,
    RoleResolver, SchemaRepo, SsrfValidator, TokenRepo, TokenSigner, TokenVerifier, UserRepo,
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
    pub request_reader: Arc<dyn RequestReader>,
    pub request_writer: Arc<dyn RequestWriter>,
    pub approval_repo: Arc<dyn ApprovalRepo>,
    pub background_task_repo: Arc<dyn BackgroundTaskRepo>,
    pub agent_repo: Arc<dyn AgentRepo>,
    pub user_repo: Arc<dyn UserRepo>,
    pub token_repo: Arc<dyn TokenRepo>,
    pub webhook_repo: Arc<dyn WebhookRepo>,
    pub policy_repo: Arc<dyn PolicyRepo>,
    pub database_registry: Arc<dyn DatabaseRegistry>,
    pub schema_repo: Arc<dyn SchemaRepo>,
    pub dry_run_repo: Arc<dyn DryRunRepo>,
    pub audit_logger: Arc<dyn AuditLogger>,
    pub audit_repo: Arc<dyn AuditRepo>,
    // Services
    pub policy_evaluator: Arc<dyn PolicyEvaluator>,
    pub result_store: Arc<dyn ResultStore>,
    pub result_channel: Arc<dyn ResultChannel>,
    pub token_signer: Arc<dyn TokenSigner>,
    pub notifier: Arc<dyn Notifier>,
    pub webhook_sender: Arc<dyn dbward_app::ports::WebhookSender>,
    pub event_dispatcher: Arc<dyn EventDispatcher>,
    pub ssrf_validator: Arc<dyn SsrfValidator>,
    pub license_checker: Arc<dyn LicenseChecker>,
    pub clock: Arc<dyn Clock>,
    pub id_generator: Arc<dyn IdGenerator>,
    pub token_value_generator: Arc<dyn dbward_app::ports::TokenValueGenerator>,
    // Repos (DLQ)
    pub webhook_delivery_repo: Option<Arc<dyn dbward_app::ports::WebhookDeliveryRepo>>,
    // Metrics
    pub metrics: Arc<Metrics>,
    // Config
    pub default_approval_ttl_secs: Option<u64>,
    pub max_persist_bytes: usize,
    pub auth_mode: String,
    pub storage_backend: String,
    // Shutdown
    pub draining: Arc<AtomicBool>,
}
