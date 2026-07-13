use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use arc_swap::ArcSwap;
use dbward_app::ports::{
    AgentRepo, ApprovalRepo, AuditLogger, AuditRepo, Authorizer, BackgroundTaskRepo, Clock,
    ContextRepo, DatabaseRegistry, DryRunRepo, GroupRepo, IdGenerator, LicenseChecker, Notifier,
    PolicyEvaluator, PolicyRepo, PreflightJobRepo, RequestReader, RequestWriter, ResultChannel,
    ResultStore, RoleResolver, SchemaRepo, SsrfValidator, TokenRepo, TokenSigner, TokenVerifier,
    UnitOfWork, UserRepo, WebhookRepo,
};
use dbward_app::use_cases::{
    agent_claim::AgentClaim,
    agent_heartbeat::AgentHeartbeat,
    agent_poll::AgentPoll,
    agent_submit_result::AgentSubmitResult,
    approve_request::ApproveRequest,
    audit_query::AuditQuery,
    cancel_request::CancelRequest,
    create_request::CreateRequest,
    dry_run::{DryRunClaim, DryRunSubmitResult},
    get_request::GetRequest,
    get_result::GetResult,
    get_schema::GetSchema,
    list_requests::ListRequests,
    preflight::PreflightUseCase,
    reject_request::RejectRequest,
    resume_request::ResumeRequest,
    schema_sync::SchemaSync,
    stream_result::StreamResult,
    token_manage::TokenManage,
    user_manage::UserManage,
};

use crate::metrics::Metrics;

/// Config fields that can be hot-reloaded via SIGHUP without restarting.
pub struct ReloadableConfig {
    pub role_resolver: Arc<dyn RoleResolver>,
    pub default_approval_ttl_secs: Option<u64>,
}

#[derive(Clone)]
pub struct AppState {
    // Reloadable portion (swapped atomically on SIGHUP)
    pub(crate) reloadable: Arc<ArcSwap<ReloadableConfig>>,

    // Auth — pub(crate) for middleware
    pub(crate) token_verifier: Arc<dyn TokenVerifier>,
    pub(crate) authorizer: Arc<dyn Authorizer>,

    // Repos — private
    request_reader: Arc<dyn RequestReader>,
    request_writer: Arc<dyn RequestWriter>,
    approval_repo: Arc<dyn ApprovalRepo>,
    background_task_repo: Arc<dyn BackgroundTaskRepo>,
    agent_repo: Arc<dyn AgentRepo>,
    user_repo: Arc<dyn UserRepo>,
    group_repo: Arc<dyn GroupRepo>,
    onboarding_repo: Arc<dyn dbward_app::ports::OnboardingRequestRepo>,
    token_repo: Arc<dyn TokenRepo>,
    webhook_repo: Arc<dyn WebhookRepo>,
    policy_repo: Arc<dyn PolicyRepo>,
    database_registry: Arc<dyn DatabaseRegistry>,
    schema_repo: Arc<dyn SchemaRepo>,
    dry_run_repo: Arc<dyn DryRunRepo>,
    context_repo: Arc<dyn ContextRepo>,
    audit_logger: Arc<dyn AuditLogger>,
    audit_repo: Arc<dyn AuditRepo>,

    // Services — private
    policy_evaluator: Arc<dyn PolicyEvaluator>,
    result_store: Arc<dyn ResultStore>,
    result_channel: Arc<dyn ResultChannel>,
    token_signer: Arc<dyn TokenSigner>,
    notifier: Arc<dyn Notifier>,
    webhook_sender: Arc<dyn dbward_app::ports::WebhookSender>,
    #[allow(dead_code)] // Used in sync_all_config (cloned before AppState build)
    ssrf_validator: Arc<dyn SsrfValidator>,
    license_checker: Arc<dyn LicenseChecker>,
    #[cfg(feature = "commercial")]
    license_checker_impl: Option<Arc<dbward_commercial_license::LicenseCheckerImpl>>,
    server_meta_repo: Option<Arc<dyn dbward_app::ports::ServerMetaRepo>>,
    clock: Arc<dyn Clock>,
    id_generator: Arc<dyn IdGenerator>,
    token_value_generator: Arc<dyn dbward_app::ports::TokenValueGenerator>,
    webhook_delivery_repo: Option<Arc<dyn dbward_app::ports::WebhookDeliveryRepo>>,
    uow: Arc<dyn dbward_app::ports::UnitOfWork>,
    pub(crate) audit_signer: Arc<dyn dbward_app::ports::crypto::AuditSigner>,
    pub(crate) audit_verifier: Arc<dyn dbward_app::ports::crypto::AuditVerifier>,

    // Metrics — pub(crate)
    pub(crate) metrics: Arc<Metrics>,

    // Config — pub(crate)
    pub(crate) max_persist_bytes: usize,
    pub(crate) accept_oidc: bool,
    pub(crate) storage_backend: String,
    pub(crate) max_active_tokens_per_user: u32,

    // Shutdown — pub(crate)
    pub(crate) draining: Arc<AtomicBool>,

    // Preflight — pub(crate)
    pub(crate) preflight_job_repo: Arc<dyn PreflightJobRepo>,
    pub(crate) preflight_notifier: Arc<crate::preflight_notifier::PreflightNotifier>,
    pub(crate) preflight_max_concurrent_per_user: u32,
    pub(crate) preflight_max_explain_timeout_ms: u64,

    // Slack — pub(crate)
    pub(crate) slack_config: Option<dbward_infra::slack::SlackConfig>,
    pub(crate) slack_client: Option<Arc<dyn dbward_infra::slack::SlackClient>>,
    pub(crate) slack_onboarding: Option<dbward_config::server::SlackOnboardingConfig>,

    // Raw DB connection for low-level ops (retained for future use / test compatibility)
    #[allow(dead_code)]
    pub(crate) db_conn: dbward_infra::sqlite::DbConn,

    // DbRoleResolver (shared, long-lived — DashMap cache survives config reloads)
    pub(crate) db_role_resolver: Option<Arc<dbward_infra::auth::DbRoleResolver>>,

    // MCP
    pub(crate) mcp_enabled: bool,
    pub(crate) mcp_allowed_origins: Vec<String>,
    pub(crate) mcp_default_database: String,
    pub(crate) mcp_default_environment: String,
    pub(crate) mcp_elicitation_timeout_secs: u64,
    pub(crate) mcp_replay_buffer_size: usize,
    pub(crate) session_store: Arc<crate::session_store::SessionStore>,
}

// ---------------------------------------------------------------------------
// UC Factories
// ---------------------------------------------------------------------------

/// Request-related use cases.
pub(crate) struct RequestUseCases<'a>(&'a AppState);

impl<'a> RequestUseCases<'a> {
    pub(crate) fn create(&self) -> CreateRequest {
        let s = self.0;
        let r = s.reloadable.load();
        CreateRequest {
            authorizer: s.authorizer.clone(),
            policy: s.policy_evaluator.clone(),
            request_reader: s.request_reader.clone(),
            request_writer: s.request_writer.clone(),
            db_registry: s.database_registry.clone(),
            schema_repo: s.schema_repo.clone(),
            dry_run_repo: s.dry_run_repo.clone(),
            context_repo: s.context_repo.clone(),
            uow: s.uow.clone(),
            notifier: s.notifier.clone(),
            audit_logger: s.audit_logger.clone(),
            break_glass_metrics: s.metrics.clone(),
            clock: s.clock.clone(),
            id_gen: s.id_generator.clone(),
            default_approval_ttl_secs: r.default_approval_ttl_secs,
        }
    }

    pub(crate) fn list(&self) -> ListRequests {
        let s = self.0;
        ListRequests {
            request_reader: s.request_reader.clone(),
            authorizer: s.authorizer.clone(),
        }
    }

    pub(crate) fn get(&self) -> GetRequest {
        let s = self.0;
        GetRequest {
            request_reader: s.request_reader.clone(),
            approval_repo: s.approval_repo.clone(),
            authorizer: s.authorizer.clone(),
            context_repo: s.context_repo.clone(),
        }
    }

    pub(crate) fn approve(&self) -> ApproveRequest {
        let s = self.0;
        ApproveRequest {
            authorizer: s.authorizer.clone(),
            request_reader: s.request_reader.clone(),
            approval_repo: s.approval_repo.clone(),
            uow: s.uow.clone(),
            notifier: s.notifier.clone(),
            clock: s.clock.clone(),
            id_gen: s.id_generator.clone(),
        }
    }

    pub(crate) fn reject(&self) -> RejectRequest {
        let s = self.0;
        RejectRequest {
            authorizer: s.authorizer.clone(),
            request_reader: s.request_reader.clone(),
            approval_repo: s.approval_repo.clone(),
            uow: s.uow.clone(),
            notifier: s.notifier.clone(),
            clock: s.clock.clone(),
            id_gen: s.id_generator.clone(),
        }
    }

    pub(crate) fn cancel(&self) -> CancelRequest {
        let s = self.0;
        CancelRequest {
            authorizer: s.authorizer.clone(),
            request_reader: s.request_reader.clone(),
            uow: s.uow.clone(),
            notifier: s.notifier.clone(),
            clock: s.clock.clone(),
            redaction_mode: dbward_app::services::audit_event_builder::RedactionMode::default(),
        }
    }

    pub(crate) fn resume(&self) -> ResumeRequest {
        let s = self.0;
        ResumeRequest {
            authorizer: s.authorizer.clone(),
            policy: s.policy_evaluator.clone(),
            request_reader: s.request_reader.clone(),
            uow: s.uow.clone(),
            result_channel: s.result_channel.clone(),
            notifier: s.notifier.clone(),
            policy_repo: s.policy_repo.clone(),
            clock: s.clock.clone(),
        }
    }

    pub(crate) fn stream_result(&self) -> StreamResult {
        let s = self.0;
        StreamResult {
            authorizer: s.authorizer.clone(),
            request_reader: s.request_reader.clone(),
            result_channel: s.result_channel.clone(),
            policy_repo: s.policy_repo.clone(),
        }
    }

    pub(crate) fn get_result(&self) -> GetResult {
        let s = self.0;
        GetResult {
            authorizer: s.authorizer.clone(),
            request_reader: s.request_reader.clone(),
            agent_repo: s.agent_repo.clone(),
            result_store: s.result_store.clone(),
            policy_repo: s.policy_repo.clone(),
            clock: s.clock.clone(),
        }
    }
}

/// Agent-related use cases.
pub(crate) struct AgentUseCases<'a>(&'a AppState);

impl<'a> AgentUseCases<'a> {
    pub(crate) fn poll(&self) -> AgentPoll {
        let s = self.0;
        AgentPoll {
            authorizer: s.authorizer.clone(),
            agent_repo: s.agent_repo.clone(),
            audit_logger: s.audit_logger.clone(),
            clock: s.clock.clone(),
        }
    }

    pub(crate) fn claim(&self) -> AgentClaim {
        let s = self.0;
        AgentClaim {
            authorizer: s.authorizer.clone(),
            request_reader: s.request_reader.clone(),
            agent_repo: s.agent_repo.clone(),
            policy: s.policy_evaluator.clone(),
            token_signer: s.token_signer.clone(),
            uow: s.uow.clone(),
            notifier: s.notifier.clone(),
            clock: s.clock.clone(),
            id_gen: s.id_generator.clone(),
            user_repo: s.user_repo.clone(),
            role_resolver: s.reloadable.load().role_resolver.clone(),
        }
    }

    pub(crate) fn heartbeat(&self) -> AgentHeartbeat {
        let s = self.0;
        AgentHeartbeat {
            authorizer: s.authorizer.clone(),
            agent_repo: s.agent_repo.clone(),
            request_reader: s.request_reader.clone(),
            policy: s.policy_evaluator.clone(),
            clock: s.clock.clone(),
        }
    }

    pub(crate) fn submit_result(&self) -> AgentSubmitResult {
        let s = self.0;
        AgentSubmitResult {
            authorizer: s.authorizer.clone(),
            agent_repo: s.agent_repo.clone(),
            request_reader: s.request_reader.clone(),
            result_store: s.result_store.clone(),
            result_channel: s.result_channel.clone(),
            notifier: s.notifier.clone(),
            uow: s.uow.clone(),
            clock: s.clock.clone(),
            max_persist_bytes: s.max_persist_bytes,
            policy_repo: s.policy_repo.clone(),
            storage_backend: s.storage_backend.clone(),
        }
    }

    pub(crate) fn schema_sync(&self) -> SchemaSync {
        let s = self.0;
        SchemaSync {
            agent_repo: s.agent_repo.clone(),
            schema_repo: s.schema_repo.clone(),
            database_registry: s.database_registry.clone(),
            audit_logger: s.audit_logger.clone(),
            clock: s.clock.clone(),
        }
    }

    pub(crate) fn dry_run_claim(&self) -> DryRunClaim {
        let s = self.0;
        DryRunClaim {
            dry_run_repo: s.dry_run_repo.clone(),
            agent_repo: s.agent_repo.clone(),
            clock: s.clock.clone(),
            id_gen: s.id_generator.clone(),
        }
    }

    pub(crate) fn dry_run_submit(&self) -> DryRunSubmitResult {
        let s = self.0;
        DryRunSubmitResult {
            dry_run_repo: s.dry_run_repo.clone(),
            context_repo: s.context_repo.clone(),
            clock: s.clock.clone(),
        }
    }

    pub(crate) fn agent_repo(&self) -> &Arc<dyn AgentRepo> {
        &self.0.agent_repo
    }

    pub(crate) fn dry_run_repo(&self) -> &Arc<dyn DryRunRepo> {
        &self.0.dry_run_repo
    }

    pub(crate) fn preflight_job_repo(&self) -> &Arc<dyn PreflightJobRepo> {
        &self.0.preflight_job_repo
    }

    pub(crate) fn preflight_notifier(&self) -> &Arc<crate::preflight_notifier::PreflightNotifier> {
        &self.0.preflight_notifier
    }
}

/// Admin use cases (policies, roles, webhooks, audit).
pub(crate) struct AdminUseCases<'a>(&'a AppState);

impl<'a> AdminUseCases<'a> {
    pub(crate) fn audit_query(&self) -> AuditQuery {
        let s = self.0;
        AuditQuery {
            authorizer: s.authorizer.clone(),
            audit_repo: s.audit_repo.clone(),
            audit_verifier: Some(s.audit_verifier.clone()),
        }
    }

    pub(crate) fn webhook_delivery_repo(
        &self,
    ) -> &Option<Arc<dyn dbward_app::ports::WebhookDeliveryRepo>> {
        &self.0.webhook_delivery_repo
    }
}

/// Token use cases.
pub(crate) struct TokenUseCases<'a>(&'a AppState);

impl<'a> TokenUseCases<'a> {
    pub(crate) fn manage(&self) -> TokenManage {
        let s = self.0;
        TokenManage {
            authorizer: s.authorizer.clone(),
            token_repo: s.token_repo.clone(),
            user_repo: s.user_repo.clone(),
            policy_repo: s.policy_repo.clone(),
            role_resolver: s.reloadable.load().role_resolver.clone(),
            license: s.license_checker.clone(),
            uow: s.uow.clone(),
            clock: s.clock.clone(),
            id_gen: s.id_generator.clone(),
            token_gen: s.token_value_generator.clone(),
            max_active_tokens_per_user: s.max_active_tokens_per_user,
        }
    }
}

/// Schema use cases.
pub(crate) struct SchemaUseCases<'a>(&'a AppState);

impl<'a> SchemaUseCases<'a> {
    pub(crate) fn get(&self) -> GetSchema {
        let s = self.0;
        GetSchema {
            database_registry: s.database_registry.clone(),
            schema_repo: s.schema_repo.clone(),
            authorizer: s.authorizer.clone(),
        }
    }
}

/// User use cases.
pub(crate) struct UserUseCases<'a>(&'a AppState);

impl<'a> UserUseCases<'a> {
    pub(crate) fn manage(&self) -> UserManage {
        let s = self.0;
        UserManage {
            authorizer: s.authorizer.clone(),
            user_repo: s.user_repo.clone(),
            group_repo: s.group_repo.clone(),
            token_repo: s.token_repo.clone(),
            uow: s.uow.clone(),
            clock: s.clock.clone(),
            license: s.license_checker.clone(),
            role_resolver: s.reloadable.load().role_resolver.clone(),
            policy_repo: s.policy_repo.clone(),
            id_gen: s.id_generator.clone(),
            token_gen: s.token_value_generator.clone(),
            notifier: s.notifier.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Factory + helper entry points
// ---------------------------------------------------------------------------

impl AppState {
    pub(crate) fn requests(&self) -> RequestUseCases<'_> {
        RequestUseCases(self)
    }

    pub(crate) fn agent(&self) -> AgentUseCases<'_> {
        AgentUseCases(self)
    }

    pub(crate) fn admin(&self) -> AdminUseCases<'_> {
        AdminUseCases(self)
    }

    pub(crate) fn tokens(&self) -> TokenUseCases<'_> {
        TokenUseCases(self)
    }

    pub(crate) fn users(&self) -> UserUseCases<'_> {
        UserUseCases(self)
    }

    pub(crate) fn schemas(&self) -> SchemaUseCases<'_> {
        SchemaUseCases(self)
    }

    pub(crate) fn preflight(&self) -> PreflightUseCase {
        PreflightUseCase {
            authorizer: self.authorizer.clone(),
            policy_evaluator: self.policy_evaluator.clone(),
            db_registry: self.database_registry.clone(),
            schema_repo: self.schema_repo.clone(),
            agent_repo: self.agent_repo.clone(),
            clock: self.clock.clone(),
            id_gen: self.id_generator.clone(),
            max_sql_length: self.max_persist_bytes,
        }
    }

    // --- Thin helpers ---

    pub(crate) fn list_databases(
        &self,
        user: &dbward_domain::auth::AuthUser,
    ) -> Result<
        Vec<(
            dbward_domain::values::DatabaseName,
            dbward_domain::values::Environment,
        )>,
        dbward_app::error::AppError,
    > {
        self.authorizer
            .authorize_global(user, dbward_domain::auth::Permission::RequestView)
            .map_err(dbward_app::error::AppError::Forbidden)?;
        self.database_registry.list_active()
    }

    pub(crate) fn render_metrics(
        &self,
        user: &dbward_domain::auth::AuthUser,
    ) -> Result<String, dbward_app::error::AppError> {
        self.authorizer
            .authorize_global(user, dbward_domain::auth::Permission::MetricsView)
            .map_err(dbward_app::error::AppError::Forbidden)?;
        Ok(crate::metrics::render(
            &self.metrics,
            self.request_reader.as_ref(),
            self.agent_repo.as_ref(),
            &self.session_store,
        ))
    }

    pub(crate) fn list_results_for_user(
        &self,
        user: &dbward_domain::auth::AuthUser,
        limit: u32,
    ) -> Result<Vec<dbward_app::ports::repos::StoredResultEntry>, dbward_app::error::AppError> {
        self.authorizer
            .authorize_global(user, dbward_domain::auth::Permission::ResultView)
            .map_err(dbward_app::error::AppError::Forbidden)?;
        self.request_reader.list_results_for_user(
            &user.subject_id,
            &user.groups,
            &user
                .roles
                .iter()
                .map(|r| r.name.clone())
                .collect::<Vec<_>>(),
            limit,
        )
    }

    pub(crate) fn token_signer(&self) -> &Arc<dyn TokenSigner> {
        &self.token_signer
    }

    #[allow(dead_code)]
    pub(crate) fn result_store(&self) -> &Arc<dyn ResultStore> {
        &self.result_store
    }

    pub(crate) fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    pub(crate) fn policy_evaluator(&self) -> &Arc<dyn PolicyEvaluator> {
        &self.policy_evaluator
    }

    pub(crate) fn request_reader(&self) -> &Arc<dyn RequestReader> {
        &self.request_reader
    }

    pub fn database_registry(&self) -> &Arc<dyn DatabaseRegistry> {
        &self.database_registry
    }

    #[allow(dead_code)]
    pub(crate) fn schema_repo(&self) -> &Arc<dyn SchemaRepo> {
        &self.schema_repo
    }

    pub(crate) fn uow(&self) -> &Arc<dyn UnitOfWork> {
        &self.uow
    }

    // --- Background access ---

    pub(crate) fn background(&self) -> BackgroundAccess<'_> {
        BackgroundAccess(self)
    }

    // --- Auth middleware access ---
    pub(crate) fn user_repo(&self) -> &Arc<dyn UserRepo> {
        &self.user_repo
    }

    pub(crate) fn group_repo(&self) -> &Arc<dyn GroupRepo> {
        &self.group_repo
    }

    pub(crate) fn onboarding_repo(&self) -> &Arc<dyn dbward_app::ports::OnboardingRequestRepo> {
        &self.onboarding_repo
    }

    #[allow(dead_code)]
    pub(crate) fn db_conn(&self) -> &dbward_infra::sqlite::DbConn {
        &self.db_conn
    }

    pub(crate) fn id_gen(&self) -> &Arc<dyn IdGenerator> {
        &self.id_generator
    }

    pub(crate) fn token_value_generator(&self) -> &Arc<dyn dbward_app::ports::TokenValueGenerator> {
        &self.token_value_generator
    }
}

// ---------------------------------------------------------------------------
// BackgroundAccess — scoped access for background tasks
// ---------------------------------------------------------------------------

pub(crate) struct BackgroundAccess<'a>(&'a AppState);

impl<'a> BackgroundAccess<'a> {
    pub(crate) fn clock(&self) -> &Arc<dyn Clock> {
        &self.0.clock
    }
    pub(crate) fn request_reader(&self) -> &Arc<dyn RequestReader> {
        &self.0.request_reader
    }
    pub(crate) fn agent_repo(&self) -> &Arc<dyn AgentRepo> {
        &self.0.agent_repo
    }
    pub(crate) fn background_task_repo(&self) -> &Arc<dyn BackgroundTaskRepo> {
        &self.0.background_task_repo
    }
    pub(crate) fn uow(&self) -> &Arc<dyn UnitOfWork> {
        &self.0.uow
    }
    pub(crate) fn audit_signer(&self) -> &Arc<dyn dbward_app::ports::crypto::AuditSigner> {
        &self.0.audit_signer
    }
    pub(crate) fn audit_repo(&self) -> &Arc<dyn AuditRepo> {
        &self.0.audit_repo
    }
    pub(crate) fn token_repo(&self) -> &Arc<dyn TokenRepo> {
        &self.0.token_repo
    }
    pub(crate) fn notifier(&self) -> &Arc<dyn Notifier> {
        &self.0.notifier
    }
    pub(crate) fn webhook_sender(&self) -> &Arc<dyn dbward_app::ports::WebhookSender> {
        &self.0.webhook_sender
    }
    pub(crate) fn webhook_delivery_repo(
        &self,
    ) -> &Option<Arc<dyn dbward_app::ports::WebhookDeliveryRepo>> {
        &self.0.webhook_delivery_repo
    }
    pub(crate) fn webhook_repo(&self) -> Option<&Arc<dyn WebhookRepo>> {
        Some(&self.0.webhook_repo)
    }
    pub(crate) fn result_store(&self) -> &Arc<dyn ResultStore> {
        &self.0.result_store
    }
    pub(crate) fn dry_run_repo(&self) -> &Arc<dyn DryRunRepo> {
        &self.0.dry_run_repo
    }
    pub(crate) fn preflight_job_repo(&self) -> &Arc<dyn PreflightJobRepo> {
        &self.0.preflight_job_repo
    }
    pub(crate) fn context_repo(&self) -> &Arc<dyn ContextRepo> {
        &self.0.context_repo
    }
    pub fn license_checker(&self) -> &Arc<dyn LicenseChecker> {
        &self.0.license_checker
    }
    #[cfg(feature = "commercial")]
    pub fn license_checker_impl(
        &self,
    ) -> Option<&Arc<dbward_commercial_license::LicenseCheckerImpl>> {
        self.0.license_checker_impl.as_ref()
    }
    pub fn persist_validated_until(
        &self,
        ts: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), dbward_app::error::AppError> {
        if let Some(repo) = &self.0.server_meta_repo {
            repo.set("license_validated_until", &ts.to_rfc3339())?;
        }
        Ok(())
    }
    pub fn persist_grace_days(&self, days: u32) -> Result<(), dbward_app::error::AppError> {
        if let Some(repo) = &self.0.server_meta_repo {
            repo.set("license_grace_days", &days.to_string())?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Bootstrap access (pub(crate) for lib.rs)
// ---------------------------------------------------------------------------

impl AppState {
    pub(crate) fn token_repo(&self) -> &Arc<dyn TokenRepo> {
        &self.token_repo
    }
    pub(crate) fn authorizer(&self) -> &Arc<dyn Authorizer> {
        &self.authorizer
    }
    #[allow(dead_code)] // Used in hot reload (Phase 4)
    pub(crate) fn notifier(&self) -> &Arc<dyn Notifier> {
        &self.notifier
    }
    pub(crate) fn policy_repo(&self) -> &Arc<dyn PolicyRepo> {
        &self.policy_repo
    }
    pub(crate) fn webhook_repo(&self) -> &Arc<dyn WebhookRepo> {
        &self.webhook_repo
    }
    pub(crate) fn id_generator(&self) -> &Arc<dyn IdGenerator> {
        &self.id_generator
    }
    pub(crate) fn audit_logger(&self) -> &Arc<dyn AuditLogger> {
        &self.audit_logger
    }
    pub fn license_checker(&self) -> &Arc<dyn LicenseChecker> {
        &self.license_checker
    }
    pub(crate) fn result_channel(&self) -> &Arc<dyn ResultChannel> {
        &self.result_channel
    }

    pub(crate) fn session_store(&self) -> &Arc<crate::session_store::SessionStore> {
        &self.session_store
    }
}

// ---------------------------------------------------------------------------
// Test Builder
// ---------------------------------------------------------------------------

/// Builder for constructing AppState in tests and integration scenarios.
pub struct AppStateBuilder {
    pub token_verifier: Arc<dyn TokenVerifier>,
    pub reloadable: Arc<ArcSwap<ReloadableConfig>>,
    pub authorizer: Arc<dyn Authorizer>,
    pub request_reader: Arc<dyn RequestReader>,
    pub request_writer: Arc<dyn RequestWriter>,
    pub approval_repo: Arc<dyn ApprovalRepo>,
    pub background_task_repo: Arc<dyn BackgroundTaskRepo>,
    pub agent_repo: Arc<dyn AgentRepo>,
    pub user_repo: Arc<dyn UserRepo>,
    pub group_repo: Arc<dyn GroupRepo>,
    pub onboarding_repo: Arc<dyn dbward_app::ports::OnboardingRequestRepo>,
    pub token_repo: Arc<dyn TokenRepo>,
    pub webhook_repo: Arc<dyn WebhookRepo>,
    pub policy_repo: Arc<dyn PolicyRepo>,
    pub database_registry: Arc<dyn DatabaseRegistry>,
    pub schema_repo: Arc<dyn SchemaRepo>,
    pub dry_run_repo: Arc<dyn DryRunRepo>,
    pub context_repo: Arc<dyn ContextRepo>,
    pub audit_logger: Arc<dyn AuditLogger>,
    pub audit_repo: Arc<dyn AuditRepo>,
    pub policy_evaluator: Arc<dyn PolicyEvaluator>,
    pub result_store: Arc<dyn ResultStore>,
    pub result_channel: Arc<dyn ResultChannel>,
    pub token_signer: Arc<dyn TokenSigner>,
    pub notifier: Arc<dyn Notifier>,
    pub webhook_sender: Arc<dyn dbward_app::ports::WebhookSender>,
    pub ssrf_validator: Arc<dyn SsrfValidator>,
    pub license_checker: Arc<dyn LicenseChecker>,
    #[cfg(feature = "commercial")]
    pub license_checker_impl: Option<Arc<dbward_commercial_license::LicenseCheckerImpl>>,
    pub server_meta_repo: Option<Arc<dyn dbward_app::ports::ServerMetaRepo>>,
    pub clock: Arc<dyn Clock>,
    pub id_generator: Arc<dyn IdGenerator>,
    pub token_value_generator: Arc<dyn dbward_app::ports::TokenValueGenerator>,
    pub webhook_delivery_repo: Option<Arc<dyn dbward_app::ports::WebhookDeliveryRepo>>,
    pub uow: Arc<dyn dbward_app::ports::UnitOfWork>,
    pub audit_signer: Arc<dyn dbward_app::ports::crypto::AuditSigner>,
    pub audit_verifier: Arc<dyn dbward_app::ports::crypto::AuditVerifier>,
    pub metrics: Arc<Metrics>,
    pub max_persist_bytes: usize,
    pub accept_oidc: bool,
    pub storage_backend: String,
    pub max_active_tokens_per_user: u32,
    pub draining: Arc<AtomicBool>,
    pub preflight_job_repo: Arc<dyn PreflightJobRepo>,
    pub preflight_notifier: Arc<crate::preflight_notifier::PreflightNotifier>,
    pub preflight_max_concurrent_per_user: u32,
    pub preflight_max_explain_timeout_ms: u64,
    pub slack_config: Option<dbward_infra::slack::SlackConfig>,
    pub slack_client: Option<Arc<dyn dbward_infra::slack::SlackClient>>,
    pub slack_onboarding: Option<dbward_config::server::SlackOnboardingConfig>,
    pub db_conn: dbward_infra::sqlite::DbConn,
    pub db_role_resolver: Option<Arc<dbward_infra::auth::DbRoleResolver>>,
    #[allow(dead_code)]
    pub mcp_enabled: bool,
    #[allow(dead_code)]
    pub mcp_allowed_origins: Vec<String>,
    #[allow(dead_code)]
    pub mcp_default_database: String,
    #[allow(dead_code)]
    pub mcp_default_environment: String,
    pub mcp_elicitation_timeout_secs: u64,
    pub mcp_replay_buffer_size: usize,
    pub session_store: Arc<crate::session_store::SessionStore>,
}

impl AppStateBuilder {
    pub fn build(self) -> AppState {
        AppState {
            reloadable: self.reloadable,
            token_verifier: self.token_verifier,
            authorizer: self.authorizer,
            request_reader: self.request_reader,
            request_writer: self.request_writer,
            approval_repo: self.approval_repo,
            background_task_repo: self.background_task_repo,
            agent_repo: self.agent_repo,
            user_repo: self.user_repo,
            group_repo: self.group_repo,
            onboarding_repo: self.onboarding_repo,
            token_repo: self.token_repo,
            webhook_repo: self.webhook_repo,
            policy_repo: self.policy_repo,
            database_registry: self.database_registry,
            schema_repo: self.schema_repo,
            dry_run_repo: self.dry_run_repo,
            context_repo: self.context_repo,
            audit_logger: self.audit_logger,
            audit_repo: self.audit_repo,
            policy_evaluator: self.policy_evaluator,
            result_store: self.result_store,
            result_channel: self.result_channel,
            token_signer: self.token_signer,
            notifier: self.notifier,
            webhook_sender: self.webhook_sender,
            ssrf_validator: self.ssrf_validator,
            license_checker: self.license_checker,
            #[cfg(feature = "commercial")]
            license_checker_impl: self.license_checker_impl,
            server_meta_repo: self.server_meta_repo,
            clock: self.clock,
            id_generator: self.id_generator,
            token_value_generator: self.token_value_generator,
            webhook_delivery_repo: self.webhook_delivery_repo,
            uow: self.uow,
            audit_signer: self.audit_signer,
            audit_verifier: self.audit_verifier,
            metrics: self.metrics,
            max_persist_bytes: self.max_persist_bytes,
            accept_oidc: self.accept_oidc,
            storage_backend: self.storage_backend,
            max_active_tokens_per_user: self.max_active_tokens_per_user,
            draining: self.draining,
            preflight_job_repo: self.preflight_job_repo,
            preflight_notifier: self.preflight_notifier,
            preflight_max_concurrent_per_user: self.preflight_max_concurrent_per_user,
            preflight_max_explain_timeout_ms: self.preflight_max_explain_timeout_ms,
            slack_config: self.slack_config,
            slack_client: self.slack_client,
            slack_onboarding: self.slack_onboarding,
            db_conn: self.db_conn,
            db_role_resolver: self.db_role_resolver,
            mcp_enabled: self.mcp_enabled,
            mcp_allowed_origins: self.mcp_allowed_origins,
            mcp_default_database: self.mcp_default_database,
            mcp_default_environment: self.mcp_default_environment,
            mcp_elicitation_timeout_secs: self.mcp_elicitation_timeout_secs,
            mcp_replay_buffer_size: self.mcp_replay_buffer_size,
            session_store: self.session_store,
        }
    }
}

#[cfg(test)]
impl AppState {
    pub fn builder() -> AppStateBuilder {
        // Requires all fields to be explicitly set — no defaults
        // This is intentional: forces tests to be explicit about dependencies
        panic!("Use AppStateBuilder {{ field: value, .. }} directly")
    }
}
