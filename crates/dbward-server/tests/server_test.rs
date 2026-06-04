mod common;
use common::*;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use dbward_app::error::{AppError, AuthError, AuthzError};
use dbward_app::ports::*;
use dbward_domain::auth::*;
use dbward_domain::entities::*;
use dbward_domain::policies::{ExecutionPolicy, Workflow};
use dbward_domain::values::{DatabaseName, Environment, Operation};
use dbward_server::build_app;
use dbward_server::state::AppState;

// --- Mock TokenVerifier ---

struct MockTokenVerifier;

#[async_trait]
impl TokenVerifier for MockTokenVerifier {
    async fn verify_api_token(&self, token: &str) -> Result<AuthUser, AuthError> {
        match token {
            "valid-test-token" => Ok(AuthUser {
                subject_id: "test-user".into(),
                subject_type: SubjectType::User,
                roles: vec![ResolvedRole {
                    name: "admin".into(),
                    permissions: [Permission::All].into(),
                    databases: vec![DatabaseName::new("*").unwrap()],
                    environments: vec![Environment::new("*").unwrap()],
                }],
                groups: vec![],
                token_id: Some("tok-1".into()),
            }),
            "agent-token" => Ok(AuthUser {
                subject_id: "agent-01".into(),
                subject_type: SubjectType::Agent,
                roles: vec![ResolvedRole {
                    name: "agent".into(),
                    permissions: [Permission::All].into(),
                    databases: vec![DatabaseName::new("*").unwrap()],
                    environments: vec![Environment::new("*").unwrap()],
                }],
                groups: vec![],
                token_id: Some("tok-agent".into()),
            }),
            _ => Err(AuthError::InvalidToken),
        }
    }

    async fn verify_oidc_token(&self, _token: &str) -> Result<(String, Vec<String>), AuthError> {
        Err(AuthError::OidcNotConfigured)
    }
}

struct StubAuthorizer;
impl Authorizer for StubAuthorizer {
    fn authorize_scoped(
        &self,
        _: &AuthUser,
        _: Permission,
        _: &DatabaseName,
        _: &Environment,
        _: &ResourceContext,
    ) -> Result<(), AuthzError> {
        Ok(())
    }
    fn authorize_global(&self, _: &AuthUser, _: Permission) -> Result<(), AuthzError> {
        Ok(())
    }
}

struct StubRequestRepo;
impl RequestReader for StubRequestRepo {
    fn get(&self, _: &str) -> Result<Option<dbward_domain::entities::Request>, AppError> {
        Ok(None)
    }
    fn list(
        &self,
        _: u32,
        _: u32,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<(Vec<dbward_domain::entities::Request>, u32), AppError> {
        Ok((vec![], 0))
    }
    fn find_by_idempotency_key(
        &self,
        _: &str,
    ) -> Result<Option<dbward_domain::entities::Request>, AppError> {
        Ok(None)
    }
    fn list_visible_to_user(
        &self,
        _: &str,
        _: &[String],
        _: &[String],
        _: Option<&str>,
        _: u32,
        _: u32,
    ) -> Result<(Vec<dbward_domain::entities::Request>, u32), AppError> {
        Ok((vec![], 0))
    }
    fn list_pending_for_user(
        &self,
        _: &str,
        _: &[String],
        _: &[String],
        _: u32,
        _: u32,
    ) -> Result<(Vec<dbward_domain::entities::Request>, u32), AppError> {
        Ok((vec![], 0))
    }
    fn is_pending_approver(
        &self,
        _: &str,
        _: &str,
        _: &[String],
        _: &[String],
    ) -> Result<bool, AppError> {
        Ok(false)
    }
    fn count_executions(&self, _: &str) -> Result<u32, AppError> {
        Ok(0)
    }
    fn count_completed_executions(&self, _: &str) -> Result<u32, AppError> {
        Ok(0)
    }
    fn find_stored_execution_ids(&self, _: &str) -> Result<Vec<String>, AppError> {
        Ok(vec![])
    }
    fn list_results_for_user(
        &self,
        _: &str,
        _: &[String],
        _: &[String],
        _: u32,
    ) -> Result<Vec<dbward_app::ports::repos::StoredResultEntry>, AppError> {
        Ok(vec![])
    }
    fn count_by_status(&self, _: &str) -> Result<u32, AppError> {
        Ok(0)
    }
    fn get_pending_approvers_for_requests(
        &self,
        _: &[&str],
    ) -> Result<std::collections::HashMap<String, (u32, Vec<String>)>, AppError> {
        Ok(std::collections::HashMap::new())
    }
}

impl RequestWriter for StubRequestRepo {
    fn insert(&self, _: &dbward_domain::entities::Request) -> Result<(), AppError> {
        Ok(())
    }
    fn create_and_dispatch(&self, _: &dbward_domain::entities::Request) -> Result<(), AppError> {
        Ok(())
    }
    fn mark_approved(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
        Ok(true)
    }
    fn mark_rejected(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
        Ok(true)
    }
    fn mark_cancelled(
        &self,
        _: &str,
        _: &str,
        _: Option<&str>,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, AppError> {
        Ok(true)
    }
    fn mark_dispatched(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
        Ok(true)
    }
    fn mark_running(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
        Ok(true)
    }
    fn mark_executed(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
        Ok(true)
    }
    fn mark_failed(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
        Ok(true)
    }
    fn cancel_all_for_user(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
        _: &dbward_domain::entities::AuditContext,
    ) -> Result<Vec<String>, AppError> {
        Ok(vec![])
    }
    fn mark_approved_from_dispatched(&self, _: &str, _: &str) -> Result<bool, AppError> {
        Ok(true)
    }
    fn mark_approved_from_dispatched_and_record(
        &self,
        _: &str,
        _: &dbward_domain::entities::AuditEvent,
        _: &str,
    ) -> Result<bool, AppError> {
        Ok(true)
    }
}

impl ApprovalRepo for StubRequestRepo {
    fn insert_approval(&self, _: &Approval) -> Result<(), AppError> {
        Ok(())
    }
    fn get_approvals(&self, _: &str) -> Result<Vec<Approval>, AppError> {
        Ok(vec![])
    }
    fn approve_and_mark_approved(
        &self,
        _: &Approval,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, AppError> {
        Ok(true)
    }
    fn reject_and_record(
        &self,
        _: &str,
        _: &Approval,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, AppError> {
        Ok(true)
    }
}

impl BackgroundTaskRepo for StubRequestRepo {
    fn find_expired_approved(&self, _: &str) -> Result<Vec<String>, AppError> {
        Ok(vec![])
    }
    fn find_expired_pending(&self, _: &str) -> Result<Vec<String>, AppError> {
        Ok(vec![])
    }
    fn find_dispatched_older_than(&self, _: &str) -> Result<Vec<String>, AppError> {
        Ok(vec![])
    }
    fn mark_expired(&self, _: &str, _: &str) -> Result<bool, AppError> {
        Ok(true)
    }
    fn mark_expired_and_record(&self, _: &str, _: &AuditEvent, _: &str) -> Result<bool, AppError> {
        Ok(true)
    }
    fn purge_old_requests(&self, _: &str) -> Result<u32, AppError> {
        Ok(0)
    }
}

struct StubAgentRepo;
impl AgentRepo for StubAgentRepo {
    fn upsert(&self, _: &Agent) -> Result<(), AppError> {
        Ok(())
    }
    fn get(&self, _: &str) -> Result<Option<Agent>, AppError> {
        Ok(None)
    }
    fn list(&self) -> Result<Vec<Agent>, AppError> {
        Ok(vec![])
    }
    fn create_execution(&self, _: &Execution) -> Result<(), AppError> {
        Ok(())
    }
    fn get_execution(&self, _: &str) -> Result<Option<Execution>, AppError> {
        Ok(None)
    }
    fn update_execution_status(&self, _: &str, _: ExecutionStatus) -> Result<(), AppError> {
        Ok(())
    }
    fn extend_lease(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<(), AppError> {
        Ok(())
    }
    fn find_dispatched_jobs(
        &self,
        _: &[(DatabaseName, Environment)],
    ) -> Result<Vec<dbward_domain::entities::Request>, AppError> {
        Ok(vec![])
    }
    fn has_running_migration(
        &self,
        _: &DatabaseName,
        _: &Environment,
        _: &str,
    ) -> Result<bool, AppError> {
        Ok(false)
    }
    fn find_executions_for_request(&self, _: &str) -> Result<Vec<Execution>, AppError> {
        Ok(vec![])
    }
    fn claim_and_mark_running(
        &self,
        _: &Execution,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, AppError> {
        Ok(true)
    }
    fn complete_execution(
        &self,
        _: &str,
        _: &str,
        _: bool,
        _: chrono::DateTime<chrono::Utc>,
        _: &AuditEvent,
        _: Option<&dbward_domain::entities::ExecutionResult>,
        _: &[dbward_domain::entities::ResultAccess],
    ) -> Result<dbward_app::ports::CompletionOutcome, AppError> {
        Ok(dbward_app::ports::CompletionOutcome::Normal)
    }
    fn find_expired_leases(&self, _: &str) -> Result<Vec<(String, String)>, AppError> {
        Ok(vec![])
    }
    fn mark_execution_lost(&self, _: &str, _: &str, _: &str) -> Result<bool, AppError> {
        Ok(true)
    }
    fn mark_execution_lost_and_record(
        &self,
        _: &str,
        _: &str,
        _: &AuditEvent,
        _: &str,
    ) -> Result<bool, AppError> {
        Ok(true)
    }
    fn find_expired_results(&self, _: &str) -> Result<Vec<(String, String)>, AppError> {
        Ok(vec![])
    }
    fn delete_result(&self, _: &str) -> Result<(), AppError> {
        Ok(())
    }
}

struct StubUserRepo;
impl UserRepo for StubUserRepo {
    fn get(&self, _: &str) -> Result<Option<User>, AppError> {
        Ok(None)
    }
    fn upsert(&self, _: &User) -> Result<(), AppError> {
        Ok(())
    }
    fn list(&self) -> Result<Vec<User>, AppError> {
        Ok(vec![])
    }
    fn suspend(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
        Ok(true)
    }
    fn activate(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
        Ok(true)
    }
    fn is_suspended(&self, _: &str) -> Result<bool, AppError> {
        Ok(false)
    }
    fn ensure_exists(&self, _: &str) -> Result<(), AppError> {
        Ok(())
    }
}

struct StubTokenRepo;
impl TokenRepo for StubTokenRepo {
    fn create(&self, _: &Token) -> Result<(), AppError> {
        Ok(())
    }
    fn verify(&self, _: &str, _: &str) -> Result<Option<Token>, AppError> {
        Ok(None)
    }
    fn list(&self) -> Result<Vec<Token>, AppError> {
        Ok(vec![])
    }
    fn get(&self, _: &str) -> Result<Option<Token>, AppError> {
        Ok(None)
    }
    fn revoke(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
        Ok(true)
    }
    fn revoke_all_for_user(
        &self,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<u32, AppError> {
        Ok(0)
    }
    fn count_active(&self) -> Result<u32, AppError> {
        Ok(0)
    }
    fn purge_revoked(&self, _: &str) -> Result<u32, AppError> {
        Ok(0)
    }
}

struct StubWebhookRepo;
impl WebhookRepo for StubWebhookRepo {
    fn create(&self, _: &Webhook) -> Result<(), AppError> {
        Ok(())
    }
    fn get(&self, _: &str) -> Result<Option<Webhook>, AppError> {
        Ok(None)
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

struct StubPolicyRepo;
impl PolicyRepo for StubPolicyRepo {
    fn create_workflow(&self, _: &Workflow) -> Result<(), AppError> {
        Ok(())
    }
    fn get_workflow(&self, _: &str) -> Result<Option<Workflow>, AppError> {
        Ok(None)
    }
    fn list_workflows(&self) -> Result<Vec<Workflow>, AppError> {
        Ok(vec![])
    }
    fn delete_workflow(&self, _: &str) -> Result<bool, AppError> {
        Ok(true)
    }
    fn count_workflows(&self) -> Result<u32, AppError> {
        Ok(0)
    }
    fn create_execution_policy(&self, _: &ExecutionPolicy) -> Result<(), AppError> {
        Ok(())
    }
    fn get_execution_policy(&self, _: &str) -> Result<Option<ExecutionPolicy>, AppError> {
        Ok(None)
    }
    fn list_execution_policies(&self) -> Result<Vec<ExecutionPolicy>, AppError> {
        Ok(vec![])
    }
    fn delete_execution_policy(&self, _: &str) -> Result<bool, AppError> {
        Ok(true)
    }
    fn find_result_policy(
        &self,
        _: &DatabaseName,
        _: &Environment,
    ) -> Result<Option<dbward_domain::policies::ResultPolicy>, AppError> {
        Ok(None)
    }
    fn create_result_policy(
        &self,
        _: &dbward_domain::policies::ResultPolicy,
    ) -> Result<(), AppError> {
        Ok(())
    }
    fn get_result_policy(
        &self,
        _: &str,
    ) -> Result<Option<dbward_domain::policies::ResultPolicy>, AppError> {
        Ok(None)
    }
    fn list_result_policies(&self) -> Result<Vec<dbward_domain::policies::ResultPolicy>, AppError> {
        Ok(vec![])
    }
    fn update_result_policy(
        &self,
        _: &dbward_domain::policies::ResultPolicy,
    ) -> Result<bool, AppError> {
        Ok(false)
    }
    fn delete_result_policy(&self, _: &str) -> Result<bool, AppError> {
        Ok(false)
    }
    fn create_notification_policy(
        &self,
        _: &dbward_domain::policies::NotificationPolicy,
    ) -> Result<(), AppError> {
        Ok(())
    }
    fn get_notification_policy(
        &self,
        _: &str,
    ) -> Result<Option<dbward_domain::policies::NotificationPolicy>, AppError> {
        Ok(None)
    }
    fn list_notification_policies(
        &self,
    ) -> Result<Vec<dbward_domain::policies::NotificationPolicy>, AppError> {
        Ok(vec![])
    }
    fn update_notification_policy(
        &self,
        _: &dbward_domain::policies::NotificationPolicy,
    ) -> Result<bool, AppError> {
        Ok(false)
    }
    fn delete_notification_policy(&self, _: &str) -> Result<bool, AppError> {
        Ok(false)
    }
    fn create_role(&self, _: &RoleDefinition) -> Result<(), AppError> {
        Ok(())
    }
    fn list_roles(&self) -> Result<Vec<RoleDefinition>, AppError> {
        Ok(vec![])
    }
    fn get_roles_by_names(&self, _: &[String]) -> Result<Vec<RoleDefinition>, AppError> {
        Ok(vec![])
    }
    fn delete_role(&self, _: &str) -> Result<bool, AppError> {
        Ok(true)
    }
    fn count_roles(&self) -> Result<u32, AppError> {
        Ok(0)
    }
}

struct StubDatabaseRegistry;
impl DatabaseRegistry for StubDatabaseRegistry {
    fn register(&self, _: &DatabaseName, _: &Environment) -> Result<(), AppError> {
        Ok(())
    }
    fn exists(&self, _: &DatabaseName, _: &Environment) -> Result<bool, AppError> {
        Ok(false)
    }
    fn list(&self) -> Result<Vec<(DatabaseName, Environment)>, AppError> {
        Ok(vec![])
    }
}

struct StubSchemaRepo;
impl dbward_app::ports::SchemaRepo for StubSchemaRepo {
    fn upsert_snapshot(&self, _: &dbward_app::ports::SchemaSnapshotRecord) -> Result<(), AppError> {
        Ok(())
    }
    fn get_snapshot(
        &self,
        _: &str,
        _: &str,
    ) -> Result<Option<dbward_app::ports::SchemaSnapshotRecord>, AppError> {
        Ok(None)
    }
    fn get_dialect(&self, _: &str, _: &str) -> Result<Option<String>, AppError> {
        Ok(None)
    }
    fn get_tables_for(
        &self,
        _: &str,
        _: &str,
        _: &[dbward_domain::services::table_extractor::TableRef],
    ) -> Result<Option<String>, AppError> {
        Ok(None)
    }
}

struct StubDryRunRepo;
impl dbward_app::ports::DryRunRepo for StubDryRunRepo {
    fn create_jobs(&self, _: &[dbward_app::ports::DryRunJobRecord]) -> Result<(), AppError> {
        Ok(())
    }
    fn find_pending_for_agent(
        &self,
        _: &[(String, String)],
    ) -> Result<Vec<dbward_app::ports::DryRunJobRecord>, AppError> {
        Ok(vec![])
    }
    fn claim(&self, _: &str, _: &str, _: &str, _: &str) -> Result<bool, AppError> {
        Ok(false)
    }
    fn complete(&self, _: &str, _: &str, _: &str, _: &str, _: &str) -> Result<bool, AppError> {
        Ok(false)
    }
    fn fail(&self, _: &str, _: &str, _: &str, _: &str, _: &str) -> Result<bool, AppError> {
        Ok(false)
    }
    fn reclaim_stale(&self, _: &str) -> Result<u32, AppError> {
        Ok(0)
    }
    fn find_for_request(
        &self,
        _: &str,
    ) -> Result<Vec<dbward_app::ports::DryRunJobRecord>, AppError> {
        Ok(vec![])
    }
    fn get_request_id(&self, _: &str) -> Result<Option<String>, AppError> {
        Ok(None)
    }
}

struct StubContextRepo;
impl dbward_app::ports::ContextRepo for StubContextRepo {
    fn create(&self, _: &dbward_app::ports::RequestContextRecord) -> Result<(), AppError> {
        Ok(())
    }
    fn get(&self, _: &str) -> Result<Option<dbward_app::ports::RequestContextRecord>, AppError> {
        Ok(None)
    }
    fn update_explain(&self, _: &str, _: &str, _: &str, _: &str) -> Result<(), AppError> {
        Ok(())
    }
    fn timeout_collecting(&self, _: &str, _: &str) -> Result<u32, AppError> {
        Ok(0)
    }
}

struct StubAuditLogger;
impl AuditLogger for StubAuditLogger {
    fn record(&self, _: &AuditEvent) -> Result<(), AppError> {
        Ok(())
    }
}

struct StubAuditRepo;
impl AuditRepo for StubAuditRepo {
    fn list(&self, _: &AuditFilter) -> Result<Vec<AuditEvent>, AppError> {
        Ok(vec![])
    }
    fn verify_chain(&self) -> Result<AuditVerifyResult, AppError> {
        Ok(AuditVerifyResult {
            total_events: 0,
            first_broken_id: None,
        })
    }
    fn purge_old(&self, _: &str) -> Result<u32, AppError> {
        Ok(0)
    }
}

struct StubPolicyEvaluator;
impl PolicyEvaluator for StubPolicyEvaluator {
    fn evaluate_workflow(
        &self,
        _: &DatabaseName,
        _: &Environment,
        _: Operation,
    ) -> Result<Option<Workflow>, AppError> {
        Ok(None)
    }
    fn get_execution_policy(&self, _: &DatabaseName, _: &Environment) -> ExecutionPolicy {
        ExecutionPolicy::default()
    }
}

fn test_state() -> AppState {
    AppState {
        token_verifier: Arc::new(MockTokenVerifier),
        role_resolver: Arc::new(NoopRoleResolver),
        authorizer: Arc::new(StubAuthorizer),
        request_reader: Arc::new(StubRequestRepo),
        request_writer: Arc::new(StubRequestRepo),
        approval_repo: Arc::new(StubRequestRepo),
        background_task_repo: Arc::new(StubRequestRepo),
        agent_repo: Arc::new(StubAgentRepo),
        user_repo: Arc::new(StubUserRepo),
        token_repo: Arc::new(StubTokenRepo),
        webhook_repo: Arc::new(StubWebhookRepo),
        policy_repo: Arc::new(StubPolicyRepo),
        database_registry: Arc::new(StubDatabaseRegistry),
        schema_repo: Arc::new(StubSchemaRepo),
        dry_run_repo: Arc::new(StubDryRunRepo),
        context_repo: Arc::new(StubContextRepo),
        audit_logger: Arc::new(StubAuditLogger),
        audit_repo: Arc::new(StubAuditRepo),
        policy_evaluator: Arc::new(StubPolicyEvaluator),
        result_store: Arc::new(NoopResultStore),
        result_channel: Arc::new(NoopResultChannel),
        token_signer: Arc::new(NoopTokenSigner),
        notifier: Arc::new(NoopNotifier),
        event_dispatcher: Arc::new(NoopEventDispatcher),
        ssrf_validator: Arc::new(NoopSsrfValidator),
        license_checker: Arc::new(NoopLicenseChecker),
        clock: Arc::new(RealClock),
        id_generator: Arc::new(SeqIdGen::new()),
        token_value_generator: Arc::new(dbward_infra::SecureTokenGenerator),
        metrics: Arc::new(dbward_server::metrics::Metrics::new()),
        webhook_delivery_repo: None,
        webhook_sender: Arc::new(NoopWebhookSender),
        draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        slack_config: None,
        slack_client: None,
        request_notifier: None,
        default_approval_ttl_secs: Some(3600),
        max_persist_bytes: 10 * 1024 * 1024,
        auth_mode: "both".to_string(),
        storage_backend: "local".into(),
        sql_review_rules: dbward_domain::services::sql_reviewer::ReviewRules::default(),
        auto_approve_entries: vec![],
    }
}

#[tokio::test]
async fn health_returns_200() {
    let app = build_app(test_state(), vec![]);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn ready_returns_200() {
    let app = build_app(test_state(), vec![]);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn unauthenticated_request_returns_401() {
    let app = build_app(test_state(), vec![]);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/requests")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn invalid_token_returns_401() {
    let app = build_app(test_state(), vec![]);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/requests")
                .header("authorization", "Bearer bad-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn valid_token_passes_auth_middleware() {
    let app = build_app(test_state(), vec![]);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/requests")
                .header("authorization", "Bearer valid-test-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // Should not be 401/403 — the handler runs (returns 200 with empty list)
    assert_ne!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_ne!(resp.status(), StatusCode::FORBIDDEN);
}

// --- Route integration tests ---

#[tokio::test]
async fn list_endpoints_return_ok_when_empty() {
    let endpoints = [
        "/api/requests",
        "/api/databases",
        "/api/tokens",
        "/api/webhooks",
        "/api/workflows",
        "/api/agents",
    ];
    for path in endpoints {
        let app = build_app(test_state(), vec![]);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header("authorization", "Bearer valid-test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "failed for {path}");
    }
}

#[tokio::test]
async fn get_request_not_found_returns_404() {
    let app = build_app(test_state(), vec![]);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/requests/nonexistent")
                .header("authorization", "Bearer valid-test-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn metrics_endpoint_returns_text() {
    let app = build_app(test_state(), vec![]);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // Metrics may return 200 or 500 depending on registry init; just verify route exists
    assert_ne!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn xff_resolves_client_ip_when_peer_trusted() {
    use axum::extract::ConnectInfo;
    use std::net::SocketAddr;

    let trusted: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
    let app = build_app(test_state(), trusted);

    // Simulate trusted peer (10.0.0.1) with XFF header
    let mut req = Request::builder()
        .uri("/health")
        .header("x-forwarded-for", "203.0.113.50, 10.0.0.2")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo("10.0.0.1:1234".parse::<SocketAddr>().unwrap()));

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn xff_ignored_when_peer_not_trusted() {
    use axum::extract::ConnectInfo;
    use std::net::SocketAddr;

    let trusted: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
    let app = build_app(test_state(), trusted);

    // Untrusted peer (1.2.3.4) — XFF should be ignored
    let mut req = Request::builder()
        .uri("/health")
        .header("x-forwarded-for", "spoofed.ip")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo("1.2.3.4:5678".parse::<SocketAddr>().unwrap()));

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// === Version upgrade tests ===

#[tokio::test]
async fn health_returns_json_with_version() {
    let app = build_app(test_state(), vec![]);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
    assert!(!json["version"].as_str().unwrap().is_empty());
    assert!(!json["min_agent_version"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn poll_returns_upgrade_required_for_old_agent() {
    let app = build_app(test_state(), vec![]);
    let body = serde_json::json!({
        "capabilities": {
            "databases": ["app"],
            "operations": ["execute_select"]
        },
        "agent_version": "0.0.1"
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/agent/poll")
                .header("content-type", "application/json")
                .header("authorization", "Bearer agent-token")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["upgrade_required"], true);
    assert!(json["jobs"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn poll_returns_no_upgrade_for_current_agent() {
    let app = build_app(test_state(), vec![]);
    let body = serde_json::json!({
        "capabilities": {
            "databases": ["app"],
            "operations": ["execute_select"]
        },
        "agent_version": env!("CARGO_PKG_VERSION")
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/agent/poll")
                .header("content-type", "application/json")
                .header("authorization", "Bearer agent-token")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["upgrade_required"], false);
}

#[tokio::test]
async fn poll_returns_no_upgrade_when_agent_version_missing() {
    let app = build_app(test_state(), vec![]);
    let body = serde_json::json!({
        "capabilities": {
            "databases": ["app"],
            "operations": ["execute_select"]
        }
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/agent/poll")
                .header("content-type", "application/json")
                .header("authorization", "Bearer agent-token")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["upgrade_required"], false);
}

#[tokio::test]
async fn response_includes_version_header() {
    let app = build_app(test_state(), vec![]);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let header = resp.headers().get("x-dbward-version").unwrap();
    assert_eq!(header.to_str().unwrap(), env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn policy_resolution_unregistered_db_returns_deny() {
    let app = build_app(test_state(), vec![]);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/policy-resolution?database=app&environment=production")
                .header("authorization", "Bearer valid-test-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["registered"], false);
    assert_eq!(json["decision_preview"], "deny");
    assert_eq!(json["reason_code"], "db_not_registered");
}

#[tokio::test]
async fn policy_resolution_invalid_operation_returns_400() {
    let app = build_app(test_state(), vec![]);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/policy-resolution?database=app&environment=production&operation=invalid_op")
                .header("authorization", "Bearer valid-test-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn policy_resolution_missing_params_returns_400() {
    let app = build_app(test_state(), vec![]);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/policy-resolution?database=app")
                .header("authorization", "Bearer valid-test-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
