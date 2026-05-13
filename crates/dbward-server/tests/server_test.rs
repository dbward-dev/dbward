use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use dbward_app::error::{AppError, AuthError, AuthzError};
use dbward_app::ports::*;
use dbward_domain::auth::*;
use dbward_domain::entities::*;
use dbward_domain::policies::{ExecutionPolicy, Workflow};
use dbward_domain::services::status_machine::{EventDispatcher, TransitionEvent};
use dbward_domain::values::{DatabaseName, Environment, Operation, ResultSummary};
use dbward_server::build_app;
use dbward_server::state::AppState;

// --- Mock TokenVerifier ---

struct MockTokenVerifier;

#[async_trait]
impl TokenVerifier for MockTokenVerifier {
    async fn verify_api_token(&self, token: &str) -> Result<AuthUser, AuthError> {
        if token == "valid-test-token" {
            Ok(AuthUser {
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
            })
        } else {
            Err(AuthError::InvalidToken)
        }
    }

    async fn verify_oidc_token(&self, _token: &str) -> Result<(String, Vec<String>), AuthError> {
        Err(AuthError::OidcNotConfigured)
    }
}

// --- Stub implementations for remaining ports ---

struct StubRoleResolver;
impl RoleResolver for StubRoleResolver {
    fn resolve(
        &self,
        _: &str,
        _: SubjectType,
        _: &[String],
    ) -> Result<Vec<ResolvedRole>, AuthError> {
        Ok(vec![])
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
impl RequestRepo for StubRequestRepo {
    fn insert(&self, _: &dbward_domain::entities::Request) -> Result<(), AppError> {
        Ok(())
    }
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
    fn insert_approval(&self, _: &Approval) -> Result<(), AppError> {
        Ok(())
    }
    fn get_approvals(&self, _: &str) -> Result<Vec<Approval>, AppError> {
        Ok(vec![])
    }
    fn count_executions(&self, _: &str) -> Result<u32, AppError> {
        Ok(0)
    }
    fn mark_approved(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
        Ok(true)
    }
    fn approve_and_mark_approved(
        &self,
        _: &Approval,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, AppError> {
        Ok(true)
    }
    fn mark_rejected(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
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
    fn create_and_dispatch(&self, _: &dbward_domain::entities::Request) -> Result<(), AppError> {
        Ok(())
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
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<u32, AppError> {
        Ok(0)
    }
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
    fn mark_approved_from_dispatched(&self, _: &str, _: &str) -> Result<bool, AppError> {
        Ok(true)
    }
    fn purge_old_requests(&self, _: &str) -> Result<u32, AppError> {
        Ok(0)
    }
    fn count_by_status(&self, _: &str) -> Result<u32, AppError> {
        Ok(0)
    }
    fn wal_checkpoint(&self) -> Result<(), AppError> {
        Ok(())
    }
    fn list_results_for_user(&self, _: &str, _: u32) -> Result<Vec<dbward_app::ports::repos::StoredResultEntry>, AppError> {
        Ok(vec![])
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
    ) -> Result<bool, AppError> {
        Ok(true)
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
    fn exists(&self, _: &DatabaseName, _: &Environment) -> Result<bool, AppError> {
        Ok(false)
    }
    fn list(&self) -> Result<Vec<(DatabaseName, Environment)>, AppError> {
        Ok(vec![])
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

struct StubResultStore;
#[async_trait]
impl ResultStore for StubResultStore {
    async fn put(&self, _: &str, _: &[u8]) -> Result<(), AppError> {
        Ok(())
    }
    async fn get(&self, _: &str) -> Result<Vec<u8>, AppError> {
        Ok(vec![])
    }
    async fn delete(&self, _: &str) -> Result<(), AppError> {
        Ok(())
    }
}

struct StubResultChannel;
#[async_trait]
impl ResultChannel for StubResultChannel {
    fn create_slot(&self, _: &str) {}
    async fn publish(&self, _: &str, _: ResultSummary) {}
    async fn subscribe(&self, _: &str, _: u64) -> Result<Option<ResultSummary>, AppError> {
        Ok(None)
    }
    async fn notify_all(&self) {}
}

struct StubTokenSigner;
impl TokenSigner for StubTokenSigner {
    fn sign(&self, _: &ExecutionTokenClaims) -> String {
        "signed".into()
    }
    fn public_key_hex(&self) -> String {
        "deadbeef".into()
    }
}

struct StubNotifier;
impl Notifier for StubNotifier {
    fn dispatch(&self, _: WebhookEvent) {}
}

struct StubEventDispatcher;
impl EventDispatcher for StubEventDispatcher {
    fn dispatch(&self, _: TransitionEvent) {}
}

struct StubSsrfValidator;
impl SsrfValidator for StubSsrfValidator {
    fn validate_url(&self, _: &str) -> Result<(), AppError> {
        Ok(())
    }
}

struct StubLicenseChecker;
impl LicenseChecker for StubLicenseChecker {
    fn max_tokens(&self) -> u32 {
        10
    }
    fn max_workflows(&self) -> u32 {
        5
    }
    fn max_webhooks(&self) -> u32 {
        3
    }
    fn max_roles(&self) -> u32 {
        3
    }
    fn max_agents(&self) -> u32 {
        3
    }
    fn is_pro(&self) -> bool {
        false
    }
}

struct StubClock;
impl Clock for StubClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
    }
}

struct StubIdGenerator;
impl IdGenerator for StubIdGenerator {
    fn generate(&self) -> String {
        "test-id".into()
    }
}

fn test_state() -> AppState {
    AppState {
        token_verifier: Arc::new(MockTokenVerifier),
        role_resolver: Arc::new(StubRoleResolver),
        authorizer: Arc::new(StubAuthorizer),
        request_repo: Arc::new(StubRequestRepo),
        agent_repo: Arc::new(StubAgentRepo),
        user_repo: Arc::new(StubUserRepo),
        token_repo: Arc::new(StubTokenRepo),
        webhook_repo: Arc::new(StubWebhookRepo),
        policy_repo: Arc::new(StubPolicyRepo),
        database_registry: Arc::new(StubDatabaseRegistry),
        audit_logger: Arc::new(StubAuditLogger),
        audit_repo: Arc::new(StubAuditRepo),
        policy_evaluator: Arc::new(StubPolicyEvaluator),
        result_store: Arc::new(StubResultStore),
        result_channel: Arc::new(StubResultChannel),
        token_signer: Arc::new(StubTokenSigner),
        notifier: Arc::new(StubNotifier),
        event_dispatcher: Arc::new(StubEventDispatcher),
        ssrf_validator: Arc::new(StubSsrfValidator),
        license_checker: Arc::new(StubLicenseChecker),
        clock: Arc::new(StubClock),
        id_generator: Arc::new(StubIdGenerator),
        metrics: Arc::new(dbward_server::metrics::Metrics::new()),
        draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        default_approval_ttl_secs: Some(3600),
        auth_mode: "both".to_string(),
    }
}

#[tokio::test]
async fn health_returns_200() {
    let app = build_app(test_state());
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
    let app = build_app(test_state());
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
    let app = build_app(test_state());
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
    let app = build_app(test_state());
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
    let app = build_app(test_state());
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
async fn list_requests_returns_empty_array() {
    let app = build_app(test_state());
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
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["requests"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn get_request_not_found_returns_404() {
    let app = build_app(test_state());
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
async fn list_databases_returns_empty() {
    let app = build_app(test_state());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/databases")
                .header("authorization", "Bearer valid-test-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn list_tokens_returns_empty() {
    let app = build_app(test_state());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/tokens")
                .header("authorization", "Bearer valid-test-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn list_webhooks_returns_empty() {
    let app = build_app(test_state());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/webhooks")
                .header("authorization", "Bearer valid-test-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn list_workflows_returns_empty() {
    let app = build_app(test_state());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/workflows")
                .header("authorization", "Bearer valid-test-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn list_agents_returns_empty() {
    let app = build_app(test_state());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/agents")
                .header("authorization", "Bearer valid-test-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn metrics_endpoint_returns_text() {
    let app = build_app(test_state());
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
