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
use dbward_domain::values::{DatabaseName, Environment, Operation};
use dbward_server::state::AppState;
use dbward_server::build_app;

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
    fn resolve(&self, _: &str, _: SubjectType, _: &[String]) -> Result<Vec<ResolvedRole>, AuthError> {
        Ok(vec![])
    }
}

struct StubAuthorizer;
impl Authorizer for StubAuthorizer {
    fn authorize_scoped(&self, _: &AuthUser, _: Permission, _: &DatabaseName, _: &Environment, _: &ResourceContext) -> Result<(), AuthzError> {
        Ok(())
    }
    fn authorize_global(&self, _: &AuthUser, _: Permission) -> Result<(), AuthzError> {
        Ok(())
    }
}

struct StubRequestRepo;
impl RequestRepo for StubRequestRepo {
    fn insert(&self, _: &dbward_domain::entities::Request) -> Result<(), AppError> { Ok(()) }
    fn get(&self, _: &str) -> Result<Option<dbward_domain::entities::Request>, AppError> { Ok(None) }
    fn find_by_idempotency_key(&self, _: &str) -> Result<Option<dbward_domain::entities::Request>, AppError> { Ok(None) }
    fn insert_approval(&self, _: &Approval) -> Result<(), AppError> { Ok(()) }
    fn get_approvals(&self, _: &str) -> Result<Vec<Approval>, AppError> { Ok(vec![]) }
    fn count_executions(&self, _: &str) -> Result<u32, AppError> { Ok(0) }
    fn mark_approved(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> { Ok(true) }
    fn mark_rejected(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> { Ok(true) }
    fn mark_cancelled(&self, _: &str, _: &str, _: Option<&str>, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> { Ok(true) }
    fn mark_dispatched(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> { Ok(true) }
    fn mark_running(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> { Ok(true) }
    fn mark_executed(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> { Ok(true) }
    fn mark_failed(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> { Ok(true) }
    fn cancel_all_for_user(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<u32, AppError> { Ok(0) }
}

struct StubAgentRepo;
impl AgentRepo for StubAgentRepo {
    fn upsert(&self, _: &Agent) -> Result<(), AppError> { Ok(()) }
    fn get(&self, _: &str) -> Result<Option<Agent>, AppError> { Ok(None) }
    fn list(&self) -> Result<Vec<Agent>, AppError> { Ok(vec![]) }
    fn create_execution(&self, _: &Execution) -> Result<(), AppError> { Ok(()) }
    fn get_execution(&self, _: &str) -> Result<Option<Execution>, AppError> { Ok(None) }
    fn update_execution_status(&self, _: &str, _: ExecutionStatus) -> Result<(), AppError> { Ok(()) }
    fn extend_lease(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<(), AppError> { Ok(()) }
    fn find_dispatched_jobs(&self, _: &[(DatabaseName, Environment)]) -> Result<Vec<dbward_domain::entities::Request>, AppError> { Ok(vec![]) }
    fn has_running_migration(&self, _: &DatabaseName, _: &Environment, _: &str) -> Result<bool, AppError> { Ok(false) }
    fn find_executions_for_request(&self, _: &str) -> Result<Vec<Execution>, AppError> { Ok(vec![]) }
}

struct StubUserRepo;
impl UserRepo for StubUserRepo {
    fn get(&self, _: &str) -> Result<Option<User>, AppError> { Ok(None) }
    fn upsert(&self, _: &User) -> Result<(), AppError> { Ok(()) }
    fn list(&self) -> Result<Vec<User>, AppError> { Ok(vec![]) }
    fn suspend(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> { Ok(true) }
    fn activate(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> { Ok(true) }
    fn is_suspended(&self, _: &str) -> Result<bool, AppError> { Ok(false) }
}

struct StubTokenRepo;
impl TokenRepo for StubTokenRepo {
    fn create(&self, _: &Token) -> Result<(), AppError> { Ok(()) }
    fn verify(&self, _: &str, _: &str) -> Result<Option<Token>, AppError> { Ok(None) }
    fn list(&self) -> Result<Vec<Token>, AppError> { Ok(vec![]) }
    fn get(&self, _: &str) -> Result<Option<Token>, AppError> { Ok(None) }
    fn revoke(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> { Ok(true) }
    fn revoke_all_for_user(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<u32, AppError> { Ok(0) }
    fn count_active(&self) -> Result<u32, AppError> { Ok(0) }
}

struct StubWebhookRepo;
impl WebhookRepo for StubWebhookRepo {
    fn create(&self, _: &Webhook) -> Result<(), AppError> { Ok(()) }
    fn get(&self, _: &str) -> Result<Option<Webhook>, AppError> { Ok(None) }
    fn list(&self) -> Result<Vec<Webhook>, AppError> { Ok(vec![]) }
    fn update(&self, _: &Webhook) -> Result<(), AppError> { Ok(()) }
    fn delete(&self, _: &str) -> Result<(), AppError> { Ok(()) }
}

struct StubPolicyRepo;
impl PolicyRepo for StubPolicyRepo {
    fn create_workflow(&self, _: &Workflow) -> Result<(), AppError> { Ok(()) }
    fn get_workflow(&self, _: &str) -> Result<Option<Workflow>, AppError> { Ok(None) }
    fn list_workflows(&self) -> Result<Vec<Workflow>, AppError> { Ok(vec![]) }
    fn delete_workflow(&self, _: &str) -> Result<bool, AppError> { Ok(true) }
    fn count_workflows(&self) -> Result<u32, AppError> { Ok(0) }
    fn create_execution_policy(&self, _: &ExecutionPolicy) -> Result<(), AppError> { Ok(()) }
    fn get_execution_policy(&self, _: &str) -> Result<Option<ExecutionPolicy>, AppError> { Ok(None) }
    fn list_execution_policies(&self) -> Result<Vec<ExecutionPolicy>, AppError> { Ok(vec![]) }
    fn delete_execution_policy(&self, _: &str) -> Result<bool, AppError> { Ok(true) }
    fn create_role(&self, _: &RoleDefinition) -> Result<(), AppError> { Ok(()) }
    fn list_roles(&self) -> Result<Vec<RoleDefinition>, AppError> { Ok(vec![]) }
    fn delete_role(&self, _: &str) -> Result<bool, AppError> { Ok(true) }
    fn count_roles(&self) -> Result<u32, AppError> { Ok(0) }
}

struct StubDatabaseRegistry;
impl DatabaseRegistry for StubDatabaseRegistry {
    fn exists(&self, _: &DatabaseName, _: &Environment) -> Result<bool, AppError> { Ok(false) }
    fn list(&self) -> Result<Vec<(DatabaseName, Environment)>, AppError> { Ok(vec![]) }
}

struct StubAuditLogger;
impl AuditLogger for StubAuditLogger {
    fn record(&self, _: &AuditEvent) -> Result<(), AppError> { Ok(()) }
}

struct StubAuditRepo;
impl AuditRepo for StubAuditRepo {
    fn list(&self, _: &AuditFilter) -> Result<Vec<AuditEvent>, AppError> { Ok(vec![]) }
    fn verify_chain(&self) -> Result<AuditVerifyResult, AppError> {
        Ok(AuditVerifyResult { total_events: 0, first_broken_id: None })
    }
}

struct StubPolicyEvaluator;
impl PolicyEvaluator for StubPolicyEvaluator {
    fn evaluate_workflow(&self, _: &DatabaseName, _: &Environment, _: Operation) -> Result<Option<Workflow>, AppError> { Ok(None) }
    fn get_execution_policy(&self, _: &DatabaseName, _: &Environment) -> ExecutionPolicy { ExecutionPolicy::default() }
}

struct StubResultStore;
#[async_trait]
impl ResultStore for StubResultStore {
    async fn put(&self, _: &str, _: &[u8]) -> Result<(), AppError> { Ok(()) }
    async fn get(&self, _: &str) -> Result<Vec<u8>, AppError> { Ok(vec![]) }
    async fn delete(&self, _: &str) -> Result<(), AppError> { Ok(()) }
}

struct StubResultChannel;
#[async_trait]
impl ResultChannel for StubResultChannel {
    async fn subscribe(&self, _: &str, _: u64) -> Result<Option<Vec<u8>>, AppError> { Ok(None) }
}

struct StubTokenSigner;
impl TokenSigner for StubTokenSigner {
    fn sign(&self, _: &ExecutionTokenClaims) -> String { "signed".into() }
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
    fn validate_url(&self, _: &str) -> Result<(), AppError> { Ok(()) }
}

struct StubLicenseChecker;
impl LicenseChecker for StubLicenseChecker {
    fn max_tokens(&self) -> u32 { 10 }
    fn max_workflows(&self) -> u32 { 5 }
    fn max_webhooks(&self) -> u32 { 3 }
    fn max_roles(&self) -> u32 { 3 }
    fn is_pro(&self) -> bool { false }
}

struct StubClock;
impl Clock for StubClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> { chrono::Utc::now() }
}

struct StubIdGenerator;
impl IdGenerator for StubIdGenerator {
    fn generate(&self) -> String { "test-id".into() }
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
    }
}

#[tokio::test]
async fn health_returns_200() {
    let app = build_app(test_state());
    let resp = app
        .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn ready_returns_200() {
    let app = build_app(test_state());
    let resp = app
        .oneshot(Request::builder().uri("/ready").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn unauthenticated_request_returns_401() {
    let app = build_app(test_state());
    let resp = app
        .oneshot(Request::builder().uri("/api/requests").body(Body::empty()).unwrap())
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
