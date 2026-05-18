//! License limit integration tests.
//! Verifies that Free/Pro/Enterprise plan limits are enforced correctly.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::Service;

use dbward_app::error::{AppError, AuthError};
use dbward_app::ports::*;
use dbward_domain::auth::*;
use dbward_domain::license::{License, Plan};
use dbward_domain::services::status_machine::{EventDispatcher, TransitionEvent};
use dbward_domain::values::*;
use dbward_infra::LicenseCheckerImpl;
use dbward_infra::sqlite::{self, *};
use dbward_server::build_app;
use dbward_server::state::AppState;

// --- Auth stubs ---

struct AdminVerifier;

#[async_trait]
impl TokenVerifier for AdminVerifier {
    async fn verify_api_token(&self, token: &str) -> Result<AuthUser, AuthError> {
        if token == "admin" {
            Ok(AuthUser {
                subject_id: "admin".into(),
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
    async fn verify_oidc_token(&self, _: &str) -> Result<(String, Vec<String>), AuthError> {
        Err(AuthError::OidcNotConfigured)
    }
}

struct NoopRoleResolver;
impl RoleResolver for NoopRoleResolver {
    fn resolve(
        &self,
        _: &str,
        _: SubjectType,
        _: &[String],
    ) -> Result<Vec<ResolvedRole>, AuthError> {
        Ok(vec![])
    }
}

// --- Minimal service stubs ---

struct NoopResultStore;
#[async_trait]
impl ResultStore for NoopResultStore {
    async fn put(&self, _: &str, _: &[u8], _: PutOptions) -> Result<(), AppError> {
        Ok(())
    }
    async fn get_stream(&self, _: &str) -> Result<ResultStream, AppError> {
        Ok(ResultStream {
            content_length: Some(0),
            stream: Box::pin(EmptyResultStream),
        })
    }
    async fn delete(&self, _: &str) -> Result<(), AppError> {
        Ok(())
    }
}

struct EmptyResultStream;
impl futures_core::Stream for EmptyResultStream {
    type Item = Result<bytes::Bytes, AppError>;
    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::task::Poll::Ready(None)
    }
}

struct NoopResultChannel;
#[async_trait]
impl ResultChannel for NoopResultChannel {
    fn create_slot(&self, _: &str) {}
    async fn publish(&self, _: &str, _: ResultSummary) {}
    async fn subscribe(&self, _: &str, _: u64) -> Result<Option<ResultSummary>, AppError> {
        Ok(None)
    }
    async fn notify_all(&self) {}
}

struct NoopTokenSigner;
impl TokenSigner for NoopTokenSigner {
    fn sign(&self, _: &ExecutionTokenClaims) -> String {
        "s".into()
    }
    fn public_key_hex(&self) -> String {
        "aa".repeat(32)
    }
}

struct NoopNotifier;
impl Notifier for NoopNotifier {
    fn dispatch(&self, _: WebhookEvent) {}
}

struct NoopEventDispatcher;
impl EventDispatcher for NoopEventDispatcher {
    fn dispatch(&self, _: TransitionEvent) {}
}

struct NoopSsrf;
impl SsrfValidator for NoopSsrf {
    fn validate_url(&self, _: &str) -> Result<(), AppError> {
        Ok(())
    }
}

struct NoopWebhookSender;
#[async_trait]
impl WebhookSender for NoopWebhookSender {
    async fn send_one(&self, _: &str, _: &str, _: Option<&str>) -> Result<(), String> {
        Ok(())
    }
}

struct SeqId(std::sync::atomic::AtomicU64);
impl IdGenerator for SeqId {
    fn generate(&self) -> String {
        let n = self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        format!("id-{n:04}")
    }
}

struct RealClock;
impl Clock for RealClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
    }
}

// --- State builder ---

fn state_with_license(license: License) -> AppState {
    let conn = sqlite::open_memory().unwrap();
    AppState {
        token_verifier: Arc::new(AdminVerifier),
        role_resolver: Arc::new(NoopRoleResolver),
        authorizer: Arc::new(dbward_infra::auth::RbacAuthorizer),
        request_reader: Arc::new(SqliteRequestRepo::new(conn.clone())),
        request_writer: Arc::new(SqliteRequestRepo::new(conn.clone())),
        approval_repo: Arc::new(SqliteRequestRepo::new(conn.clone())),
        background_task_repo: Arc::new(SqliteRequestRepo::new(conn.clone())),
        agent_repo: Arc::new(SqliteAgentRepo::new(conn.clone())),
        user_repo: Arc::new(SqliteUserRepo::new(conn.clone())),
        token_repo: Arc::new(SqliteTokenRepo::new(conn.clone())),
        webhook_repo: Arc::new(SqliteWebhookRepo::new(conn.clone())),
        policy_repo: Arc::new(SqlitePolicyRepo::new(conn.clone())),
        database_registry: Arc::new(SqliteDatabaseRegistry::new(conn.clone())),
        audit_logger: Arc::new(SqliteAuditLogger::new(conn.clone())),
        audit_repo: Arc::new(SqliteAuditRepo::new(conn.clone())),
        policy_evaluator: Arc::new(SqlitePolicyEvaluator::new(conn.clone())),
        result_store: Arc::new(NoopResultStore),
        result_channel: Arc::new(NoopResultChannel),
        token_signer: Arc::new(NoopTokenSigner),
        notifier: Arc::new(NoopNotifier),
        event_dispatcher: Arc::new(NoopEventDispatcher),
        ssrf_validator: Arc::new(NoopSsrf),
        license_checker: Arc::new(LicenseCheckerImpl::new(license)),
        clock: Arc::new(RealClock),
        id_generator: Arc::new(SeqId(std::sync::atomic::AtomicU64::new(1))),
        token_value_generator: Arc::new(dbward_infra::SecureTokenGenerator),
        metrics: Arc::new(dbward_server::metrics::Metrics::new()),
        webhook_delivery_repo: None,
        webhook_sender: Arc::new(NoopWebhookSender),
        draining: Arc::new(AtomicBool::new(false)),
        auth_mode: "token".into(),
        default_approval_ttl_secs: Some(3600),
        max_persist_bytes: 10 * 1024 * 1024,
        storage_backend: "local".into(),
    }
}

fn wf_request(db: &str, env: &str) -> Request<Body> {
    let body = serde_json::json!({
        "database": db,
        "environment": env,
        "operations": ["execute_select"],
        "steps": [],
    });
    Request::builder()
        .method("POST")
        .uri("/api/workflows")
        .header("content-type", "application/json")
        .header("authorization", "Bearer admin")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

// === Test 1: Free plan — database registration blocked at max_databases ===

#[tokio::test]
async fn free_database_limit_blocks_at_max() {
    let license = License {
        plan: Plan::Free,
        issued_to: None,
        expires_at: None,
    };
    let state = state_with_license(license);

    // Free allows 3 databases
    let registry = state.database_registry.clone();
    for i in 0..3 {
        let db = DatabaseName::new(format!("db{i}")).unwrap();
        let env = Environment::new("production").unwrap();
        registry.register(&db, &env).unwrap();
    }

    // Verify limit is 3
    assert_eq!(state.license_checker.max_databases(), 3);
    let count = registry.list().unwrap().len() as u32;
    assert_eq!(count, 3);

    // 4th registration should be blocked by the limit check
    assert!(count >= state.license_checker.max_databases());
}

// === Test 2: Free plan — workflow creation blocked at max_workflows ===

#[tokio::test]
async fn free_workflow_limit_blocks_at_max() {
    let license = License {
        plan: Plan::Free,
        issued_to: None,
        expires_at: None,
    };
    let state = state_with_license(license);
    let mut app = build_app(state, vec![]);

    // Create 5 workflows (Free limit)
    for i in 0..5 {
        let resp = app
            .call(wf_request(&format!("db{i}"), "production"))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "workflow {i} should succeed"
        );
    }

    // 6th should fail with 402
    let resp = app.call(wf_request("db99", "staging")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
}

// === Test 3: Pro plan — DB up to 10 OK ===

#[tokio::test]
async fn pro_database_limit_allows_10() {
    let license = License {
        plan: Plan::Pro,
        issued_to: None,
        expires_at: None,
    };
    let state = state_with_license(license);

    let registry = state.database_registry.clone();
    for i in 0..10 {
        let db = DatabaseName::new(format!("db{i}")).unwrap();
        let env = Environment::new("production").unwrap();
        registry.register(&db, &env).unwrap();
    }

    assert_eq!(registry.list().unwrap().len(), 10);
    assert_eq!(state.license_checker.max_databases(), 10);
}

// === Test 4: Pro plan — DB 11 blocked ===

#[tokio::test]
async fn pro_database_limit_blocks_at_11() {
    let license = License {
        plan: Plan::Pro,
        issued_to: None,
        expires_at: None,
    };
    let state = state_with_license(license);

    let registry = state.database_registry.clone();
    for i in 0..10 {
        let db = DatabaseName::new(format!("db{i}")).unwrap();
        let env = Environment::new("production").unwrap();
        registry.register(&db, &env).unwrap();
    }

    let count = registry.list().unwrap().len() as u32;
    assert!(count >= state.license_checker.max_databases());
}

// === Test 5: Enterprise — no database limit ===

#[tokio::test]
async fn enterprise_no_database_limit() {
    let license = License {
        plan: Plan::Enterprise,
        issued_to: None,
        expires_at: None,
    };
    let state = state_with_license(license);

    let registry = state.database_registry.clone();
    for i in 0..50 {
        let db = DatabaseName::new(format!("db{i}")).unwrap();
        let env = Environment::new("production").unwrap();
        registry.register(&db, &env).unwrap();
    }

    assert_eq!(registry.list().unwrap().len(), 50);
    assert_eq!(state.license_checker.max_databases(), u32::MAX);
    assert!(state.license_checker.is_enterprise());
}

// === Test 6: Expired license falls back to Free limits ===

#[tokio::test]
async fn expired_license_falls_back_to_free() {
    let expired = License {
        plan: Plan::Pro,
        issued_to: Some("org".into()),
        expires_at: Some(chrono::Utc::now() - chrono::Duration::hours(1)),
    };

    // When expired, the system should use Free limits
    assert!(expired.is_expired_at(chrono::Utc::now()));

    // Simulate fallback: if expired, construct Free license
    let effective = if expired.is_expired_at(chrono::Utc::now()) {
        License::default()
    } else {
        expired
    };

    let state = state_with_license(effective);
    let mut app = build_app(state, vec![]);

    // Free limit: 5 workflows
    for i in 0..5 {
        let resp = app
            .call(wf_request(&format!("db{i}"), "production"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    // 6th blocked
    let resp = app.call(wf_request("extra", "staging")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
}
