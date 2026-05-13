//! Full-stack integration tests: HTTP API → real SQLite repos
//! Tests the complete request lifecycle through the REST API.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use dbward_app::error::{AppError, AuthError};
use dbward_app::ports::*;
use dbward_domain::auth::*;
use dbward_domain::services::status_machine::{EventDispatcher, TransitionEvent};
use dbward_domain::values::*;
use dbward_infra::sqlite::{self, *};
use dbward_infra::auth::RbacAuthorizer;
use dbward_server::state::AppState;
use dbward_server::build_app;

// --- Minimal stubs for ports that don't have infra impls in test ---

struct TestTokenVerifier;
#[async_trait]
impl TokenVerifier for TestTokenVerifier {
    async fn verify_api_token(&self, token: &str) -> Result<AuthUser, AuthError> {
        match token {
            "admin-token" => Ok(AuthUser {
                subject_id: "admin".into(),
                subject_type: SubjectType::User,
                roles: vec![ResolvedRole {
                    name: "admin".into(),
                    permissions: [Permission::All].into(),
                    databases: vec![DatabaseName::new("*").unwrap()],
                    environments: vec![Environment::new("*").unwrap()],
                }],
                groups: vec![],
                token_id: Some("tok-admin".into()),
            }),
            "dev-token" => Ok(AuthUser {
                subject_id: "alice".into(),
                subject_type: SubjectType::User,
                roles: vec![ResolvedRole {
                    name: "developer".into(),
                    permissions: [Permission::RequestCreate, Permission::ResultView].into_iter().collect(),
                    databases: vec![DatabaseName::new("*").unwrap()],
                    environments: vec![Environment::new("*").unwrap()],
                }],
                groups: vec![],
                token_id: Some("tok-dev".into()),
            }),
            _ => Err(AuthError::InvalidToken),
        }
    }
    async fn verify_oidc_token(&self, _: &str) -> Result<(String, Vec<String>), AuthError> {
        Err(AuthError::OidcNotConfigured)
    }
}

struct TestRoleResolver;
impl RoleResolver for TestRoleResolver {
    fn resolve(&self, _: &str, _: SubjectType, _: &[String]) -> Result<Vec<ResolvedRole>, AuthError> {
        Ok(vec![])
    }
}

struct TestResultStore;
#[async_trait]
impl ResultStore for TestResultStore {
    async fn put(&self, _: &str, _: &[u8]) -> Result<(), AppError> { Ok(()) }
    async fn get(&self, _: &str) -> Result<Vec<u8>, AppError> { Ok(vec![]) }
    async fn delete(&self, _: &str) -> Result<(), AppError> { Ok(()) }
}

struct TestResultChannel;
#[async_trait]
impl ResultChannel for TestResultChannel {
    fn create_slot(&self, _: &str) {}
    async fn publish(&self, _: &str, _: ResultSummary) {}
    async fn subscribe(&self, _: &str, _: u64) -> Result<Option<ResultSummary>, AppError> { Ok(None) }
    async fn notify_all(&self) {}
}

struct TestTokenSigner;
impl TokenSigner for TestTokenSigner {
    fn sign(&self, _: &ExecutionTokenClaims) -> String { "signed-token".into() }
    fn public_key_hex(&self) -> String { "deadbeef".repeat(4) }
}

struct TestNotifier;
impl Notifier for TestNotifier { fn dispatch(&self, _: WebhookEvent) {} }

struct TestEventDispatcher;
impl EventDispatcher for TestEventDispatcher { fn dispatch(&self, _: TransitionEvent) {} }

struct TestSsrfValidator;
impl SsrfValidator for TestSsrfValidator { fn validate_url(&self, _: &str) -> Result<(), AppError> { Ok(()) } }

struct TestLicense;
impl LicenseChecker for TestLicense {
    fn max_tokens(&self) -> u32 { 10 }
    fn max_workflows(&self) -> u32 { 5 }
    fn max_webhooks(&self) -> u32 { 3 }
    fn max_roles(&self) -> u32 { 8 }
    fn max_agents(&self) -> u32 { 3 }
    fn is_pro(&self) -> bool { false }
}

struct TestClock;
impl Clock for TestClock { fn now(&self) -> chrono::DateTime<chrono::Utc> { chrono::Utc::now() } }

struct TestIdGen(std::sync::atomic::AtomicU64);
impl IdGenerator for TestIdGen {
    fn generate(&self) -> String {
        let n = self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        format!("req-{n:04}")
    }
}

/// Build a full-stack AppState with real SQLite repos
fn real_state() -> AppState {
    let conn = sqlite::open_memory().unwrap();

    // Register a database so requests can be created
    conn.lock().unwrap()
        .execute(
            "INSERT INTO databases (id, name, environment, created_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params!["app:production", "app", "production", chrono::Utc::now().to_rfc3339()],
        )
        .unwrap();

    // Insert auto-approve workflow (empty steps)
    conn.lock().unwrap()
        .execute(
            "INSERT INTO workflows (id, database_name, environment, operations_json, steps_json, skip_approval_for_json, require_reason, allow_self_approve, allow_same_approver_across_steps) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 0, 0)",
            rusqlite::params!["wf-auto", "app", "production", "[]", "[]", "[]"],
        )
        .unwrap();

    let authorizer = Arc::new(RbacAuthorizer);

    AppState {
        token_verifier: Arc::new(TestTokenVerifier),
        role_resolver: Arc::new(TestRoleResolver),
        authorizer,
        request_repo: Arc::new(SqliteRequestRepo::new(conn.clone())),
        agent_repo: Arc::new(SqliteAgentRepo::new(conn.clone())),
        user_repo: Arc::new(SqliteUserRepo::new(conn.clone())),
        token_repo: Arc::new(SqliteTokenRepo::new(conn.clone())),
        webhook_repo: Arc::new(SqliteWebhookRepo::new(conn.clone())),
        policy_repo: Arc::new(SqlitePolicyRepo::new(conn.clone())),
        database_registry: Arc::new(SqliteDatabaseRegistry::new(conn.clone())),
        audit_logger: Arc::new(SqliteAuditLogger::new(conn.clone())),
        audit_repo: Arc::new(SqliteAuditRepo::new(conn.clone())),
        policy_evaluator: Arc::new(SqlitePolicyEvaluator::new(conn.clone())),
        result_store: Arc::new(TestResultStore),
        result_channel: Arc::new(TestResultChannel),
        token_signer: Arc::new(TestTokenSigner),
        notifier: Arc::new(TestNotifier),
        event_dispatcher: Arc::new(TestEventDispatcher),
        ssrf_validator: Arc::new(TestSsrfValidator),
        license_checker: Arc::new(TestLicense),
        clock: Arc::new(TestClock),
        id_generator: Arc::new(TestIdGen(std::sync::atomic::AtomicU64::new(1))),
        metrics: Arc::new(dbward_server::metrics::Metrics::new()),
        draining: Arc::new(AtomicBool::new(false)),
        default_approval_ttl_secs: Some(3600),
    }
}

fn auth_header(token: &str) -> (&str, String) {
    ("authorization", format!("Bearer {token}"))
}

// === Full lifecycle integration tests ===

#[tokio::test]
async fn create_request_persists_and_returns_id() {
    let state = real_state();
    let app = build_app(state);

    let body = serde_json::json!({
        "database": "app",
        "environment": "production",
        "operation": "execute",
        "detail": "SELECT 1"
    });

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/requests")
                .header("content-type", "application/json")
                .header(auth_header("admin-token").0, auth_header("admin-token").1)
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["id"].as_str().is_some());
    assert_eq!(json["status"], "dispatched");
}

#[tokio::test]
async fn list_requests_returns_created_request() {
    let state = real_state();
    let app = build_app(state.clone());

    // Create
    let body = serde_json::json!({
        "database": "app",
        "environment": "production",
        "operation": "execute",
        "detail": "SELECT 1"
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/requests")
                .header("content-type", "application/json")
                .header(auth_header("admin-token").0, auth_header("admin-token").1)
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // List
    let app2 = build_app(state);
    let resp = app2
        .oneshot(
            Request::builder()
                .uri("/api/requests")
                .header(auth_header("admin-token").0, auth_header("admin-token").1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(!json["requests"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn get_request_returns_detail() {
    let state = real_state();
    let app = build_app(state.clone());

    let body = serde_json::json!({
        "database": "app",
        "environment": "production",
        "operation": "execute",
        "detail": "SELECT 1"
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/requests")
                .header("content-type", "application/json")
                .header(auth_header("admin-token").0, auth_header("admin-token").1)
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let created: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), 4096).await.unwrap()
    ).unwrap();
    let id = created["id"].as_str().unwrap();

    let app2 = build_app(state);
    let resp = app2
        .oneshot(
            Request::builder()
                .uri(format!("/api/requests/{id}"))
                .header(auth_header("admin-token").0, auth_header("admin-token").1)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["id"], id);
    assert_eq!(json["database"], "app");
}

#[tokio::test]
async fn unregistered_database_rejected() {
    let state = real_state();
    let app = build_app(state);

    let body = serde_json::json!({
        "database": "unknown_db",
        "environment": "production",
        "operation": "execute",
        "detail": "SELECT 1"
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/requests")
                .header("content-type", "application/json")
                .header(auth_header("admin-token").0, auth_header("admin-token").1)
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    // Should be 400 or 422 (validation error)
    assert!(resp.status().is_client_error());
}
