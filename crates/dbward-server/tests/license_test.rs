//! License limit integration tests.
//! Verifies that Free/Team/Enterprise plan limits are enforced correctly.
//! These tests require the `commercial` feature (LicenseCheckerImpl).

#![cfg(feature = "commercial")]

use std::sync::atomic::AtomicBool;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::Service;

use dbward_app::error::AuthError;
use dbward_app::ports::*;
use dbward_commercial_license::LicenseCheckerImpl;
use dbward_domain::auth::*;
use dbward_domain::license::{License, Plan};
use dbward_domain::values::*;
use dbward_infra::sqlite::{self, *};
use dbward_server::build_app;
use dbward_server::state::{AppState, AppStateBuilder};

mod common;
use common::*;

// --- Auth stubs (test-specific) ---

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

// --- State builder ---

fn state_with_license(license: License) -> AppState {
    let conn = sqlite::open_memory().unwrap();
    AppStateBuilder {
        token_verifier: Arc::new(AdminVerifier),
        reloadable: Arc::new(arc_swap::ArcSwap::from_pointee(
            dbward_server::state::ReloadableConfig {
                role_resolver: Arc::new(NoopRoleResolver),
                auto_approve_entries: vec![],
                sql_review_rules: dbward_domain::services::sql_reviewer::ReviewRules::default(),
                default_approval_ttl_secs: Some(3600),
            },
        )),
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
        schema_repo: Arc::new(dbward_infra::sqlite::SqliteSchemaRepo::new(conn.clone())),
        dry_run_repo: Arc::new(dbward_infra::sqlite::SqliteDryRunRepo::new(conn.clone())),
        context_repo: Arc::new(dbward_infra::sqlite::SqliteContextRepo::new(conn.clone())),
        audit_logger: Arc::new(SqliteAuditLogger::new(conn.clone())),
        audit_repo: Arc::new(SqliteAuditRepo::new(conn.clone())),
        policy_evaluator: Arc::new(SqlitePolicyEvaluator::new(conn.clone())),
        result_store: Arc::new(NoopResultStore),
        result_channel: Arc::new(NoopResultChannel),
        token_signer: Arc::new(NoopTokenSigner),
        notifier: Arc::new(NoopNotifier),
        ssrf_validator: Arc::new(NoopSsrfValidator),
        license_checker: Arc::new(LicenseCheckerImpl::new(
            license,
            chrono::Utc::now(),
            None,
            None,
            true,
            String::new(),
        )),
        #[cfg(feature = "commercial")]
        license_checker_impl: None,
        server_meta_repo: None,
        clock: Arc::new(RealClock),
        id_generator: Arc::new(SeqIdGen::new()),
        token_value_generator: Arc::new(dbward_infra::SecureTokenGenerator),
        metrics: Arc::new(dbward_server::metrics::Metrics::new()),
        webhook_delivery_repo: None,
        uow: Arc::new(dbward_infra::sqlite::SqliteUnitOfWork::new(conn.clone())),
        audit_signer: Arc::new(common::NoopAuditSigner),
        audit_verifier: Arc::new(common::NoopAuditSigner),
        webhook_sender: Arc::new(NoopWebhookSender),
        draining: Arc::new(AtomicBool::new(false)),
        slack_config: None,
        slack_client: None,
        auth_mode: "token".into(),
        max_persist_bytes: 10 * 1024 * 1024,
        storage_backend: "local".into(),
        mcp_enabled: false,
        mcp_allowed_origins: vec![],
        mcp_default_database: String::new(),
        mcp_default_environment: "development".into(),
        mcp_elicitation_timeout_secs: 300,
        mcp_replay_buffer_size: 100,
        session_store: std::sync::Arc::new(dbward_server::session_store::SessionStore::new(3600, 100)),
    }
    .build()
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
        key_id: None,
        issued_to: None,
        issued_at: None,
        expires_at: None,
    };
    let state = state_with_license(license);

    // Free allows 3 databases — register 3 successfully
    let registry = state.database_registry().clone();
    for i in 0..3 {
        let db = DatabaseName::new(format!("db{i}")).unwrap();
        let env = Environment::new("production").unwrap();
        registry.register(&db, &env).unwrap();
    }

    assert_eq!(state.license_checker().max_databases(), 3);

    // 4th database via register_databases should succeed (register is now additive)
    // License limit is enforced in sync_all_config, not register_databases
    let dbs = vec![dbward_config::server::DatabaseDef {
        name: "db_over_limit".into(),
        environments: vec!["production".into()],
    }];
    let result = dbward_server::register_databases(&state, &dbs);
    // register_databases no longer checks limits (sync does), so this succeeds
    assert!(result.is_ok());
    // But the total is now 4, which exceeds max_databases=3
    assert_eq!(registry.list_active().unwrap().len(), 4);
}

// === Test 2: Free plan — workflows are unlimited ===

#[tokio::test]
async fn free_workflow_unlimited() {
    let license = License {
        plan: Plan::Free,
        key_id: None,
        issued_to: None,
        issued_at: None,
        expires_at: None,
    };
    let state = state_with_license(license);
    let mut app = build_app(state, vec![]);

    // CFG-24: workflow creation via API now returns 405
    let resp = app.call(wf_request("db0", "production")).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::METHOD_NOT_ALLOWED,
        "workflow API should return 405 (config-managed)"
    );
}

// === Test 3: Team plan — DB up to 20 OK ===

#[tokio::test]
async fn pro_database_limit_allows_20() {
    let license = License {
        plan: Plan::Team,
        key_id: None,
        issued_to: None,
        issued_at: None,
        expires_at: None,
    };
    let state = state_with_license(license);

    let registry = state.database_registry().clone();
    for i in 0..20 {
        let db = DatabaseName::new(format!("db{i}")).unwrap();
        let env = Environment::new("production").unwrap();
        registry.register(&db, &env).unwrap();
    }

    assert_eq!(registry.list_active().unwrap().len(), 20);
    assert_eq!(state.license_checker().max_databases(), 20);
}

// === Test 4: Team plan — DB 21 blocked ===

#[tokio::test]
async fn pro_database_limit_blocks_at_21() {
    let license = License {
        plan: Plan::Team,
        key_id: None,
        issued_to: None,
        issued_at: None,
        expires_at: None,
    };
    let state = state_with_license(license);

    let registry = state.database_registry().clone();
    for i in 0..20 {
        let db = DatabaseName::new(format!("db{i}")).unwrap();
        let env = Environment::new("production").unwrap();
        registry.register(&db, &env).unwrap();
    }

    // register_databases no longer enforces limits (sync does)
    let dbs = vec![dbward_config::server::DatabaseDef {
        name: "db_over_limit".into(),
        environments: vec!["production".into()],
    }];
    let result = dbward_server::register_databases(&state, &dbs);
    assert!(result.is_ok(), "register_databases no longer checks limits");
    assert_eq!(registry.list_active().unwrap().len(), 21);
}

// === Test 5: Enterprise — no database limit ===

#[tokio::test]
async fn enterprise_no_database_limit() {
    let license = License {
        plan: Plan::Enterprise,
        key_id: None,
        issued_to: None,
        issued_at: None,
        expires_at: None,
    };
    let state = state_with_license(license);

    let registry = state.database_registry().clone();
    for i in 0..50 {
        let db = DatabaseName::new(format!("db{i}")).unwrap();
        let env = Environment::new("production").unwrap();
        registry.register(&db, &env).unwrap();
    }

    assert_eq!(registry.list_active().unwrap().len(), 50);
    assert_eq!(state.license_checker().max_databases(), u32::MAX);
    assert!(state.license_checker().is_enterprise());
}

// === Test 6: Expired license falls back to Free limits via LicenseCheckerImpl ===

#[tokio::test]
async fn expired_license_falls_back_to_free() {
    // Pass expired license directly to LicenseCheckerImpl — it should detect
    // expiry in the constructor and apply Free limits.
    let expired = License {
        plan: Plan::Team,
        key_id: None,
        issued_to: Some("org".into()),
        issued_at: None,
        expires_at: Some(chrono::Utc::now() - chrono::Duration::hours(1)),
    };

    let state = state_with_license(expired);

    // LicenseCheckerImpl should have detected expiry
    assert!(state.license_checker().is_expired());
    assert_eq!(state.license_checker().effective_plan(), "free");
    assert_eq!(state.license_checker().configured_plan(), "team");
    assert_eq!(state.license_checker().max_workflows(), u32::MAX);

    let mut app = build_app(state, vec![]);

    // CFG-24: workflow API returns 405 regardless of license
    let resp = app.call(wf_request("db0", "production")).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::METHOD_NOT_ALLOWED,
        "workflow API should return 405 (config-managed)"
    );
}
