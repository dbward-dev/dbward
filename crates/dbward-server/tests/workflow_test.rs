//! Workflow state-transition integration tests.
//! Tests the approval lifecycle through the REST API with real SQLite.

use std::sync::atomic::AtomicBool;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::Service;

use dbward_app::error::AuthError;
use dbward_app::ports::*;
use dbward_domain::auth::*;
use dbward_infra::auth::RbacAuthorizer;
use dbward_infra::sqlite::{self, *};
use dbward_server::build_app;
use dbward_server::state::{AppState, AppStateBuilder};

mod common;
use common::*;

// --- Token verifier with multiple users ---

struct MultiUserVerifier;

#[async_trait]
impl TokenVerifier for MultiUserVerifier {
    async fn verify_api_token(
        &self,
        token: &str,
    ) -> Result<dbward_app::ports::VerifiedToken, AuthError> {
        match token {
            "admin-token" => Ok(dbward_app::ports::VerifiedToken {
                id: "tok-admin".into(),
                subject_id: "admin".into(),
                subject_type: SubjectType::User,
                scope_ceiling: Some(dbward_domain::entities::ScopeCeiling {
                    roles: vec!["admin".into()],
                }),
            }),
            "dev-token" => Ok(dbward_app::ports::VerifiedToken {
                id: "tok-dev".into(),
                subject_id: "developer".into(),
                subject_type: SubjectType::User,
                scope_ceiling: Some(dbward_domain::entities::ScopeCeiling {
                    roles: vec!["developer".into()],
                }),
            }),
            "approver-token" => Ok(dbward_app::ports::VerifiedToken {
                id: "tok-approver".into(),
                subject_id: "approver".into(),
                subject_type: SubjectType::User,
                scope_ceiling: Some(dbward_domain::entities::ScopeCeiling {
                    roles: vec!["developer".into()],
                }),
            }),
            "dba-token" => Ok(dbward_app::ports::VerifiedToken {
                id: "tok-dba".into(),
                subject_id: "dba".into(),
                subject_type: SubjectType::User,
                scope_ceiling: Some(dbward_domain::entities::ScopeCeiling {
                    roles: vec!["developer".into()],
                }),
            }),
            _ => Err(AuthError::InvalidToken),
        }
    }

    async fn verify_oidc_token(&self, _: &str) -> Result<(String, Vec<String>), AuthError> {
        Err(AuthError::OidcNotConfigured)
    }
}

// --- Minimal stubs (shared via common/) ---

// --- Test state builder ---

fn workflow_state() -> AppState {
    let conn = sqlite::open_memory().unwrap();

    // Register databases
    {
        let c = conn.lock();
        c.execute(
            "INSERT INTO databases (id, name, environment, created_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                "app:production",
                "app",
                "production",
                "2026-01-01T00:00:00Z"
            ],
        )
        .unwrap();
        c.execute(
            "INSERT INTO databases (id, name, environment, created_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                "app:development",
                "app",
                "development",
                "2026-01-01T00:00:00Z"
            ],
        )
        .unwrap();

        // 2-step production workflow (backend-team → dba-team)
        c.execute(
            "INSERT INTO workflows (id, database_name, environment, operations_json, steps_json, require_reason, allow_self_approve, allow_same_approver_across_steps) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                "wf-prod", "app", "production", "[]",
                r#"[{"approvers":[{"selector":"group:backend-team","min":1}],"mode":"all"},{"approvers":[{"selector":"group:dba-team","min":1}],"mode":"all"}]"#,
                1, 0, 0
            ],
        ).unwrap();

        // Auto-approve development workflow (always mode)
        c.execute(
            "INSERT INTO workflows (id, database_name, environment, operations_json, steps_json, auto_approve_json, require_reason, allow_self_approve, allow_same_approver_across_steps) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params!["wf-dev", "app", "development", "[]", "[]", r#"{"mode":"always","max_risk_level":null,"allow_read_only":true,"allow_safe_ddl":true,"max_estimated_rows":1000}"#, 0, 0, 1],
        ).unwrap();
    }

    AppStateBuilder {
        token_verifier: Arc::new(MultiUserVerifier),
        reloadable: Arc::new(arc_swap::ArcSwap::from_pointee(
            dbward_server::state::ReloadableConfig {
                role_resolver: Arc::new(NoopRoleResolver),
                default_approval_ttl_secs: Some(3600),
            },
        )),
        authorizer: Arc::new(RbacAuthorizer),
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
        license_checker: Arc::new(NoopLicenseChecker),
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
        preflight_job_repo: Arc::new(dbward_infra::sqlite::SqlitePreflightJobRepo::new(
            conn.clone(),
        )),
        preflight_notifier: std::sync::Arc::new(
            dbward_server::preflight_notifier::PreflightNotifier::new(),
        ),
        preflight_max_concurrent_per_user: 3,
        preflight_max_explain_timeout_ms: 10000,
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
        session_store: std::sync::Arc::new(dbward_server::session_store::SessionStore::new(
            3600, 100,
        )),
    }
    .build()
}

// --- Helpers ---

fn json_req(method: &str, uri: &str, token: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

async fn resp_json(resp: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or_default()
}

fn create_request(token: &str, env: &str, detail: &str, reason: Option<&str>) -> Request<Body> {
    let mut body = serde_json::json!({
        "database": "app",
        "environment": env,
        "detail": detail,
    });
    if let Some(r) = reason {
        body["reason"] = serde_json::Value::String(r.into());
    }
    json_req("POST", "/api/requests", token, body)
}

// === Tests ===

#[tokio::test]
async fn reject_then_approve_returns_conflict() {
    let mut app = build_app(workflow_state(), vec![]);

    // Create pending request
    let resp = app
        .call(create_request(
            "dev-token",
            "production",
            "SELECT 1",
            Some("test"),
        ))
        .await
        .unwrap();
    let body = resp_json(resp).await;
    let id = body["id"].as_str().unwrap().to_string();

    // Reject
    let resp = app
        .call(json_req(
            "POST",
            &format!("/api/requests/{id}/reject"),
            "admin-token",
            serde_json::json!({"comment":"no"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Try approve after reject
    let resp = app
        .call(json_req(
            "POST",
            &format!("/api/requests/{id}/approve"),
            "admin-token",
            serde_json::json!({"comment":"yes"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn step1_approve_then_reject_at_step2() {
    let mut app = build_app(workflow_state(), vec![]);

    let resp = app
        .call(create_request(
            "dev-token",
            "production",
            "SELECT 1",
            Some("test"),
        ))
        .await
        .unwrap();
    let body = resp_json(resp).await;
    let id = body["id"].as_str().unwrap().to_string();

    // Step 1 approve (backend-team)
    let resp = app
        .call(json_req(
            "POST",
            &format!("/api/requests/{id}/approve"),
            "approver-token",
            serde_json::json!({"comment":"ok"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp_json(resp).await;
    assert_eq!(body["status"].as_str().unwrap(), "pending");

    // Reject at step 2
    let resp = app
        .call(json_req(
            "POST",
            &format!("/api/requests/{id}/reject"),
            "dba-token",
            serde_json::json!({"comment":"nope"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp_json(resp).await;
    assert_eq!(body["status"].as_str().unwrap(), "rejected");
}

#[tokio::test]
async fn cancel_pending_succeeds() {
    let mut app = build_app(workflow_state(), vec![]);

    let resp = app
        .call(create_request(
            "dev-token",
            "production",
            "SELECT 1",
            Some("test"),
        ))
        .await
        .unwrap();
    let body = resp_json(resp).await;
    let id = body["id"].as_str().unwrap().to_string();

    let resp = app
        .call(json_req(
            "POST",
            &format!("/api/requests/{id}/cancel"),
            "dev-token",
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp_json(resp).await;
    assert_eq!(body["status"].as_str().unwrap(), "cancelled");
}

#[tokio::test]
async fn cancel_approved_succeeds() {
    let mut app = build_app(workflow_state(), vec![]);

    let resp = app
        .call(create_request(
            "dev-token",
            "production",
            "SELECT 1",
            Some("test"),
        ))
        .await
        .unwrap();
    let body = resp_json(resp).await;
    let id = body["id"].as_str().unwrap().to_string();

    // Approve both steps
    app.call(json_req(
        "POST",
        &format!("/api/requests/{id}/approve"),
        "approver-token",
        serde_json::json!({"comment":"1"}),
    ))
    .await
    .unwrap();
    app.call(json_req(
        "POST",
        &format!("/api/requests/{id}/approve"),
        "dba-token",
        serde_json::json!({"comment":"2"}),
    ))
    .await
    .unwrap();

    // Cancel approved
    let resp = app
        .call(json_req(
            "POST",
            &format!("/api/requests/{id}/cancel"),
            "dev-token",
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn other_user_cannot_cancel() {
    let mut app = build_app(workflow_state(), vec![]);

    let resp = app
        .call(create_request(
            "dev-token",
            "production",
            "SELECT 1",
            Some("test"),
        ))
        .await
        .unwrap();
    let body = resp_json(resp).await;
    let id = body["id"].as_str().unwrap().to_string();

    // approver tries to cancel dev's request
    let resp = app
        .call(json_req(
            "POST",
            &format!("/api/requests/{id}/cancel"),
            "approver-token",
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_can_cancel_others_request() {
    let mut app = build_app(workflow_state(), vec![]);

    let resp = app
        .call(create_request(
            "dev-token",
            "production",
            "SELECT 1",
            Some("test"),
        ))
        .await
        .unwrap();
    let body = resp_json(resp).await;
    let id = body["id"].as_str().unwrap().to_string();

    let resp = app
        .call(json_req(
            "POST",
            &format!("/api/requests/{id}/cancel"),
            "admin-token",
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn break_glass_skips_approval() {
    let mut app = build_app(workflow_state(), vec![]);

    let body = serde_json::json!({
        "database": "app",
        "environment": "production",
        "detail": "SELECT 1",
        "reason": "emergency",
        "emergency": true,
    });
    let resp = app
        .call(json_req("POST", "/api/requests", "admin-token", body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = resp_json(resp).await;
    assert_eq!(body["status"].as_str().unwrap(), "dispatched");
}

#[tokio::test]
async fn developer_cannot_break_glass() {
    let mut app = build_app(workflow_state(), vec![]);

    let body = serde_json::json!({
        "database": "app",
        "environment": "production",
        "detail": "SELECT 1",
        "reason": "emergency",
        "emergency": true,
    });
    let resp = app
        .call(json_req("POST", "/api/requests", "dev-token", body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn approve_already_approved_returns_conflict() {
    let mut app = build_app(workflow_state(), vec![]);

    let resp = app
        .call(create_request(
            "dev-token",
            "production",
            "SELECT 1",
            Some("test"),
        ))
        .await
        .unwrap();
    let body = resp_json(resp).await;
    let id = body["id"].as_str().unwrap().to_string();

    // Approve both steps
    app.call(json_req(
        "POST",
        &format!("/api/requests/{id}/approve"),
        "approver-token",
        serde_json::json!({"comment":"1"}),
    ))
    .await
    .unwrap();
    app.call(json_req(
        "POST",
        &format!("/api/requests/{id}/approve"),
        "dba-token",
        serde_json::json!({"comment":"2"}),
    ))
    .await
    .unwrap();

    // 3rd approve
    let resp = app
        .call(json_req(
            "POST",
            &format!("/api/requests/{id}/approve"),
            "admin-token",
            serde_json::json!({"comment":"3"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn self_approve_blocked_even_for_admin() {
    let mut app = build_app(workflow_state(), vec![]);

    // Admin creates request
    let body = serde_json::json!({
        "database": "app",
        "environment": "production",
        "detail": "SELECT 1",
        "reason": "self test",
    });
    let resp = app
        .call(json_req("POST", "/api/requests", "admin-token", body))
        .await
        .unwrap();
    let body = resp_json(resp).await;
    let id = body["id"].as_str().unwrap().to_string();

    // Admin tries to approve own request
    let resp = app
        .call(json_req(
            "POST",
            &format!("/api/requests/{id}/approve"),
            "admin-token",
            serde_json::json!({"comment":"self"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn reject_then_cancel_returns_conflict() {
    let mut app = build_app(workflow_state(), vec![]);

    let resp = app
        .call(create_request(
            "dev-token",
            "production",
            "SELECT 1",
            Some("test"),
        ))
        .await
        .unwrap();
    let body = resp_json(resp).await;
    let id = body["id"].as_str().unwrap().to_string();

    // Reject
    app.call(json_req(
        "POST",
        &format!("/api/requests/{id}/reject"),
        "admin-token",
        serde_json::json!({"comment":"no"}),
    ))
    .await
    .unwrap();

    // Try cancel
    let resp = app
        .call(json_req(
            "POST",
            &format!("/api/requests/{id}/cancel"),
            "dev-token",
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn development_auto_approves() {
    let mut app = build_app(workflow_state(), vec![]);

    let resp = app
        .call(create_request("dev-token", "development", "SELECT 1", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = resp_json(resp).await;
    assert_eq!(body["status"].as_str().unwrap(), "dispatched");
}

#[tokio::test]
async fn require_reason_enforced() {
    let mut app = build_app(workflow_state(), vec![]);

    // Production requires reason
    let resp = app
        .call(create_request("dev-token", "production", "SELECT 1", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
