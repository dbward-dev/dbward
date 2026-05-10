//! Verifies that all state-changing operations produce the expected audit events.
//! This test acts as a safety net: if someone adds a new endpoint or refactors
//! a handler and forgets to add audit logging, this test will fail.

use axum::http::StatusCode;
use dbward_server::db;
use dbward_server::token::TokenSigner;
use dbward_server::{AppState, Metrics, ResultChannels};
use rusqlite::Connection;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;

fn test_state() -> AppState {
    let conn = Connection::open_in_memory().unwrap();
    db::init(&conn).unwrap();
    let workflows = vec![dbward_server::server_config::WorkflowDef {
        database: "*".into(),
        environment: "development".into(),
        operations: vec![],
        steps: vec![],
        require_reason: false,
        allow_same_approver_across_steps: false,
        allow_self_approve: false,
    }];
    db::policy_repo::sync_workflows(&conn, &workflows).unwrap();
    AppState {
        license: dbward_server::license::License {
            plan: dbward_server::license::Plan::Pro,
        },
        sqlite: Arc::new(Mutex::new(conn)),
        token_signer: Arc::new(TokenSigner::generate()),
        webhooks: Arc::new(std::sync::RwLock::new(
            dbward_server::webhook::WebhookDispatcher::empty(),
        )),
        metrics: Arc::new(Metrics::new()),
        oidc: None,
        auth_mode: "token".to_string(),
        result_channels: Arc::new(ResultChannels::new()),
        retention: Default::default(),
        request_notifier: Arc::new(dbward_server::RequestNotifier::new()),
        result_store: Arc::new(
            dbward_server::result_storage::ResultStore::new_local(
                &std::env::temp_dir().join("dbward-test").to_string_lossy(),
            )
            .unwrap(),
        ),
        draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        break_glass_roles: dbward_server::server_config::default_break_glass_roles(),
        audit_config: Default::default(),
        trusted_proxies: vec![],
        update_available: Arc::new(Mutex::new(None)),
        update_check_enabled: false,
        enforcer: dbward_server::authz::get_enforcer_arc(),
    }
}

async fn admin_token(state: &AppState) -> String {
    let (_, token) = dbward_server::auth::create_token_with_type(state, "admin", "admin", "user")
        .await
        .unwrap();
    token
}

async fn dev_token(state: &AppState) -> String {
    let (_, token) =
        dbward_server::auth::create_token_with_type(state, "dev1", "developer", "user")
            .await
            .unwrap();
    token
}

fn app(state: AppState) -> axum::Router {
    dbward_server::routes::router(state)
}

fn get_audit_event_types(conn: &Connection) -> Vec<String> {
    let mut stmt = conn
        .prepare("SELECT event_type FROM audit_events ORDER BY rowid")
        .unwrap();
    stmt.query_map([], |row| row.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
}

fn req(method: &str, path: &str, token: &str, body: &str) -> axum::http::Request<axum::body::Body> {
    let builder = axum::http::Request::builder()
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .header("x-real-ip", "10.0.0.1");
    match method {
        "POST" => builder
            .method("POST")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap(),
        "PUT" => builder
            .method("PUT")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap(),
        "DELETE" => builder
            .method("DELETE")
            .body(axum::body::Body::empty())
            .unwrap(),
        _ => builder
            .method("GET")
            .body(axum::body::Body::empty())
            .unwrap(),
    }
}

#[tokio::test]
async fn request_lifecycle_produces_audit_events() {
    let state = test_state();
    let admin = admin_token(&state).await;
    let dev = dev_token(&state).await;
    let router = app(state.clone());

    // Create request (auto-approved in development)
    let resp = router
        .clone()
        .oneshot(req(
            "POST",
            "/api/requests",
            &dev,
            r#"{"operation":"execute_query","environment":"development","database":"app","detail":"SELECT 1"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let conn = state.sqlite.lock().await;
    let events = get_audit_event_types(&conn);
    drop(conn);

    // token_created events from setup + auto_approved from the request
    assert!(
        events.contains(&"auto_approved".to_string()),
        "Missing auto_approved audit event. Got: {events:?}"
    );
}

#[tokio::test]
async fn auth_failure_produces_audit_event() {
    let state = test_state();
    let router = app(state.clone());

    let resp = router
        .clone()
        .oneshot(req("GET", "/api/requests", "dbw_invalid_token_xyz", ""))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let conn = state.sqlite.lock().await;
    let events = get_audit_event_types(&conn);
    assert!(
        events.contains(&"auth_failure".to_string()),
        "Missing auth_failure audit event. Got: {events:?}"
    );
}

#[tokio::test]
async fn policy_crud_produces_audit_events() {
    let state = test_state();
    let admin = admin_token(&state).await;
    let router = app(state.clone());

    // Create workflow
    let resp = router
        .clone()
        .oneshot(req(
            "POST",
            "/api/workflows",
            &admin,
            r#"{"database":"test","environment":"staging","steps":[]}"#,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Update workflow
    let resp = router
        .clone()
        .oneshot(req(
            "PUT",
            "/api/workflows/test:staging",
            &admin,
            r#"{"steps":[]}"#,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Delete workflow
    let resp = router
        .clone()
        .oneshot(req("DELETE", "/api/workflows/test:staging", &admin, ""))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let conn = state.sqlite.lock().await;
    let events = get_audit_event_types(&conn);

    assert!(
        events.contains(&"policy_created".to_string()),
        "Missing policy_created. Got: {events:?}"
    );
    assert!(
        events.contains(&"policy_updated".to_string()),
        "Missing policy_updated. Got: {events:?}"
    );
    assert!(
        events.contains(&"policy_deleted".to_string()),
        "Missing policy_deleted. Got: {events:?}"
    );
}

#[tokio::test]
async fn webhook_crud_produces_audit_events() {
    let state = test_state();
    let admin = admin_token(&state).await;
    let router = app(state.clone());

    // Create webhook
    let resp = router
        .clone()
        .oneshot(req(
            "POST",
            "/api/webhooks",
            &admin,
            r#"{"url":"https://example.com/hook","events":["request_created"],"format":"generic"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 10000).await.unwrap())
            .unwrap();
    let wh_id = body["id"].as_str().unwrap().to_string();

    // Update webhook
    let resp = router
        .clone()
        .oneshot(req(
            "PUT",
            &format!("/api/webhooks/{wh_id}"),
            &admin,
            r#"{"url":"https://example.com/hook2"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Delete webhook
    let resp = router
        .clone()
        .oneshot(req("DELETE", &format!("/api/webhooks/{wh_id}"), &admin, ""))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let conn = state.sqlite.lock().await;
    let events = get_audit_event_types(&conn);

    assert!(
        events.contains(&"webhook_created".to_string()),
        "Missing webhook_created. Got: {events:?}"
    );
    assert!(
        events.contains(&"webhook_updated".to_string()),
        "Missing webhook_updated. Got: {events:?}"
    );
    assert!(
        events.contains(&"webhook_deleted".to_string()),
        "Missing webhook_deleted. Got: {events:?}"
    );
}

#[tokio::test]
async fn token_revoke_produces_audit_event() {
    let state = test_state();
    let admin = admin_token(&state).await;
    let router = app(state.clone());

    // Create token via API
    let resp = router
        .clone()
        .oneshot(req(
            "POST",
            "/api/tokens",
            &admin,
            r#"{"subject_id":"ci-bot","role":"readonly","subject_type":"user"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 10000).await.unwrap())
            .unwrap();
    let token_id = body["id"].as_str().unwrap().to_string();

    // Revoke
    let resp = router
        .clone()
        .oneshot(req(
            "DELETE",
            &format!("/api/tokens/{token_id}"),
            &admin,
            "",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let conn = state.sqlite.lock().await;
    let events = get_audit_event_types(&conn);

    assert!(
        events.contains(&"token_revoked".to_string()),
        "Missing token_revoked. Got: {events:?}"
    );
}

#[tokio::test]
async fn audit_events_have_client_ip_when_header_present() {
    let state = test_state();
    let dev = dev_token(&state).await;
    let router = app(state.clone());

    // Request with X-Real-IP header
    let _ = router
        .clone()
        .oneshot(req(
            "POST",
            "/api/requests",
            &dev,
            r#"{"operation":"execute_query","environment":"development","database":"app","detail":"SELECT 1"}"#,
        ))
        .await
        .unwrap();

    let conn = state.sqlite.lock().await;
    let ip: Option<String> = conn
        .query_row(
            "SELECT client_ip FROM audit_events WHERE event_type = 'auto_approved' LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();

    assert_eq!(
        ip.as_deref(),
        Some("10.0.0.1"),
        "IP should be recorded from X-Real-IP header"
    );
}
