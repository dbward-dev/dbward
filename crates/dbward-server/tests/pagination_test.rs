//! Pagination and filtering tests for /api/requests and /api/audit endpoints.

use axum::body::Body;
use axum::http::StatusCode;
use http_body_util::BodyExt;
use hyper::Request;
use rusqlite::Connection;
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;

use dbward_server::{AppState, Metrics, ResultChannels, auth, db, routes, token::TokenSigner};

fn test_state() -> AppState {
    let conn = Connection::open_in_memory().unwrap();
    db::init(&conn).unwrap();
    let workflows = vec![
        dbward_server::server_config::WorkflowDef {
            database: "*".into(),
            environment: "development".into(),
            operations: vec![],
            steps: vec![],
            require_reason: false,
            allow_same_approver_across_steps: false,
            allow_self_approve: false,
        },
        dbward_server::server_config::WorkflowDef {
            database: "*".into(),
            environment: "production".into(),
            operations: vec![],
            steps: vec![dbward_server::server_config::WorkflowStep {
                step_type: "approval".into(),
                mode: "all".into(),
                approvers: vec![dbward_server::server_config::ApproverGroup {
                    role: Some("admin".into()),
                    group: None,
                    min: 1,
                }],
                require_distinct_actors: true,
            }],
            require_reason: false,
            allow_same_approver_across_steps: false,
            allow_self_approve: false,
        },
    ];
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

fn auth_header(token: &str) -> String {
    format!("Bearer {token}")
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

async fn create_request(app: &axum::Router, token: &str, env: &str) -> String {
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "operation": "execute_query",
                        "environment": env,
                        "detail": "SELECT 1"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        resp.status() == StatusCode::OK || resp.status() == StatusCode::CREATED,
        "create_request failed: {}",
        resp.status()
    );
    let body = body_json(resp).await;
    body["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn default_pagination_limit_50_offset_0() {
    let state = test_state();
    let (_, admin_token) = auth::create_token(&state, "admin1", "admin").await.unwrap();
    let app = routes::router(state);

    let resp = app
        .oneshot(
            Request::get("/api/requests")
                .header("authorization", auth_header(&admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["limit"], 50);
    assert_eq!(body["offset"], 0);
}

#[tokio::test]
async fn custom_limit_and_offset() {
    let state = test_state();
    let (_, dev_token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let (_, admin_token) = auth::create_token(&state, "admin1", "admin").await.unwrap();
    let app = routes::router(state);

    // Create 5 requests in development (auto-approved)
    for _ in 0..5 {
        create_request(&app, &dev_token, "development").await;
    }

    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/requests?limit=2&offset=1")
                .header("authorization", auth_header(&admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["requests"].as_array().unwrap().len(), 2);
    assert_eq!(body["total"], 5);
    assert_eq!(body["limit"], 2);
    assert_eq!(body["offset"], 1);
}

#[tokio::test]
async fn limit_clamped_to_max_200() {
    let state = test_state();
    let (_, admin_token) = auth::create_token(&state, "admin1", "admin").await.unwrap();
    let app = routes::router(state);

    let resp = app
        .oneshot(
            Request::get("/api/requests?limit=500")
                .header("authorization", auth_header(&admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["limit"], 200);
}

#[tokio::test]
async fn limit_clamped_to_min_1() {
    let state = test_state();
    let (_, admin_token) = auth::create_token(&state, "admin1", "admin").await.unwrap();
    let app = routes::router(state);

    let resp = app
        .oneshot(
            Request::get("/api/requests?limit=0")
                .header("authorization", auth_header(&admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["limit"], 1);
}

#[tokio::test]
async fn offset_beyond_total_returns_empty() {
    let state = test_state();
    let (_, dev_token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let (_, admin_token) = auth::create_token(&state, "admin1", "admin").await.unwrap();
    let app = routes::router(state);

    // Create 3 requests
    for _ in 0..3 {
        create_request(&app, &dev_token, "development").await;
    }

    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/requests?offset=9999")
                .header("authorization", auth_header(&admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert!(body["requests"].as_array().unwrap().is_empty());
    assert_eq!(body["total"], 3);
}

#[tokio::test]
async fn filter_by_status() {
    let state = test_state();
    let (_, dev_token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let (_, admin_token) = auth::create_token(&state, "admin1", "admin").await.unwrap();
    let app = routes::router(state);

    // development → auto_approved/dispatched
    create_request(&app, &dev_token, "development").await;
    create_request(&app, &dev_token, "development").await;

    // production → pending (requires approval)
    create_request(&app, &dev_token, "production").await;

    // Filter by status=pending
    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/requests?status=pending")
                .header("authorization", auth_header(&admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let requests = body["requests"].as_array().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["status"], "pending");
    assert_eq!(body["total"], 1);
}

#[tokio::test]
async fn filter_by_environment() {
    let state = test_state();
    let (_, dev_token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let (_, admin_token) = auth::create_token(&state, "admin1", "admin").await.unwrap();
    let app = routes::router(state);

    // Create requests in different environments
    create_request(&app, &dev_token, "development").await;
    create_request(&app, &dev_token, "development").await;
    create_request(&app, &dev_token, "production").await;

    // Filter by environment=production
    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/requests?environment=production")
                .header("authorization", auth_header(&admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let requests = body["requests"].as_array().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["environment"], "production");
    assert_eq!(body["total"], 1);

    // Filter by environment=development
    let resp = app
        .oneshot(
            Request::get("/api/requests?environment=development")
                .header("authorization", auth_header(&admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["requests"].as_array().unwrap().len(), 2);
    assert_eq!(body["total"], 2);
}

#[tokio::test]
async fn audit_pagination_works() {
    let state = test_state();
    let (_, dev_token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let (_, admin_token) = auth::create_token(&state, "admin1", "admin").await.unwrap();
    let app = routes::router(state);

    // Create multiple requests to generate audit events
    for _ in 0..4 {
        create_request(&app, &dev_token, "development").await;
    }

    // Admin can see all audit events; verify pagination
    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/audit/events?limit=2&offset=0")
                .header("authorization", auth_header(&admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let entries = body["audit_events"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(body["limit"], 2);
    assert_eq!(body["offset"], 0);
    let total = body["total"].as_i64().unwrap();
    assert!(total >= 4);

    // Second page
    let resp = app
        .oneshot(
            Request::get("/api/audit/events?limit=2&offset=2")
                .header("authorization", auth_header(&admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let entries = body["audit_events"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(body["limit"], 2);
    assert_eq!(body["offset"], 2);
    assert_eq!(body["total"].as_i64().unwrap(), total);
}
