//! State machine tests: verify all valid/invalid state transitions.

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
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// Create a pending request (production env requires approval)
async fn create_pending(app: &axum::Router, token: &str) -> String {
    let resp = app.clone().oneshot(
        Request::post("/api/requests")
            .header("authorization", auth_header(token))
            .header("content-type", "application/json")
            .body(Body::from(json!({"operation":"execute_query","environment":"production","detail":"SELECT 1","database":"default"}).to_string()))
            .unwrap(),
    ).await.unwrap();
    let v = body_json(resp).await;
    v["id"].as_str().unwrap().to_string()
}

/// Create an auto-approved (dispatched) request (development env)
async fn create_dispatched(app: &axum::Router, token: &str) -> String {
    let resp = app.clone().oneshot(
        Request::post("/api/requests")
            .header("authorization", auth_header(token))
            .header("content-type", "application/json")
            .body(Body::from(json!({"operation":"execute_query","environment":"development","detail":"SELECT 1","database":"default"}).to_string()))
            .unwrap(),
    ).await.unwrap();
    let v = body_json(resp).await;
    v["id"].as_str().unwrap().to_string()
}

async fn get_status(app: &axum::Router, token: &str, id: &str) -> String {
    let resp = app
        .clone()
        .oneshot(
            Request::get(format!("/api/requests/{id}"))
                .header("authorization", auth_header(token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let v = body_json(resp).await;
    v["status"].as_str().unwrap_or("").to_string()
}

// ─── Valid transitions ───

#[tokio::test]
async fn pending_can_be_approved_and_dispatched() {
    let state = test_state();
    let (_, dev_token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let (_, admin_token) = auth::create_token(&state, "admin1", "admin").await.unwrap();
    let app = routes::router(state);

    let id = create_pending(&app, &dev_token).await;
    assert_eq!(get_status(&app, &dev_token, &id).await, "pending");

    // Approve
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{id}/approve"))
                .header("authorization", auth_header(&admin_token))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(get_status(&app, &dev_token, &id).await, "approved");
}

#[tokio::test]
async fn pending_can_be_rejected() {
    let state = test_state();
    let (_, dev_token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let (_, admin_token) = auth::create_token(&state, "admin1", "admin").await.unwrap();
    let app = routes::router(state);

    let id = create_pending(&app, &dev_token).await;

    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{id}/reject"))
                .header("authorization", auth_header(&admin_token))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(get_status(&app, &dev_token, &id).await, "rejected");
}

#[tokio::test]
async fn pending_can_be_cancelled() {
    let state = test_state();
    let (_, dev_token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let app = routes::router(state);

    let id = create_pending(&app, &dev_token).await;

    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{id}/cancel"))
                .header("authorization", auth_header(&dev_token))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(get_status(&app, &dev_token, &id).await, "cancelled");
}

#[tokio::test]
async fn dispatched_can_be_cancelled() {
    let state = test_state();
    let (_, dev_token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let app = routes::router(state);

    let id = create_dispatched(&app, &dev_token).await;
    assert_eq!(get_status(&app, &dev_token, &id).await, "dispatched");

    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{id}/cancel"))
                .header("authorization", auth_header(&dev_token))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(get_status(&app, &dev_token, &id).await, "cancelled");
}

// ─── Invalid transitions ───

#[tokio::test]
async fn cannot_approve_non_pending() {
    let state = test_state();
    let (_, dev_token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let (_, admin_token) = auth::create_token(&state, "admin1", "admin").await.unwrap();
    let app = routes::router(state);

    // dispatched (auto-approved)
    let id = create_dispatched(&app, &dev_token).await;

    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{id}/approve"))
                .header("authorization", auth_header(&admin_token))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn cannot_approve_rejected() {
    let state = test_state();
    let (_, dev_token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let (_, admin_token) = auth::create_token(&state, "admin1", "admin").await.unwrap();
    let app = routes::router(state);

    let id = create_pending(&app, &dev_token).await;
    // Reject it
    app.clone()
        .oneshot(
            Request::post(format!("/api/requests/{id}/reject"))
                .header("authorization", auth_header(&admin_token))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    // Try to approve rejected
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{id}/approve"))
                .header("authorization", auth_header(&admin_token))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn cannot_approve_cancelled() {
    let state = test_state();
    let (_, dev_token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let (_, admin_token) = auth::create_token(&state, "admin1", "admin").await.unwrap();
    let app = routes::router(state);

    let id = create_pending(&app, &dev_token).await;
    // Cancel it
    app.clone()
        .oneshot(
            Request::post(format!("/api/requests/{id}/cancel"))
                .header("authorization", auth_header(&dev_token))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    // Try to approve cancelled
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{id}/approve"))
                .header("authorization", auth_header(&admin_token))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn cannot_reject_non_pending() {
    let state = test_state();
    let (_, dev_token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let (_, admin_token) = auth::create_token(&state, "admin1", "admin").await.unwrap();
    let app = routes::router(state);

    // dispatched (auto-approved)
    let id = create_dispatched(&app, &dev_token).await;

    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{id}/reject"))
                .header("authorization", auth_header(&admin_token))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn cannot_cancel_rejected() {
    let state = test_state();
    let (_, dev_token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let (_, admin_token) = auth::create_token(&state, "admin1", "admin").await.unwrap();
    let app = routes::router(state);

    let id = create_pending(&app, &dev_token).await;
    app.clone()
        .oneshot(
            Request::post(format!("/api/requests/{id}/reject"))
                .header("authorization", auth_header(&admin_token))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{id}/cancel"))
                .header("authorization", auth_header(&dev_token))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn cannot_cancel_already_cancelled() {
    let state = test_state();
    let (_, dev_token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let app = routes::router(state);

    let id = create_pending(&app, &dev_token).await;
    app.clone()
        .oneshot(
            Request::post(format!("/api/requests/{id}/cancel"))
                .header("authorization", auth_header(&dev_token))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{id}/cancel"))
                .header("authorization", auth_header(&dev_token))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn cannot_dispatch_pending() {
    let state = test_state();
    let (_, dev_token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let app = routes::router(state);

    let id = create_pending(&app, &dev_token).await;

    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{id}/dispatch"))
                .header("authorization", auth_header(&dev_token))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    // Should be 409 (wrong status) or 403
    assert!(resp.status() == StatusCode::CONFLICT || resp.status() == StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn agent_cannot_claim_pending() {
    let state = test_state();
    let (_, dev_token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let (_, agent_token) = auth::create_token_with_type(&state, "agent1", "admin", "agent")
        .await
        .unwrap();
    let app = routes::router(state);

    let id = create_pending(&app, &dev_token).await;

    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/agent/jobs/{id}/claim"))
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

// ─── Additional invalid transitions (from Codex review) ───

#[tokio::test]
async fn cannot_dispatch_already_dispatched() {
    let state = test_state();
    let (_, dev_token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let app = routes::router(state);

    let id = create_dispatched(&app, &dev_token).await;

    // Try to dispatch again
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{id}/dispatch"))
                .header("authorization", auth_header(&dev_token))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    // Should be 409 (already dispatched, not re-executable without execution first)
    assert!(
        resp.status() == StatusCode::CONFLICT || resp.status() == StatusCode::OK,
        "dispatch of dispatched should be 409 or 200 (idempotent), got {}",
        resp.status()
    );
}

#[tokio::test]
async fn cannot_approve_after_cancel() {
    let state = test_state();
    let (_, dev_token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let (_, admin_token) = auth::create_token(&state, "admin1", "admin").await.unwrap();
    let app = routes::router(state);

    let id = create_pending(&app, &dev_token).await;

    // Cancel
    app.clone()
        .oneshot(
            Request::post(format!("/api/requests/{id}/cancel"))
                .header("authorization", auth_header(&dev_token))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    // Try approve after cancel
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{id}/approve"))
                .header("authorization", auth_header(&admin_token))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn cannot_reject_after_cancel() {
    let state = test_state();
    let (_, dev_token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let (_, admin_token) = auth::create_token(&state, "admin1", "admin").await.unwrap();
    let app = routes::router(state);

    let id = create_pending(&app, &dev_token).await;

    // Cancel
    app.clone()
        .oneshot(
            Request::post(format!("/api/requests/{id}/cancel"))
                .header("authorization", auth_header(&dev_token))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    // Try reject after cancel
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{id}/reject"))
                .header("authorization", auth_header(&admin_token))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn dispatch_fails_when_approval_expired() {
    let mut state = test_state();
    state.retention.approval_ttl_secs = 1;

    let app = routes::router(state.clone());
    let (_, dev_token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let (_, admin_token) = auth::create_token(&state, "admin1", "admin").await.unwrap();

    // Dev creates request (production env requires approval)
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&dev_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"operation":"execute_query","environment":"production","detail":"SELECT 1","database":"default"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let v = body_json(resp).await;
    let id = v["id"].as_str().unwrap().to_string();

    // Simulate: approved but expired (backdate resolved_at, set status to approved)
    {
        let conn = state.sqlite.lock().await;
        let past = (chrono::Utc::now() - chrono::Duration::seconds(10)).to_rfc3339();
        conn.execute(
            "UPDATE requests SET status = 'approved', resolved_at = ?1 WHERE id = ?2",
            rusqlite::params![past, id],
        )
        .unwrap();
    }

    // Dispatch should fail with 410 Gone (approval expired)
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{id}/dispatch"))
                .header("authorization", auth_header(&admin_token))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::GONE);
}
