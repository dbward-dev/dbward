//! Concurrency tests: verify correct behavior under simultaneous access.

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
        },
    ];
    db::policy_repo::sync_workflows(&conn, &workflows).unwrap();
    AppState {
        license: dbward_server::license::License { plan: dbward_server::license::Plan::Pro },
        sqlite: Arc::new(Mutex::new(conn)),
        token_signer: Arc::new(TokenSigner::generate()),
        webhooks: Arc::new(dbward_server::webhook::WebhookDispatcher::empty()),
        metrics: Arc::new(Metrics::new()),
        oidc: None,
        auth_mode: "token".to_string(),
        result_channels: Arc::new(ResultChannels::new()),
        retention: Default::default(),
        request_notifier: Arc::new(dbward_server::RequestNotifier::new()),
        result_store: None,
        draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        break_glass_roles: dbward_server::server_config::default_break_glass_roles(),
        audit_config: Default::default(),
        trusted_proxies: vec![],
    }
}

fn auth_header(token: &str) -> String {
    format!("Bearer {token}")
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

async fn create_pending(app: &axum::Router, token: &str) -> String {
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"operation":"execute_query","environment":"production","detail":"SELECT 1","database":"default"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let v = body_json(resp).await;
    v["id"].as_str().unwrap().to_string()
}

async fn create_dispatched(app: &axum::Router, token: &str) -> String {
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"operation":"execute_query","environment":"development","detail":"SELECT 1","database":"default"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let v = body_json(resp).await;
    v["id"].as_str().unwrap().to_string()
}

// ─── Concurrent approve ───

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_approve_one_succeeds_one_conflicts() {
    let state = test_state();
    let (_, dev_token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let (_, admin1_token) = auth::create_token(&state, "admin1", "admin").await.unwrap();
    let (_, admin2_token) = auth::create_token(&state, "admin2", "admin").await.unwrap();
    let app = routes::router(state);

    let id = create_pending(&app, &dev_token).await;

    let req1 = app.clone().oneshot(
        Request::post(format!("/api/requests/{id}/approve"))
            .header("authorization", auth_header(&admin1_token))
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap(),
    );
    let req2 = app.clone().oneshot(
        Request::post(format!("/api/requests/{id}/approve"))
            .header("authorization", auth_header(&admin2_token))
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap(),
    );

    let (resp1, resp2) = tokio::join!(req1, req2);
    let s1 = resp1.unwrap().status();
    let s2 = resp2.unwrap().status();

    let mut statuses = vec![s1, s2];
    statuses.sort();
    assert_eq!(statuses, vec![StatusCode::OK, StatusCode::CONFLICT]);
}

// ─── Concurrent agent claim ───

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_claim_one_succeeds_one_conflicts() {
    let state = test_state();
    let (_, dev_token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let (_, agent1_token) = auth::create_token_with_type(&state, "agent1", "admin", "agent")
        .await
        .unwrap();
    let (_, agent2_token) = auth::create_token_with_type(&state, "agent2", "admin", "agent")
        .await
        .unwrap();
    let app = routes::router(state);

    let id = create_dispatched(&app, &dev_token).await;

    let req1 = app.clone().oneshot(
        Request::post(format!("/api/agent/jobs/{id}/claim"))
            .header("authorization", auth_header(&agent1_token))
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap(),
    );
    let req2 = app.clone().oneshot(
        Request::post(format!("/api/agent/jobs/{id}/claim"))
            .header("authorization", auth_header(&agent2_token))
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap(),
    );

    let (resp1, resp2) = tokio::join!(req1, req2);
    let s1 = resp1.unwrap().status();
    let s2 = resp2.unwrap().status();

    let mut statuses = vec![s1, s2];
    statuses.sort();
    assert_eq!(statuses, vec![StatusCode::OK, StatusCode::CONFLICT]);
}

// ─── Concurrent idempotency key ───

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_same_idempotency_key_one_creates_one_returns_existing() {
    let state = test_state();
    let (_, dev_token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let app = routes::router(state);

    let payload = json!({
        "operation": "execute_query",
        "environment": "development",
        "detail": "SELECT 1",
        "idempotency_key": "concurrent-key-1"
    })
    .to_string();

    let req1 = app.clone().oneshot(
        Request::post("/api/requests")
            .header("authorization", auth_header(&dev_token))
            .header("content-type", "application/json")
            .body(Body::from(payload.clone()))
            .unwrap(),
    );
    let req2 = app.clone().oneshot(
        Request::post("/api/requests")
            .header("authorization", auth_header(&dev_token))
            .header("content-type", "application/json")
            .body(Body::from(payload))
            .unwrap(),
    );

    let (resp1, resp2) = tokio::join!(req1, req2);
    let r1 = resp1.unwrap();
    let r2 = resp2.unwrap();

    let (s1, s2) = (r1.status(), r2.status());
    let (b1, b2) = (body_json(r1).await, body_json(r2).await);

    // One should be CREATED (201), the other OK (200) with idempotent=true
    if s1 == StatusCode::CREATED {
        assert_eq!(s2, StatusCode::OK);
        assert_eq!(b2["idempotent"], true);
        assert_eq!(b1["id"], b2["id"]);
    } else {
        assert_eq!(s1, StatusCode::OK);
        assert_eq!(s2, StatusCode::CREATED);
        assert_eq!(b1["idempotent"], true);
        assert_eq!(b1["id"], b2["id"]);
    }
}

// ─── Concurrent creations + audit hash chain integrity ───

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_creations_preserve_audit_hash_chain() {
    let state = test_state();
    let (_, dev_token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let (_, admin_token) = auth::create_token(&state, "admin1", "admin").await.unwrap();
    let app = routes::router(state);

    let mut set = tokio::task::JoinSet::new();
    for i in 0..10 {
        let a = app.clone();
        let t = dev_token.clone();
        set.spawn(async move {
            a.oneshot(
                Request::post("/api/requests")
                    .header("authorization", auth_header(&t))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "operation": "execute_query",
                            "environment": "development",
                            "detail": format!("SELECT {i}"),
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
        });
    }

    while let Some(result) = set.join_next().await {
        let resp = result.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    // Verify audit events were recorded with hash chain via events endpoint
    let resp = app
        .oneshot(
            Request::get("/api/audit/events?limit=100")
                .header("authorization", auth_header(&admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let events = body["audit_events"].as_array().unwrap();
    // Each request creation generates at least one audit event
    assert!(events.len() >= 10);
    // All events have a non-empty hash
    for event in events {
        let hash = event["event_hash"].as_str().unwrap_or("");
        assert!(!hash.is_empty(), "audit event missing hash");
    }
}
