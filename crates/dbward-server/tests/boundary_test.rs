//! Boundary/input validation tests: verify correct rejection of invalid inputs.

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

// ─── Operation validation ───

#[tokio::test]
async fn invalid_operation_rejected() {
    let state = test_state();
    let (_, token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let app = routes::router(state);

    let resp = app
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"operation":"drop_table","environment":"development","detail":"x"})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert_eq!(body["code"], "unknown_operation");
}

#[tokio::test]
async fn all_valid_operations_accepted() {
    let state = test_state();
    let (_, token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let app = routes::router(state);

    for op in [
        "execute_query",
        "migrate_up",
        "migrate_down",
        "migrate_status",
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/requests")
                    .header("authorization", auth_header(&token))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"operation": op, "environment":"development","detail":"x"})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "operation {op} should be accepted"
        );
    }
}

// ─── Metadata validation ───

#[tokio::test]
async fn metadata_not_object_rejected() {
    let state = test_state();
    let (_, token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let app = routes::router(state);

    for invalid in [json!("a string"), json!(["an", "array"]), json!(42)] {
        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/requests")
                    .header("authorization", auth_header(&token))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"operation":"execute_query","environment":"development","detail":"x","metadata": invalid}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = body_json(resp).await;
        assert_eq!(body["code"], "invalid_metadata");
    }
}

#[tokio::test]
async fn metadata_oversized_rejected() {
    let state = test_state();
    let (_, token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let app = routes::router(state);

    // Create metadata that serializes to > 8192 bytes
    let big = "x".repeat(8192);
    let resp = app
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"operation":"execute_query","environment":"development","detail":"x","metadata":{"blob": big}}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert_eq!(body["code"], "metadata_too_large");
}

#[tokio::test]
async fn metadata_at_exact_limit_accepted() {
    let state = test_state();
    let (_, token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let app = routes::router(state);

    // {"k":"..."} → overhead is {"k":""} = 6 bytes + quotes around value = 2 → 8 bytes overhead
    // We need total serialized JSON to be exactly 8192 bytes
    // {"k":"<padding>"} = 6 + padding_len bytes (the quotes around value are included in 6)
    // Actually: serde_json::to_string({"k":"x"}) = {"k":"x"} = 7 bytes
    // So for {"k":"<N chars>"} = 5 + N + 1 = 6 + N bytes... let's just measure
    let target = 8192;
    // {"k":""} is 6 bytes, each char in value adds 1
    let overhead = serde_json::to_string(&json!({"k":""})).unwrap().len();
    let padding = "a".repeat(target - overhead);
    let metadata = json!({"k": padding});
    let serialized_len = serde_json::to_string(&metadata).unwrap().len();
    assert_eq!(serialized_len, target);

    let resp = app
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"operation":"execute_query","environment":"development","detail":"x","metadata": metadata}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

// ─── Idempotency key validation ───

#[tokio::test]
async fn idempotency_key_empty_rejected() {
    let state = test_state();
    let (_, token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let app = routes::router(state);

    let resp = app
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"operation":"execute_query","environment":"development","detail":"x","idempotency_key":""}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert_eq!(body["code"], "invalid_idempotency_key");
}

#[tokio::test]
async fn idempotency_key_too_long_rejected() {
    let state = test_state();
    let (_, token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let app = routes::router(state);

    let long_key = "a".repeat(256);
    let resp = app
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"operation":"execute_query","environment":"development","detail":"x","idempotency_key": long_key}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert_eq!(body["code"], "idempotency_key_too_large");
}

#[tokio::test]
async fn idempotency_key_at_max_length_accepted() {
    let state = test_state();
    let (_, token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let app = routes::router(state);

    let max_key = "b".repeat(255);
    let resp = app
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"operation":"execute_query","environment":"development","detail":"x","idempotency_key": max_key}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn idempotency_key_duplicate_returns_existing() {
    let state = test_state();
    let (_, token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let app = routes::router(state);

    let payload = json!({
        "operation": "execute_query",
        "environment": "development",
        "detail": "SELECT 1",
        "idempotency_key": "dup-key-1"
    })
    .to_string();

    let resp1 = app
        .clone()
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&token))
                .header("content-type", "application/json")
                .body(Body::from(payload.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp1.status(), StatusCode::CREATED);
    let b1 = body_json(resp1).await;

    let resp2 = app
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&token))
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let b2 = body_json(resp2).await;
    assert_eq!(b2["idempotent"], true);
    assert_eq!(b2["id"], b1["id"]);
}

// ─── Unicode preservation ───

#[tokio::test]
async fn unicode_in_detail_preserved() {
    let state = test_state();
    let (_, token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let app = routes::router(state);

    let detail = "SELECT * FROM users WHERE name = '日本語テスト 🚀'";
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"operation":"execute_query","environment":"development","detail": detail}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let id = body_json(resp).await["id"].as_str().unwrap().to_string();

    let resp = app
        .oneshot(
            Request::get(format!("/api/requests/{id}"))
                .header("authorization", auth_header(&token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["detail"].as_str().unwrap(), detail);
}

// ─── Emergency without reason ───

#[tokio::test]
async fn emergency_without_reason_rejected() {
    let state = test_state();
    let (_, token) = auth::create_token(&state, "admin1", "admin").await.unwrap();
    let app = routes::router(state);

    let resp = app
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"operation":"execute_query","environment":"production","detail":"x","emergency":true}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert_eq!(body["code"], "emergency_reason_required");
}
