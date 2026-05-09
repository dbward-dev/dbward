use axum::body::Body;
use axum::http::{Request, StatusCode};
use dbward_server::db;
use dbward_server::license::{License, Plan};
use dbward_server::routes::router;
use dbward_server::token::TokenSigner;
use dbward_server::AppState;
use rusqlite::Connection;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;

fn free_state() -> AppState {
    let conn = Connection::open_in_memory().unwrap();
    db::init(&conn).unwrap();
    let signer = TokenSigner::generate();
    AppState {
        license: License { plan: Plan::Free },
        sqlite: Arc::new(Mutex::new(conn)),
        token_signer: Arc::new(signer),
        webhooks: Arc::new(std::sync::RwLock::new(dbward_server::webhook::WebhookDispatcher::empty())),
        metrics: Arc::new(dbward_server::Metrics::new()),
        oidc: None,
        auth_mode: "token".to_string(),
        result_channels: Arc::new(dbward_server::ResultChannels::new()),
        retention: Default::default(),
        request_notifier: Arc::new(dbward_server::RequestNotifier::new()),
        result_store: Arc::new(dbward_server::result_storage::ResultStore::new_local(&std::env::temp_dir().join("dbward-test").to_string_lossy()).unwrap()),
        draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        break_glass_roles: dbward_server::server_config::default_break_glass_roles(),
        audit_config: Default::default(),
        trusted_proxies: vec![],
        update_available: Arc::new(Mutex::new(None)),
        update_check_enabled: false,
    }
}

async fn create_token(state: &AppState) -> String {
    let (_, raw) =
        dbward_server::auth::create_token_with_type(state, "admin", "admin", "user")
            .await
            .unwrap();
    raw
}

async fn post_json(
    state: &AppState,
    path: &str,
    body: serde_json::Value,
    token: &str,
) -> axum::response::Response {
    let app = router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    app.oneshot(req).await.unwrap()
}

#[tokio::test]
async fn free_tier_blocks_workflow_at_limit() {
    let state = free_state();
    let token = create_token(&state).await;

    // Create 5 workflows (should succeed)
    for i in 0..5 {
        let resp = post_json(
            &state,
            "/api/workflows",
            json!({"database": format!("db{i}"), "environment": "prod", "steps": []}),
            &token,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED, "workflow {i} should succeed");
    }

    // 6th should fail with 402
    let resp = post_json(
        &state,
        "/api/workflows",
        json!({"database": "db_extra", "environment": "prod", "steps": []}),
        &token,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
}

#[tokio::test]
async fn free_tier_blocks_execution_policy_at_limit() {
    let state = free_state();
    let token = create_token(&state).await;

    for i in 0..3 {
        let resp = post_json(
            &state,
            "/api/execution-policies",
            json!({"database": format!("db{i}"), "environment": "prod", "max_executions": 10}),
            &token,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED, "policy {i} should succeed");
    }

    let resp = post_json(
        &state,
        "/api/execution-policies",
        json!({"database": "db_extra", "environment": "prod", "max_executions": 10}),
        &token,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
}

#[tokio::test]
async fn free_tier_blocks_result_policy_creation() {
    let state = free_state();
    let token = create_token(&state).await;

    let resp = post_json(
        &state,
        "/api/result-policies",
        json!({"database": "app", "environment": "prod", "delivery_mode": "stream"}),
        &token,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
}

#[tokio::test]
async fn free_tier_blocks_notification_policy_creation() {
    let state = free_state();
    let token = create_token(&state).await;

    let resp = post_json(
        &state,
        "/api/notification-policies",
        json!({"database": "app", "environment": "prod", "webhooks": []}),
        &token,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
}

#[tokio::test]
async fn free_tier_blocks_share_with() {
    let state = free_state();
    let token = create_token(&state).await;

    let resp = post_json(
        &state,
        "/api/requests",
        json!({
            "operation": "execute_query",
            "environment": "development",
            "database": "app",
            "detail": "SELECT 1",
            "share_with": ["user:bob"]
        }),
        &token,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
}
