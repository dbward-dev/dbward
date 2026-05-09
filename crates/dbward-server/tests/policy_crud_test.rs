//! Integration tests for policy CRUD endpoints (workflows, execution, result, notification).

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
        webhooks: Arc::new(std::sync::RwLock::new(dbward_server::webhook::WebhookDispatcher::empty())),
        metrics: Arc::new(Metrics::new()),
        oidc: None,
        auth_mode: "token".to_string(),
        result_channels: Arc::new(ResultChannels::new()),
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

async fn admin_token(state: &AppState) -> String {
    auth::create_token(state, "admin1", "admin")
        .await
        .unwrap()
        .1
}

async fn json_body(resp: axum::response::Response) -> Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

// ─── Workflow CRUD ───

#[tokio::test]
async fn create_workflow_minimal() {
    let state = test_state();
    let app = routes::router(state.clone());
    let token = admin_token(&state).await;

    let resp = app
        .oneshot(
            Request::post("/api/workflows")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"database":"testdb","environment":"staging"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = json_body(resp).await;
    assert_eq!(body["id"], "testdb:staging");
}

#[tokio::test]
async fn create_workflow_missing_database() {
    let state = test_state();
    let app = routes::router(state.clone());
    let token = admin_token(&state).await;

    let resp = app
        .oneshot(
            Request::post("/api/workflows")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"environment":"staging"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_workflow_duplicate() {
    let state = test_state();
    let token = admin_token(&state).await;

    let make_req = || {
        Request::post("/api/workflows")
            .header("authorization", format!("Bearer {}", token.clone()))
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"database":"dupdb","environment":"dev"}).to_string(),
            ))
            .unwrap()
    };

    let app = routes::router(state.clone());
    let resp = app.oneshot(make_req()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let app = routes::router(state.clone());
    let resp = app.oneshot(make_req()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn list_workflows() {
    let state = test_state();
    let token = admin_token(&state).await;

    // Create 2 API workflows (in addition to the 2 config-sourced ones)
    for (db, env) in [("listdb1", "dev"), ("listdb2", "prod")] {
        let app = routes::router(state.clone());
        app.oneshot(
            Request::post("/api/workflows")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"database": db, "environment": env}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    }

    let app = routes::router(state.clone());
    let resp = app
        .oneshot(
            Request::get("/api/workflows")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert!(body["workflows"].as_array().unwrap().len() >= 2);
}

#[tokio::test]
async fn get_workflow_by_id() {
    let state = test_state();
    let token = admin_token(&state).await;

    let app = routes::router(state.clone());
    app.oneshot(
        Request::post("/api/workflows")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"database":"testdb","environment":"staging"}).to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    let app = routes::router(state.clone());
    let resp = app
        .oneshot(
            Request::get("/api/workflows/testdb:staging")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["id"], "testdb:staging");
}

#[tokio::test]
async fn get_workflow_not_found() {
    let state = test_state();
    let app = routes::router(state.clone());
    let token = admin_token(&state).await;

    let resp = app
        .oneshot(
            Request::get("/api/workflows/nonexistent:id")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn update_workflow() {
    let state = test_state();
    let token = admin_token(&state).await;

    let app = routes::router(state.clone());
    app.oneshot(
        Request::post("/api/workflows")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"database":"testdb","environment":"staging"}).to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    let app = routes::router(state.clone());
    let resp = app
        .oneshot(
            Request::put("/api/workflows/testdb:staging")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"require_reason": true}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn delete_workflow() {
    let state = test_state();
    let token = admin_token(&state).await;

    let app = routes::router(state.clone());
    app.oneshot(
        Request::post("/api/workflows")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"database":"testdb","environment":"staging"}).to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    let app = routes::router(state.clone());
    let resp = app
        .oneshot(
            Request::delete("/api/workflows/testdb:staging")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn delete_workflow_not_found() {
    let state = test_state();
    let app = routes::router(state.clone());
    let token = admin_token(&state).await;

    let resp = app
        .oneshot(
            Request::delete("/api/workflows/nonexistent:id")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn update_workflow_blocked_by_pending() {
    let state = test_state();
    let token = admin_token(&state).await;

    // Create a workflow with approval steps for mydb:production
    let app = routes::router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/workflows")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "database": "mydb",
                        "environment": "production",
                        "steps": [{
                            "type": "approval",
                            "mode": "all",
                            "approvers": [{"role": "admin", "min": 1}],
                            "require_distinct_actors": true
                        }]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Create a request targeting mydb:production → goes to pending
    let app = routes::router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "operation": "execute_query",
                        "database": "mydb",
                        "environment": "production",
                        "detail": "SELECT 1"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = json_body(resp).await;
    assert_eq!(body["status"], "pending");

    // Try to update the workflow → 409
    let app = routes::router(state.clone());
    let resp = app
        .oneshot(
            Request::put("/api/workflows/mydb:production")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"require_reason": true}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

// ─── Execution Policy CRUD ───

#[tokio::test]
async fn create_execution_policy() {
    let state = test_state();
    let app = routes::router(state.clone());
    let token = admin_token(&state).await;

    let resp = app
        .oneshot(
            Request::post("/api/execution-policies")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"database":"db1","environment":"prod"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = json_body(resp).await;
    assert_eq!(body["id"], "db1:prod");
}

#[tokio::test]
async fn get_execution_policy() {
    let state = test_state();
    let token = admin_token(&state).await;

    let app = routes::router(state.clone());
    app.oneshot(
        Request::post("/api/execution-policies")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"database":"db1","environment":"prod"}).to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    let app = routes::router(state.clone());
    let resp = app
        .oneshot(
            Request::get("/api/execution-policies/db1:prod")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert!(body.get("max_executions").is_some());
    assert!(body.get("execution_window_secs").is_some());
    assert!(body.get("retry_on_failure").is_some());
}

#[tokio::test]
async fn delete_execution_policy() {
    let state = test_state();
    let token = admin_token(&state).await;

    let app = routes::router(state.clone());
    app.oneshot(
        Request::post("/api/execution-policies")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"database":"db1","environment":"prod"}).to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    let app = routes::router(state.clone());
    let resp = app
        .oneshot(
            Request::delete("/api/execution-policies/db1:prod")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

// ─── Result Policy CRUD ───

#[tokio::test]
async fn create_result_policy() {
    let state = test_state();
    let app = routes::router(state.clone());
    let token = admin_token(&state).await;

    let resp = app
        .oneshot(
            Request::post("/api/result-policies")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"database":"db1","environment":"prod","delivery_mode":"stream"})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = json_body(resp).await;
    assert_eq!(body["id"], "db1:prod");
}

#[tokio::test]
async fn delete_result_policy() {
    let state = test_state();
    let token = admin_token(&state).await;

    let app = routes::router(state.clone());
    app.oneshot(
        Request::post("/api/result-policies")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"database":"db1","environment":"prod","delivery_mode":"stream"}).to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    let app = routes::router(state.clone());
    let resp = app
        .oneshot(
            Request::delete("/api/result-policies/db1:prod")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

// ─── Notification Policy CRUD ───

#[tokio::test]
async fn create_notification_policy() {
    let state = test_state();
    let app = routes::router(state.clone());
    let token = admin_token(&state).await;

    let resp = app
        .oneshot(
            Request::post("/api/notification-policies")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"database":"db1","environment":"prod","webhooks":[]}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = json_body(resp).await;
    assert_eq!(body["id"], "db1:prod");
}

#[tokio::test]
async fn delete_notification_policy() {
    let state = test_state();
    let token = admin_token(&state).await;

    let app = routes::router(state.clone());
    app.oneshot(
        Request::post("/api/notification-policies")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"database":"db1","environment":"prod","webhooks":[]}).to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    let app = routes::router(state.clone());
    let resp = app
        .oneshot(
            Request::delete("/api/notification-policies/db1:prod")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}
