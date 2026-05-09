//! Authorization matrix tests: verify all role × endpoint combinations.

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
    let workflows = vec![dbward_server::server_config::WorkflowDef {
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
    }];
    db::policy_repo::sync_workflows(&conn, &workflows).unwrap();
    AppState {
        license: dbward_server::license::License { plan: dbward_server::license::Plan::Pro },
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

async fn status(resp: axum::response::Response) -> StatusCode {
    resp.status()
}

async fn create_request(app: &axum::Router, token: &str, env: &str) -> String {
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"operation":"execute_query","environment":env,"detail":"SELECT 1","database":"default"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    v["id"].as_str().unwrap_or("").to_string()
}

// ─── 1. No auth → 401 ───

#[tokio::test]
async fn no_auth_returns_401_for_protected_endpoints() {
    let app = routes::router(test_state());
    let paths = vec![
        ("GET", "/api/requests"),
        ("POST", "/api/requests"),
        ("GET", "/api/audit"),
        ("GET", "/api/workflows"),
        ("POST", "/api/agent/poll"),
    ];
    for (method, path) in paths {
        let req = match method {
            "POST" => Request::post(path)
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
            _ => Request::get(path).body(Body::empty()).unwrap(),
        };
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "expected 401 for {method} {path}"
        );
    }
}

#[tokio::test]
async fn malformed_auth_returns_401() {
    let app = routes::router(test_state());
    let cases = vec!["Basic dXNlcjpwYXNz", "Bearer ", "Token abc"];
    for header_val in cases {
        let resp = app
            .clone()
            .oneshot(
                Request::get("/api/requests")
                    .header("authorization", header_val)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "expected 401 for auth={header_val}"
        );
    }
}

// ─── 2. Admin role ───

#[tokio::test]
async fn admin_can_list_all_requests() {
    let state = test_state();
    let (_, admin_token) = auth::create_token(&state, "admin1", "admin").await.unwrap();
    let (_, dev_token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let app = routes::router(state);

    // dev creates a request
    create_request(&app, &dev_token, "production").await;

    // admin can see it
    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/requests")
                .header("authorization", format!("Bearer {admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(v["total"].as_i64().unwrap() >= 1);
}

#[tokio::test]
async fn admin_can_crud_workflows() {
    let state = test_state();
    let (_, token) = auth::create_token(&state, "admin1", "admin").await.unwrap();
    let app = routes::router(state);
    let auth = format!("Bearer {token}");

    // Create
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/workflows")
                .header("authorization", &auth)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"database":"testdb","environment":"staging"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // List
    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/workflows")
                .header("authorization", &auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Get
    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/workflows/testdb:staging")
                .header("authorization", &auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Delete
    let resp = app
        .clone()
        .oneshot(
            Request::delete("/api/workflows/testdb:staging")
                .header("authorization", &auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn admin_user_cannot_use_agent_endpoints() {
    let state = test_state();
    let (_, token) = auth::create_token(&state, "admin1", "admin").await.unwrap();
    let app = routes::router(state);

    let resp = app
        .oneshot(
            Request::post("/api/agent/poll")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ─── 3. Developer role ───

#[tokio::test]
async fn developer_cannot_get_others_request() {
    let state = test_state();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, bob_token) = auth::create_token(&state, "bob", "developer")
        .await
        .unwrap();
    let app = routes::router(state);

    let id = create_request(&app, &alice_token, "production").await;

    let resp = app
        .oneshot(
            Request::get(format!("/api/requests/{id}"))
                .header("authorization", format!("Bearer {bob_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn developer_cannot_approve() {
    let state = test_state();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, bob_token) = auth::create_token(&state, "bob", "developer")
        .await
        .unwrap();
    let app = routes::router(state);

    let id = create_request(&app, &alice_token, "production").await;

    let resp = app
        .oneshot(
            Request::post(format!("/api/requests/{id}/approve"))
                .header("authorization", format!("Bearer {bob_token}"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn developer_cannot_crud_policies() {
    let state = test_state();
    let (_, token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let app = routes::router(state);
    let auth = format!("Bearer {token}");

    let endpoints = vec![
        ("GET", "/api/workflows"),
        ("POST", "/api/workflows"),
        ("GET", "/api/execution-policies"),
        ("POST", "/api/execution-policies"),
        ("GET", "/api/result-policies"),
        ("POST", "/api/result-policies"),
        ("GET", "/api/notification-policies"),
        ("POST", "/api/notification-policies"),
    ];
    for (method, path) in endpoints {
        let req = match method {
            "POST" => Request::post(path)
                .header("authorization", &auth)
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"database":"x","environment":"y"}).to_string(),
                ))
                .unwrap(),
            _ => Request::get(path)
                .header("authorization", &auth)
                .body(Body::empty())
                .unwrap(),
        };
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "expected 403 for developer {method} {path}"
        );
    }
}

#[tokio::test]
async fn developer_audit_cannot_query_other_users() {
    let state = test_state();
    let (_, dev_token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let app = routes::router(state);

    // dev can read own audit
    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/audit")
                .header("authorization", format!("Bearer {dev_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // dev cannot query another user's audit
    let resp = app
        .oneshot(
            Request::get("/api/audit?user=admin1")
                .header("authorization", format!("Bearer {dev_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ─── 4. Readonly role ───

#[tokio::test]
async fn readonly_cannot_create_request() {
    let state = test_state();
    let (_, token) = auth::create_token(&state, "ro1", "readonly").await.unwrap();
    let app = routes::router(state);

    let resp = app.oneshot(
        Request::post("/api/requests")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(json!({"operation":"execute_query","environment":"production","detail":"SELECT 1"}).to_string()))
            .unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn readonly_cannot_read_audit() {
    let state = test_state();
    let (_, token) = auth::create_token(&state, "ro1", "readonly").await.unwrap();
    let app = routes::router(state);

    let resp = app
        .oneshot(
            Request::get("/api/audit")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ─── 5. Agent role ───

#[tokio::test]
async fn agent_can_poll() {
    let state = test_state();
    let (_, token) = auth::create_token_with_type(&state, "agent1", "admin", "agent")
        .await
        .unwrap();
    let app = routes::router(state);

    let resp = app
        .oneshot(
            Request::post("/api/agent/poll")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"databases":["*"],"environments":["*"],"operations":["*"]}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn agent_cannot_create_request() {
    let state = test_state();
    let (_, token) = auth::create_token_with_type(&state, "agent1", "admin", "agent")
        .await
        .unwrap();
    let app = routes::router(state);

    let resp = app.oneshot(
        Request::post("/api/requests")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(json!({"operation":"execute_query","environment":"production","detail":"SELECT 1"}).to_string()))
            .unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn agent_cannot_list_requests() {
    let state = test_state();
    let (_, token) = auth::create_token_with_type(&state, "agent1", "admin", "agent")
        .await
        .unwrap();
    let app = routes::router(state);

    let resp = app
        .oneshot(
            Request::get("/api/requests")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn agent_cannot_read_audit() {
    let state = test_state();
    let (_, token) = auth::create_token_with_type(&state, "agent1", "admin", "agent")
        .await
        .unwrap();
    let app = routes::router(state);

    let resp = app
        .oneshot(
            Request::get("/api/audit")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn agent_cannot_crud_policies() {
    let state = test_state();
    let (_, token) = auth::create_token_with_type(&state, "agent1", "admin", "agent")
        .await
        .unwrap();
    let app = routes::router(state);

    let resp = app
        .oneshot(
            Request::get("/api/workflows")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ─── 6. SQLi in filter params ───

#[tokio::test]
async fn sqli_in_filter_params_is_safe() {
    let state = test_state();
    let (_, token) = auth::create_token(&state, "admin1", "admin").await.unwrap();
    let app = routes::router(state);

    // SQLi in status param (URL-encoded)
    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/requests?status=pending%27%3B%20DROP%20TABLE%20requests%3B%20--")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // SQLi in audit user param (URL-encoded)
    let resp = app
        .oneshot(
            Request::get("/api/audit?user=%27%20OR%20%271%27%3D%271")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
