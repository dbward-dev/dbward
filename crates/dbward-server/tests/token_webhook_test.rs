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
        environment: "*".into(),
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
    let (_, token) = dbward_server::auth::create_token_with_type(state, "admin", "admin", "user")
        .await
        .unwrap();
    token
}

async fn dev_token(state: &AppState) -> String {
    let (_, token) =
        dbward_server::auth::create_token_with_type(state, "dev", "developer", "user")
            .await
            .unwrap();
    token
}

fn req(method: &str, uri: &str, token: &str, body: Option<&str>) -> axum::http::Request<String> {
    let mut builder = axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json");
    builder
        .body(body.unwrap_or("").to_string())
        .unwrap()
}

// === Token API Tests ===

#[tokio::test]
async fn token_create_list_revoke() {
    let state = test_state();
    let app = dbward_server::routes::router(state.clone());
    let admin = admin_token(&state).await;

    // Create
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/tokens",
            &admin,
            Some(r#"{"subject_id":"ci","role":"developer","name":"CI Token","groups":["deploy"]}"#),
        ))
        .await
        .unwrap();
    let status = resp.status();
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 10000).await.unwrap())
            .unwrap();
    assert_eq!(status, StatusCode::CREATED, "body: {body}");
    assert!(body["token"].as_str().unwrap().starts_with("dbw_"));
    assert_eq!(body["name"], "CI Token");
    assert_eq!(body["groups"], serde_json::json!(["deploy"]));
    let token_id = body["id"].as_str().unwrap().to_string();

    // List
    let resp = app
        .clone()
        .oneshot(req("GET", "/api/tokens", &admin, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 10000).await.unwrap())
            .unwrap();
    let tokens = body["tokens"].as_array().unwrap();
    // admin token + ci token
    assert!(tokens.len() >= 2);
    // Verify raw token is NOT in list
    assert!(tokens.iter().all(|t| t.get("token").is_none()));
    // Verify prefix is present
    assert!(tokens.iter().any(|t| t["name"] == "CI Token"));

    // Revoke
    let resp = app
        .clone()
        .oneshot(req("DELETE", &format!("/api/tokens/{token_id}"), &admin, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 10000).await.unwrap())
            .unwrap();
    assert_eq!(body["status"], "revoked");
}

#[tokio::test]
async fn token_api_denied_for_non_admin() {
    let state = test_state();
    let app = dbward_server::routes::router(state.clone());
    let dev = dev_token(&state).await;

    let resp = app
        .clone()
        .oneshot(req("GET", "/api/tokens", &dev, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/tokens",
            &dev,
            Some(r#"{"subject_id":"x","role":"developer"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// === Webhook API Tests ===

#[tokio::test]
async fn webhook_crud() {
    let state = test_state();
    let app = dbward_server::routes::router(state.clone());
    let admin = admin_token(&state).await;

    // Create (use httpbin as a safe external URL)
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/webhooks",
            &admin,
            Some(r#"{"url":"https://httpbin.org/post","events":["request_created"],"format":"generic","secret":"mysecret"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 10000).await.unwrap())
            .unwrap();
    assert_eq!(body["has_secret"], true);
    assert!(body.get("secret").is_none()); // secret not returned
    let wh_id = body["id"].as_str().unwrap().to_string();

    // List
    let resp = app
        .clone()
        .oneshot(req("GET", "/api/webhooks", &admin, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 10000).await.unwrap())
            .unwrap();
    assert_eq!(body["webhooks"].as_array().unwrap().len(), 1);

    // Get
    let resp = app
        .clone()
        .oneshot(req("GET", &format!("/api/webhooks/{wh_id}"), &admin, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 10000).await.unwrap())
            .unwrap();
    assert_eq!(body["url"], "https://httpbin.org/post");
    assert_eq!(body["has_secret"], true);

    // Update (change events, remove secret)
    let resp = app
        .clone()
        .oneshot(req(
            "PUT",
            &format!("/api/webhooks/{wh_id}"),
            &admin,
            Some(r#"{"events":["request_approved"],"secret":null}"#),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 10000).await.unwrap())
            .unwrap();
    assert_eq!(body["events"], serde_json::json!(["request_approved"]));
    assert_eq!(body["has_secret"], false);

    // Delete
    let resp = app
        .clone()
        .oneshot(req(
            "DELETE",
            &format!("/api/webhooks/{wh_id}"),
            &admin,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 10000).await.unwrap())
            .unwrap();
    assert_eq!(body["deleted"], true);

    // Verify deleted
    let resp = app
        .clone()
        .oneshot(req("GET", &format!("/api/webhooks/{wh_id}"), &admin, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn webhook_ssrf_blocked() {
    let state = test_state();
    let app = dbward_server::routes::router(state.clone());
    let admin = admin_token(&state).await;

    // Private IP should be blocked
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/webhooks",
            &admin,
            Some(r#"{"url":"http://127.0.0.1:8080/hook"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 10000).await.unwrap())
            .unwrap();
    assert_eq!(body["code"], "invalid_webhook_url");
}

#[tokio::test]
async fn webhook_api_denied_for_non_admin() {
    let state = test_state();
    let app = dbward_server::routes::router(state.clone());
    let dev = dev_token(&state).await;

    let resp = app
        .clone()
        .oneshot(req("GET", "/api/webhooks", &dev, None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
