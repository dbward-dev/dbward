//! Token security tests: tampering, revocation, execution token validation, auth modes.

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
        environment: "development".into(),
        operations: vec![],
        steps: vec![],
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
        result_store: None,
        draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        break_glass_roles: dbward_server::server_config::default_break_glass_roles(),
        audit_config: Default::default(),
        trusted_proxies: vec![],
        update_available: Arc::new(Mutex::new(None)),
    }
}

fn auth_header(token: &str) -> String {
    format!("Bearer {token}")
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

// ─── API Token Tampering ───

#[tokio::test]
async fn tampered_token_one_char_change_rejected() {
    let state = test_state();
    let (_, raw_token) = auth::create_token(&state, "alice", "admin").await.unwrap();
    let app = routes::router(state);

    // Flip last character
    let mut tampered = raw_token.clone();
    let last = tampered.pop().unwrap();
    tampered.push(if last == 'a' { 'b' } else { 'a' });

    let resp = app
        .oneshot(
            Request::get("/api/requests")
                .header("authorization", auth_header(&tampered))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn truncated_token_rejected() {
    let state = test_state();
    let (_, raw_token) = auth::create_token(&state, "alice", "admin").await.unwrap();
    let app = routes::router(state);

    let truncated = &raw_token[..raw_token.len() / 2];

    let resp = app
        .oneshot(
            Request::get("/api/requests")
                .header("authorization", auth_header(truncated))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn token_without_dbw_prefix_rejected() {
    let state = test_state();
    let app = routes::router(state);

    let resp = app
        .oneshot(
            Request::get("/api/requests")
                .header("authorization", "Bearer randomstring12345678901234567890")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn revoked_token_rejected() {
    let state = test_state();
    let (token_id, raw_token) = auth::create_token(&state, "alice", "admin").await.unwrap();
    auth::revoke_token(&state, &token_id).await.unwrap();
    let app = routes::router(state);

    let resp = app
        .oneshot(
            Request::get("/api/requests")
                .header("authorization", auth_header(&raw_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn double_revoke_is_idempotent_or_errors() {
    let state = test_state();
    let (token_id, _) = auth::create_token(&state, "alice", "admin").await.unwrap();
    auth::revoke_token(&state, &token_id).await.unwrap();
    // Second revoke: either errors or is idempotent (both acceptable)
    let result = auth::revoke_token(&state, &token_id).await;
    // Just verify it doesn't panic — either Ok or Err is fine
    let _ = result;
}

// ─── Auth Mode Control ───

#[tokio::test]
async fn jwt_rejected_when_mode_is_token_only() {
    let state = test_state();
    // auth_mode is already "token"
    let app = routes::router(state);

    // Fake JWT-like token (starts with eyJ)
    let resp = app
        .oneshot(
            Request::get("/api/requests")
                .header(
                    "authorization",
                    "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.fake",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn api_token_rejected_when_mode_is_oidc_only() {
    let mut state = test_state();
    state.auth_mode = "oidc".to_string();
    let (_, raw_token) = auth::create_token(&state, "alice", "admin").await.unwrap();
    let app = routes::router(state);

    let resp = app
        .oneshot(
            Request::get("/api/requests")
                .header("authorization", auth_header(&raw_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ─── Execution Token (Ed25519) ───

#[tokio::test]
async fn execution_token_has_correct_fields() {
    let signer = TokenSigner::generate();
    let token = signer.issue("req-123", "execute_query", "production", "mydb", "SELECT 1");

    assert_eq!(token.request_id, "req-123");
    assert_eq!(token.operation, "execute_query");
    assert_eq!(token.environment, "production");
    assert_eq!(token.database, "mydb");
    assert!(!token.signature.is_empty());
    assert!(!token.expires_at.is_empty());
    assert!(!token.detail_hash.is_empty());
}

#[tokio::test]
async fn execution_token_tampered_signature_rejected() {
    use dbward_core::token::verify_token;

    let signer = TokenSigner::generate();
    let mut token = signer.issue(
        "req-1",
        "execute_query",
        "development",
        "default",
        "SELECT 1",
    );

    // Tamper signature
    let mut sig_bytes = hex::decode(&token.signature).unwrap();
    sig_bytes[0] ^= 0xff;
    token.signature = hex::encode(&sig_bytes);

    let verifying_key = signer.verifying_key();
    let result = verify_token(
        &token,
        &verifying_key,
        "execute_query",
        "development",
        "default",
        "SELECT 1",
    );
    assert!(result.is_err());
}

#[tokio::test]
async fn execution_token_wrong_environment_rejected() {
    use dbward_core::token::verify_token;

    let signer = TokenSigner::generate();
    let token = signer.issue(
        "req-1",
        "execute_query",
        "development",
        "default",
        "SELECT 1",
    );

    let verifying_key = signer.verifying_key();
    // Verify with wrong environment
    let result = verify_token(
        &token,
        &verifying_key,
        "execute_query",
        "production",
        "default",
        "SELECT 1",
    );
    assert!(result.is_err());
}

#[tokio::test]
async fn execution_token_wrong_detail_hash_rejected() {
    use dbward_core::token::verify_token;

    let signer = TokenSigner::generate();
    let token = signer.issue(
        "req-1",
        "execute_query",
        "development",
        "default",
        "SELECT 1",
    );

    let verifying_key = signer.verifying_key();
    // Verify with wrong detail
    let result = verify_token(
        &token,
        &verifying_key,
        "execute_query",
        "development",
        "default",
        "SELECT 2",
    );
    assert!(result.is_err());
}

// ─── Agent Token Isolation ───

#[tokio::test]
async fn agent_token_subject_type_enforced() {
    let state = test_state();
    let (_, agent_token) = auth::create_token_with_type(&state, "agent1", "admin", "agent")
        .await
        .unwrap();
    let (_, user_token) = auth::create_token(&state, "user1", "admin").await.unwrap();
    let app = routes::router(state);

    // Agent cannot use user endpoints
    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/requests")
                .header("authorization", auth_header(&agent_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // User cannot use agent endpoints
    let resp = app
        .oneshot(
            Request::post("/api/agent/poll")
                .header("authorization", auth_header(&user_token))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ─── Break-glass role restriction ───

#[tokio::test]
async fn break_glass_rejected_for_non_permitted_role() {
    let mut state = test_state();
    state.break_glass_roles = vec!["admin".to_string()]; // only admin
    let (_, dev_token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let app = routes::router(state);

    let resp = app.oneshot(
        Request::post("/api/requests")
            .header("authorization", auth_header(&dev_token))
            .header("content-type", "application/json")
            .body(Body::from(json!({"operation":"execute_query","environment":"production","detail":"SELECT 1","database":"default","emergency":true,"reason":"incident"}).to_string()))
            .unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ─── TTL Expiration ───

#[tokio::test]
async fn expired_token_rejected() {
    let state = test_state();
    let (_, admin_token) = auth::create_token(&state, "admin1", "admin").await.unwrap();
    let app = routes::router(state.clone());

    // Create a token with 1-second TTL
    let resp = app
        .oneshot(
            Request::post("/api/tokens")
                .header("authorization", auth_header(&admin_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "subject_id": "bob",
                        "role": "developer",
                        "expires_in": 1
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;
    let short_lived_token = body["token"].as_str().unwrap().to_string();

    // Wait for expiration
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Using expired token should fail
    let app = routes::router(state);
    let resp = app
        .oneshot(
            Request::get("/api/requests")
                .header("authorization", auth_header(&short_lived_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ─── Self-Revoke ───

#[tokio::test]
async fn developer_can_revoke_own_token() {
    let state = test_state();
    let (_, admin_token) = auth::create_token(&state, "admin1", "admin").await.unwrap();
    let app = routes::router(state.clone());

    // Admin creates a token for "dev1"
    let resp = app
        .oneshot(
            Request::post("/api/tokens")
                .header("authorization", auth_header(&admin_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"subject_id": "dev1", "role": "developer"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;
    let dev_token = body["token"].as_str().unwrap().to_string();
    let token_id = body["id"].as_str().unwrap().to_string();

    // dev1 revokes their own token
    let app = routes::router(state);
    let resp = app
        .oneshot(
            Request::delete(&format!("/api/tokens/{token_id}"))
                .header("authorization", auth_header(&dev_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn developer_cannot_revoke_others_token() {
    let state = test_state();
    let (_, admin_token) = auth::create_token(&state, "admin1", "admin").await.unwrap();

    // Create token for dev1
    let app = routes::router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/tokens")
                .header("authorization", auth_header(&admin_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"subject_id": "dev1", "role": "developer"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = body_json(resp).await;
    let dev1_token_id = body["id"].as_str().unwrap().to_string();

    // Create token for dev2
    let app = routes::router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/tokens")
                .header("authorization", auth_header(&admin_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"subject_id": "dev2", "role": "developer"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = body_json(resp).await;
    let dev2_token = body["token"].as_str().unwrap().to_string();

    // dev2 tries to revoke dev1's token → should fail
    let app = routes::router(state);
    let resp = app
        .oneshot(
            Request::delete(&format!("/api/tokens/{dev1_token_id}"))
                .header("authorization", auth_header(&dev2_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
