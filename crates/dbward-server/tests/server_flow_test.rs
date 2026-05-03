use axum::body::Body;
use http_body_util::BodyExt;
use hyper::Request;
use rusqlite::Connection;
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;

use dbward_core::Role;
use dbward_server::{AppState, auth, db, routes, token::TokenSigner};

fn test_state() -> AppState {
    let conn = Connection::open_in_memory().unwrap();
    db::init(&conn).unwrap();
    AppState {
        sqlite: Arc::new(Mutex::new(conn)),
        token_signer: Arc::new(TokenSigner::generate()),
        webhooks: Arc::new(dbward_server::webhook::WebhookDispatcher::empty()),
        oidc: None,
        auth_mode: "token".to_string(),
        policy: Arc::new(Default::default()),
    }
}

fn auth_header(token: &str) -> String {
    format!("Bearer {token}")
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn health_check() {
    let app = routes::router(test_state());
    let resp = app
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn auto_approve_non_production() {
    let state = test_state();
    let (_, token) = auth::create_token(&state, "alice", Role::Developer).await.unwrap();
    let app = routes::router(state);

    let resp = app
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"operation": "execute_query", "environment": "staging", "detail": "SELECT 1"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), 201);
    let body = body_json(resp).await;
    assert_eq!(body["status"], "auto_approved");
    assert!(body["execution_token"].is_object());
}

#[tokio::test]
async fn production_requires_approval() {
    let state = test_state();
    let (_, alice_token) = auth::create_token(&state, "alice", Role::Developer).await.unwrap();
    let (_, bob_token) = auth::create_token(&state, "bob", Role::Admin).await.unwrap();
    let app = routes::router(state);

    // Alice creates a production request
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&alice_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"operation": "execute_query", "environment": "production", "detail": "DELETE FROM old_data"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), 201);
    let body = body_json(resp).await;
    assert_eq!(body["status"], "pending");
    let request_id = body["id"].as_str().unwrap().to_string();

    // Bob approves
    let resp = app
        .clone()
        .oneshot(
            Request::post(&format!("/api/requests/{request_id}/approve"))
                .header("authorization", auth_header(&bob_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["status"], "approved");
    assert!(body["execution_token"].is_object());

    // Verify the token is valid
    let token: dbward_core::token::ExecutionToken =
        serde_json::from_value(body["execution_token"].clone()).unwrap();
    assert_eq!(token.operation, "execute_query");
    assert_eq!(token.environment, "production");
}

#[tokio::test]
async fn self_approve_rejected() {
    let state = test_state();
    let (_, alice_token) = auth::create_token(&state, "alice", Role::Admin).await.unwrap();
    let app = routes::router(state);

    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&alice_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"operation": "migrate_up", "environment": "production", "detail": "count:0"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = body_json(resp).await;
    let request_id = body["id"].as_str().unwrap().to_string();

    // Alice tries to approve her own request
    let resp = app
        .oneshot(
            Request::post(&format!("/api/requests/{request_id}/approve"))
                .header("authorization", auth_header(&alice_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn complete_flow() {
    let state = test_state();
    let (_, alice_token) = auth::create_token(&state, "alice", Role::Developer).await.unwrap();
    let app = routes::router(state);

    // Create auto-approved request
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&alice_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"operation": "execute_query", "environment": "staging", "detail": "SELECT 1"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = body_json(resp).await;
    let request_id = body["id"].as_str().unwrap().to_string();

    // Complete
    let resp = app
        .clone()
        .oneshot(
            Request::post(&format!("/api/requests/{request_id}/complete"))
                .header("authorization", auth_header(&alice_token))
                .header("content-type", "application/json")
                .body(Body::from(json!({"success": true}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);

    // Verify status is executed
    let resp = app
        .clone()
        .oneshot(
            Request::get(&format!("/api/requests/{request_id}"))
                .header("authorization", auth_header(&alice_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = body_json(resp).await;
    assert_eq!(body["status"], "executed");
    // Token replay prevention: executed requests should NOT have execution_token
    assert!(body.get("execution_token").is_none() || body["execution_token"].is_null());
}

#[tokio::test]
async fn public_key_endpoint() {
    let state = test_state();
    let app = routes::router(state);

    let resp = app
        .oneshot(Request::get("/api/public-key").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(bytes.len(), 32); // Ed25519 public key is 32 bytes
}

#[tokio::test]
async fn agent_full_flow() {
    // Setup: server with alice (developer) and agent tokens
    let state = test_state();
    let (_, alice_token) = auth::create_token(&state, "alice", Role::Developer).await.unwrap();
    let (_, agent_token) = auth::create_token(&state, "agent-1", Role::Admin).await.unwrap();

    // 1. Alice creates a request (development → auto_approved)
    let app = routes::router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&alice_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"operation": "execute_query", "environment": "development", "database": "app", "detail": "SELECT 1"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body = body_json(resp).await;
    let request_id = body["id"].as_str().unwrap();
    assert_eq!(body["status"], "auto_approved");

    // 2. Agent polls for jobs
    let app = routes::router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/agent/poll")
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from(json!({"databases": ["app"]}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let poll_status = resp.status();
    let poll_body = body_json(resp).await;
    assert_eq!(poll_status, 200);
    let jobs = poll_body["jobs"].as_array().unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0]["id"].as_str().unwrap(), request_id);

    // 3. Agent claims the job
    let app = routes::router(state.clone());
    let resp = app
        .oneshot(
            Request::post(&format!("/api/agent/jobs/{request_id}/claim"))
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from(json!({"agent_id": "agent-1"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let claim_status = resp.status();
    let body = body_json(resp).await;
    assert_eq!(claim_status, 200);
    let exec_id = body["execution_id"].as_str().unwrap().to_string();
    assert_eq!(body["operation"], "execute_query");
    assert_eq!(body["database"], "app");
    assert!(body["execution_token"].is_object());

    // 4. Verify request is now "running"
    let app = routes::router(state.clone());
    let resp = app
        .oneshot(
            Request::get(&format!("/api/requests/{request_id}"))
                .header("authorization", auth_header(&alice_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = body_json(resp).await;
    assert_eq!(body["status"], "running");

    // 5. Agent completes the job
    let app = routes::router(state.clone());
    let resp = app
        .oneshot(
            Request::post(&format!("/api/agent/jobs/{exec_id}/complete"))
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"success": true, "result": "[{\"test\": 1}]"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["status"], "executed");

    // 6. Alice gets the result
    let app = routes::router(state.clone());
    let resp = app
        .oneshot(
            Request::get(&format!("/api/requests/{request_id}"))
                .header("authorization", auth_header(&alice_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = body_json(resp).await;
    assert_eq!(body["status"], "executed");
    assert_eq!(body["execution_result"], "[{\"test\": 1}]");
}

#[tokio::test]
async fn agent_poll_empty_when_no_approved() {
    let state = test_state();
    let (_, agent_token) = auth::create_token(&state, "agent-1", Role::Admin).await.unwrap();

    let app = routes::router(state);
    let resp = app
        .oneshot(
            Request::post("/api/agent/poll")
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["jobs"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn agent_cannot_claim_pending() {
    let state = test_state();
    let (_, alice_token) = auth::create_token(&state, "alice", Role::Developer).await.unwrap();
    let (_, agent_token) = auth::create_token(&state, "agent-1", Role::Admin).await.unwrap();

    // Create production request (pending)
    let app = routes::router(state.clone());
    let resp = app
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&alice_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"operation": "execute_query", "environment": "production", "detail": "DELETE FROM x"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = body_json(resp).await;
    let request_id = body["id"].as_str().unwrap();

    // Agent tries to claim pending request → should fail
    let app = routes::router(state);
    let resp = app
        .oneshot(
            Request::post(&format!("/api/agent/jobs/{request_id}/claim"))
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from(json!({"agent_id": "agent-1"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
}
