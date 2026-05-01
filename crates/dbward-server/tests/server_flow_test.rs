use axum::body::Body;
use http_body_util::BodyExt;
use hyper::Request;
use rusqlite::Connection;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

use dbward_core::Role;
use dbward_server::{AppState, auth, db, routes, token::TokenSigner};

fn test_state() -> AppState {
    let conn = Connection::open_in_memory().unwrap();
    db::init(&conn).unwrap();
    AppState {
        sqlite: Arc::new(Mutex::new(conn)),
        token_signer: Arc::new(TokenSigner::generate()),
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
    let (_, token) = auth::create_token(&state, "alice", Role::Developer).unwrap();
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
    let (_, alice_token) = auth::create_token(&state, "alice", Role::Developer).unwrap();
    let (_, bob_token) = auth::create_token(&state, "bob", Role::Admin).unwrap();
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
    let (_, alice_token) = auth::create_token(&state, "alice", Role::Admin).unwrap();
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
    let (_, alice_token) = auth::create_token(&state, "alice", Role::Developer).unwrap();
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
}
