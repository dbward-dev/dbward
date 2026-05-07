//! Lease management tests: expiry, reclaim, heartbeat edge cases.

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
    }];
    db::policy_repo::sync_workflows(&conn, &workflows).unwrap();
    AppState {
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

#[tokio::test]
async fn expired_lease_reclaimed_to_execution_lost() {
    let state = test_state();
    let (_, dev_token) = auth::create_token(&state, "dev1", "developer").await.unwrap();
    let (_, agent_token) =
        auth::create_token_with_type(&state, "agent1", "admin", "agent").await.unwrap();
    let app = routes::router(state.clone());

    // Create auto-approved request (development)
    let resp = app.clone().oneshot(
        Request::post("/api/requests")
            .header("authorization", auth_header(&dev_token))
            .header("content-type", "application/json")
            .body(Body::from(json!({"operation":"execute_query","environment":"development","detail":"SELECT 1","database":"default"}).to_string()))
            .unwrap(),
    ).await.unwrap();
    let v = body_json(resp).await;
    let req_id = v["id"].as_str().unwrap().to_string();

    // Agent polls and claims
    let resp = app.clone().oneshot(
        Request::post("/api/agent/poll")
            .header("authorization", auth_header(&agent_token))
            .header("content-type", "application/json")
            .body(Body::from(json!({"databases":["*"],"environments":["*"],"operations":["*"]}).to_string()))
            .unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app.clone().oneshot(
        Request::post(format!("/api/agent/jobs/{req_id}/claim"))
            .header("authorization", auth_header(&agent_token))
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Manually expire the lease in SQLite
    {
        let conn = state.sqlite.lock().await;
        conn.execute(
            "UPDATE agent_executions SET lease_expires_at = '2020-01-01T00:00:00Z' WHERE request_id = ?1",
            rusqlite::params![req_id],
        ).unwrap();
    }

    // Run reclaim
    {
        let conn = state.sqlite.lock().await;
        let reclaimed = db::maintenance::reclaim_expired_leases(&conn).unwrap();
        assert_eq!(reclaimed.len(), 1);
    }

    // Verify status is execution_lost
    let resp = app.clone().oneshot(
        Request::get(format!("/api/requests/{req_id}"))
            .header("authorization", auth_header(&dev_token))
            .body(Body::empty())
            .unwrap(),
    ).await.unwrap();
    let v = body_json(resp).await;
    assert_eq!(v["status"].as_str().unwrap(), "execution_lost");
}

#[tokio::test]
async fn heartbeat_on_nonexistent_execution_returns_404() {
    let state = test_state();
    let (_, agent_token) =
        auth::create_token_with_type(&state, "agent1", "admin", "agent").await.unwrap();
    let app = routes::router(state);

    let resp = app.oneshot(
        Request::post("/api/agent/jobs/nonexistent-id/heartbeat")
            .header("authorization", auth_header(&agent_token))
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn agent_result_after_lease_expired_returns_conflict() {
    let state = test_state();
    let (_, dev_token) = auth::create_token(&state, "dev1", "developer").await.unwrap();
    let (_, agent_token) =
        auth::create_token_with_type(&state, "agent1", "admin", "agent").await.unwrap();
    let app = routes::router(state.clone());

    // Create + claim
    let resp = app.clone().oneshot(
        Request::post("/api/requests")
            .header("authorization", auth_header(&dev_token))
            .header("content-type", "application/json")
            .body(Body::from(json!({"operation":"execute_query","environment":"development","detail":"SELECT 1","database":"default"}).to_string()))
            .unwrap(),
    ).await.unwrap();
    let req_id = body_json(resp).await["id"].as_str().unwrap().to_string();

    let resp = app.clone().oneshot(
        Request::post(format!("/api/agent/jobs/{req_id}/claim"))
            .header("authorization", auth_header(&agent_token))
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap(),
    ).await.unwrap();
    let claim_body = body_json(resp).await;
    let exec_id = claim_body["execution_id"].as_str().unwrap().to_string();

    // Expire lease + reclaim
    {
        let conn = state.sqlite.lock().await;
        conn.execute(
            "UPDATE agent_executions SET lease_expires_at = '2020-01-01T00:00:00Z' WHERE id = ?1",
            rusqlite::params![exec_id],
        ).unwrap();
        db::maintenance::reclaim_expired_leases(&conn).unwrap();
    }

    // Agent tries to submit result after reclaim
    let resp = app.oneshot(
        Request::post(format!("/api/agent/jobs/{exec_id}/result"))
            .header("authorization", auth_header(&agent_token))
            .header("content-type", "application/json")
            .body(Body::from(json!({"success":true,"result":{"rows":[]}}).to_string()))
            .unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}
