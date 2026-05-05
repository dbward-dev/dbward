use axum::body::Body;
use axum::http::StatusCode;
use http_body_util::BodyExt;
use hyper::Request;
use rusqlite::Connection;
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower::ServiceExt;

use dbward_server::{AppState, ResultChannels, auth, db, routes, token::TokenSigner};

fn test_state() -> AppState {
    let conn = Connection::open_in_memory().unwrap();
    db::init(&conn).unwrap();
    // Register default workflows matching previous hardcoded behavior
    let workflows = vec![
        dbward_server::server_config::WorkflowDef {
            database: "*".into(),
            environment: "development".into(),
            operations: vec![],
            steps: vec![],
            require_reason: false,
        },
        dbward_server::server_config::WorkflowDef {
            database: "*".into(),
            environment: "staging".into(),
            operations: vec![],
            steps: vec![],
            require_reason: false,
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
        },
    ];
    db::policy_repo::sync_workflows(&conn, &workflows).unwrap();
    AppState {
        sqlite: Arc::new(Mutex::new(conn)),
        token_signer: Arc::new(TokenSigner::generate()),
        webhooks: Arc::new(dbward_server::webhook::WebhookDispatcher::empty()),
        oidc: None,
        auth_mode: "token".to_string(),
        policy: Arc::new(Default::default()),
        result_channels: Arc::new(ResultChannels::new()),
        retention: Default::default(),
        request_notifier: Arc::new(dbward_server::RequestNotifier::new()),
    result_store: None,
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
    let (_, token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
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
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, bob_token) = auth::create_token(&state, "bob", "admin").await.unwrap();
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
            Request::post(format!("/api/requests/{request_id}/approve"))
                .header("authorization", auth_header(&bob_token))
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["status"], "approved");
    assert_eq!(body["approved_by"], "bob");
    assert_eq!(body["step_completed"], 0);
    assert_eq!(body["current_step"], 1);
    assert_eq!(body["total_steps"], 1);
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
    let (_, alice_token) = auth::create_token(&state, "alice", "admin").await.unwrap();
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
            Request::post(format!("/api/requests/{request_id}/approve"))
                .header("authorization", auth_header(&alice_token))
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn non_admin_cannot_approve_requests() {
    let state = test_state();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, bob_token) = auth::create_token(&state, "bob", "developer")
        .await
        .unwrap();
    let app = routes::router(state);

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
    let body = body_json(resp).await;
    let request_id = body["id"].as_str().unwrap().to_string();

    let resp = app
        .oneshot(
            Request::post(format!("/api/requests/{request_id}/approve"))
                .header("authorization", auth_header(&bob_token))
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn complete_flow_via_agent() {
    let state = test_state();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, agent_token) = auth::create_token_with_type(&state, "agent-1", "admin", "agent")
        .await
        .unwrap();

    // Create auto-approved request
    let app = routes::router(state.clone());
    let resp = app
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

    // Dispatch
    let app = routes::router(state.clone());
    let resp = app
        .oneshot(
            Request::post(format!("/api/requests/{request_id}/dispatch"))
                .header("authorization", auth_header(&alice_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Agent claims
    let app = routes::router(state.clone());
    let resp = app
        .oneshot(
            Request::post(format!("/api/agent/jobs/{request_id}/claim"))
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    let exec_id = body["execution_id"].as_str().unwrap().to_string();

    // Agent reports result
    let app = routes::router(state.clone());
    let resp = app
        .oneshot(
            Request::post(format!("/api/agent/jobs/{exec_id}/result"))
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"success": true, "result": []}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Verify status is executed
    let app = routes::router(state.clone());
    let resp = app
        .oneshot(
            Request::get(format!("/api/requests/{request_id}"))
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
async fn non_admin_cannot_read_other_users_request() {
    let state = test_state();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, bob_token) = auth::create_token(&state, "bob", "developer")
        .await
        .unwrap();
    let app = routes::router(state);

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

    let resp = app
        .oneshot(
            Request::get(format!("/api/requests/{request_id}"))
                .header("authorization", auth_header(&bob_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
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
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, agent_token) = auth::create_token_with_type(&state, "agent-1", "admin", "agent")
        .await
        .unwrap();

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
    let request_id = body["id"].as_str().unwrap().to_string();
    assert_eq!(body["status"], "auto_approved");

    // 2. Agent polls — should be empty (not yet dispatched)
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
    let body = body_json(resp).await;
    assert_eq!(body["jobs"].as_array().unwrap().len(), 0);

    // 3. Alice dispatches the request
    let app = routes::router(state.clone());
    let resp = app
        .oneshot(
            Request::post(format!("/api/requests/{request_id}/dispatch"))
                .header("authorization", auth_header(&alice_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["status"], "dispatched");

    // 4. Agent polls — now sees the dispatched request
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
    let body = body_json(resp).await;
    let jobs = body["jobs"].as_array().unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0]["id"].as_str().unwrap(), request_id);

    // 5. Agent claims the job
    let app = routes::router(state.clone());
    let resp = app
        .oneshot(
            Request::post(format!("/api/agent/jobs/{request_id}/claim"))
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from(json!({"agent_id": "agent-1"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    let exec_id = body["execution_id"].as_str().unwrap().to_string();

    // 6. Agent sends result + Alice streams result (concurrent)
    let state2 = state.clone();
    let alice_token2 = alice_token.clone();
    let request_id2 = request_id.clone();
    let stream_handle = tokio::spawn(async move {
        let app = routes::router(state2);
        app.oneshot(
            Request::get(format!("/api/requests/{request_id2}/result/stream"))
                .header("authorization", auth_header(&alice_token2))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
    });

    // Small delay to ensure stream handler is waiting
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let app = routes::router(state.clone());
    let resp = app
        .oneshot(
            Request::post(format!("/api/agent/jobs/{exec_id}/result"))
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"success": true, "result": [{"test": 1}]}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // 7. Alice receives the streamed result
    let stream_resp = stream_handle.await.unwrap();
    assert_eq!(stream_resp.status(), 200);
    let body = body_json(stream_resp).await;
    assert_eq!(body["success"], true);
    assert_eq!(body["result"], json!([{"test": 1}]));

    // 8. Request is now executed
    let app = routes::router(state.clone());
    let resp = app
        .oneshot(
            Request::get(format!("/api/requests/{request_id}"))
                .header("authorization", auth_header(&alice_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = body_json(resp).await;
    assert_eq!(body["status"], "executed");
}

#[tokio::test]
async fn stream_result_after_agent_posts_still_succeeds() {
    let state = test_state();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, agent_token) = auth::create_token_with_type(&state, "agent-1", "admin", "agent")
        .await
        .unwrap();

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
    let body = body_json(resp).await;
    let request_id = body["id"].as_str().unwrap().to_string();

    let app = routes::router(state.clone());
    let resp = app
        .oneshot(
            Request::post(format!("/api/requests/{request_id}/dispatch"))
                .header("authorization", auth_header(&alice_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let app = routes::router(state.clone());
    let resp = app
        .oneshot(
            Request::post(format!("/api/agent/jobs/{request_id}/claim"))
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from(json!({"agent_id": "agent-1"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    let exec_id = body["execution_id"].as_str().unwrap().to_string();

    let app = routes::router(state.clone());
    let resp = app
        .oneshot(
            Request::post(format!("/api/agent/jobs/{exec_id}/result"))
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"success": true, "result": [{"late": true}]}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let app = routes::router(state);
    let resp = app
        .oneshot(
            Request::get(format!("/api/requests/{request_id}/result/stream"))
                .header("authorization", auth_header(&alice_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["success"], true);
    assert_eq!(body["result"], json!([{"late": true}]));
}

#[tokio::test]
async fn agent_poll_empty_when_no_approved() {
    let state = test_state();
    let (_, agent_token) = auth::create_token_with_type(&state, "agent-1", "admin", "agent")
        .await
        .unwrap();

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
async fn agent_poll_empty_capability_arrays_do_not_break_query() {
    let state = test_state();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, agent_token) = auth::create_token_with_type(&state, "agent-1", "admin", "agent")
        .await
        .unwrap();

    let app = routes::router(state);
    let resp = app
        .clone()
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
    let request_id = body_json(resp).await["id"].as_str().unwrap().to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{request_id}/dispatch"))
                .header("authorization", auth_header(&alice_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .oneshot(
            Request::post("/api/agent/poll")
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"databases": [], "environments": [], "operations": []}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["jobs"].as_array().unwrap().len(), 1);
    assert_eq!(body["jobs"][0]["id"], request_id);
}

#[tokio::test]
async fn agent_poll_wildcard_capability_arrays_match_all_values() {
    let state = test_state();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, agent_token) = auth::create_token_with_type(&state, "agent-1", "admin", "agent")
        .await
        .unwrap();

    let app = routes::router(state);
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&alice_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"operation": "execute_query", "environment": "development", "database": "mydb", "detail": "SELECT 1"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let request_id = body_json(resp).await["id"].as_str().unwrap().to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{request_id}/dispatch"))
                .header("authorization", auth_header(&alice_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .oneshot(
            Request::post("/api/agent/poll")
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"databases": ["*"], "environments": ["development"], "operations": ["*"]}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["jobs"].as_array().unwrap().len(), 1);
    assert_eq!(body["jobs"][0]["id"], request_id);
}

#[tokio::test]
async fn agent_cannot_claim_pending() {
    let state = test_state();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, agent_token) = auth::create_token_with_type(&state, "agent-1", "admin", "agent")
        .await
        .unwrap();

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
            Request::post(format!("/api/agent/jobs/{request_id}/claim"))
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from(json!({"agent_id": "agent-1"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
}

#[tokio::test]
async fn workflow_operations_are_respected() {
    let state = test_state();
    {
        let conn = state.sqlite.lock().await;
        conn.execute(
            "INSERT OR REPLACE INTO workflows (id, database_name, environment, operations_json, steps_json, source, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'api', ?6, ?6)",
            rusqlite::params![
                "app:development:migrate_status",
                "app",
                "development",
                r#"["migrate_status"]"#,
                r#"[{"type":"approval","mode":"all","approvers":[{"role":"admin","min":1}],"require_distinct_actors":true}]"#,
                "2026-05-03T00:00:00Z",
            ],
        )
        .unwrap();
    }

    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let app = routes::router(state);

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
    assert_eq!(body["status"], "auto_approved");
}

#[tokio::test]
async fn create_request_falls_back_to_static_policy_when_no_workflow_matches() {
    let conn = Connection::open_in_memory().unwrap();
    db::init(&conn).unwrap();
    let state = AppState {
        sqlite: Arc::new(Mutex::new(conn)),
        token_signer: Arc::new(TokenSigner::generate()),
        webhooks: Arc::new(dbward_server::webhook::WebhookDispatcher::empty()),
        oidc: None,
        auth_mode: "token".to_string(),
        policy: Arc::new(Default::default()),
        result_channels: Arc::new(ResultChannels::new()),
        retention: Default::default(),
        request_notifier: Arc::new(dbward_server::RequestNotifier::new()),
    result_store: None,
        };
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let app = routes::router(state);

    let resp = app
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

    assert_eq!(resp.status(), 201);
    let body = body_json(resp).await;
    assert_eq!(body["status"], "auto_approved");
}

#[tokio::test]
async fn non_admin_cannot_use_agent_endpoints() {
    let state = test_state();
    let (_, user_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let app = routes::router(state);

    let resp = app
        .oneshot(
            Request::post("/api/agent/poll")
                .header("authorization", auth_header(&user_token))
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn result_stream_honors_result_policy_access() {
    let state = test_state();
    {
        let conn = state.sqlite.lock().await;
        conn.execute(
            "INSERT OR REPLACE INTO result_policies (id, database_name, environment, delivery_mode, storage_config_json, access_json, source, created_at, updated_at)
             VALUES (?1, ?2, ?3, 'direct', '{}', ?4, 'api', ?5, ?5)",
            rusqlite::params![
                "app:development",
                "app",
                "development",
                r#"["requester"]"#,
                "2026-05-03T00:00:00Z",
            ],
        )
        .unwrap();
    }
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, bob_token) = auth::create_token(&state, "bob", "developer")
        .await
        .unwrap();

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
    let body = body_json(resp).await;
    let request_id = body["id"].as_str().unwrap().to_string();

    let app = routes::router(state.clone());
    let resp = app
        .oneshot(
            Request::post(format!("/api/requests/{request_id}/dispatch"))
                .header("authorization", auth_header(&alice_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let app = routes::router(state);
    let resp = app
        .oneshot(
            Request::get(format!("/api/requests/{request_id}/result/stream"))
                .header("authorization", auth_header(&bob_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn only_claiming_agent_can_submit_result() {
    let state = test_state();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, agent1_token) = auth::create_token_with_type(&state, "agent-1", "admin", "agent")
        .await
        .unwrap();
    let (_, agent2_token) = auth::create_token_with_type(&state, "agent-2", "admin", "agent")
        .await
        .unwrap();

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
    let body = body_json(resp).await;
    let request_id = body["id"].as_str().unwrap().to_string();

    let app = routes::router(state.clone());
    app.oneshot(
        Request::post(format!("/api/requests/{request_id}/dispatch"))
            .header("authorization", auth_header(&alice_token))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    let app = routes::router(state.clone());
    let resp = app
        .oneshot(
            Request::post(format!("/api/agent/jobs/{request_id}/claim"))
                .header("authorization", auth_header(&agent1_token))
                .header("content-type", "application/json")
                .body(Body::from(json!({"agent_id": "spoofed"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    let exec_id = body["execution_id"].as_str().unwrap().to_string();

    let app = routes::router(state);
    let resp = app
        .oneshot(
            Request::post(format!("/api/agent/jobs/{exec_id}/result"))
                .header("authorization", auth_header(&agent2_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"success": true, "result": []}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn failed_request_still_respects_max_executions() {
    let state = test_state();
    {
        let conn = state.sqlite.lock().await;
        conn.execute(
            "INSERT OR REPLACE INTO execution_policies (id, database_name, environment, max_executions, execution_window_secs, retry_on_failure, source, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'api', ?7, ?7)",
            rusqlite::params![
                "app:development",
                "app",
                "development",
                1,
                86400,
                true,
                "2026-05-03T00:00:00Z",
            ],
        )
        .unwrap();
    }
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, agent_token) = auth::create_token_with_type(&state, "agent-1", "admin", "agent")
        .await
        .unwrap();

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
    let body = body_json(resp).await;
    let request_id = body["id"].as_str().unwrap().to_string();

    let app = routes::router(state.clone());
    app.oneshot(
        Request::post(format!("/api/requests/{request_id}/dispatch"))
            .header("authorization", auth_header(&alice_token))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    let app = routes::router(state.clone());
    let resp = app
        .oneshot(
            Request::post(format!("/api/agent/jobs/{request_id}/claim"))
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = body_json(resp).await;
    let exec_id = body["execution_id"].as_str().unwrap().to_string();

    let app = routes::router(state.clone());
    let resp = app
        .oneshot(
            Request::post(format!("/api/agent/jobs/{exec_id}/result"))
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"success": false, "error": "boom"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let app = routes::router(state);
    let resp = app
        .oneshot(
            Request::post(format!("/api/requests/{request_id}/dispatch"))
                .header("authorization", auth_header(&alice_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
}

// ---------------------------------------------------------------------------
// Hardening regression tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn agent_token_cannot_approve() {
    let state = test_state();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, agent_token) = auth::create_token_with_type(&state, "agent-1", "admin", "agent")
        .await
        .unwrap();

    let app = routes::router(state);

    // Create request as alice
    let resp = app.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/api/requests")
            .header("authorization", auth_header(&alice_token))
            .header("content-type", "application/json")
            .body(Body::from(r#"{"operation":"execute_query","environment":"production","database":"default","detail":"SELECT 1"}"#))
            .unwrap(),
    ).await.unwrap();
    let body = body_json(resp).await;
    let id = body["id"].as_str().unwrap();

    // Agent tries to approve -> 403
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/requests/{id}/approve"))
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn user_token_cannot_poll_agent() {
    let state = test_state();
    let (_, admin_token) = auth::create_token(&state, "admin", "admin").await.unwrap();

    let app = routes::router(state);

    // Human admin tries agent poll -> 403
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/agent/poll")
                .header("authorization", auth_header(&admin_token))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"databases":[],"environments":[]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn readonly_cannot_read_audit() {
    let state = test_state();
    let (_, ro_token) = auth::create_token(&state, "viewer", "readonly")
        .await
        .unwrap();

    let app = routes::router(state);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/audit")
                .header("authorization", auth_header(&ro_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/workflows")
                .header("authorization", auth_header(&ro_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn developer_can_read_own_audit() {
    let state = test_state();
    let (_, dev_token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();
    let (_, admin_token) = auth::create_token(&state, "admin1", "admin").await.unwrap();

    let app = routes::router(state);

    // Developer can access audit (gets own logs)
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/audit")
                .header("authorization", auth_header(&dev_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Developer cannot filter by another user
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/audit?user=admin1")
                .header("authorization", auth_header(&dev_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Developer can filter by own user explicitly
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/audit?user=dev1")
                .header("authorization", auth_header(&dev_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Admin can filter by any user
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/audit?user=dev1")
                .header("authorization", auth_header(&admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn requester_can_reject_own_request() {
    let state = test_state();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();

    let app = routes::router(state);

    let resp = app.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/api/requests")
            .header("authorization", auth_header(&alice_token))
            .header("content-type", "application/json")
            .body(Body::from(r#"{"operation":"execute_query","environment":"production","database":"default","detail":"SELECT 1"}"#))
            .unwrap(),
    ).await.unwrap();
    let body = body_json(resp).await;
    let id = body["id"].as_str().unwrap();

    // Alice rejects her own request -> success
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/requests/{id}/reject"))
                .header("authorization", auth_header(&alice_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn current_step_approver_can_reject_request() {
    let state = test_state_multistep();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, lead_token) = auth::create_token(&state, "lead1", "team-lead")
        .await
        .unwrap();

    let app = routes::router(state);

    let resp = app.clone().oneshot(
        Request::post("/api/requests")
            .header("authorization", auth_header(&alice_token))
            .header("content-type", "application/json")
            .body(Body::from(json!({"operation": "execute_query", "environment": "production", "detail": "DELETE FROM old"}).to_string()))
            .unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;
    let request_id = body["id"].as_str().unwrap().to_string();

    let resp = app
        .oneshot(
            Request::post(format!("/api/requests/{request_id}/reject"))
                .header("authorization", auth_header(&lead_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn complete_endpoint_removed() {
    let state = test_state();
    let (_, token) = auth::create_token(&state, "alice", "admin").await.unwrap();

    let app = routes::router(state);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/requests/fake-id/complete")
                .header("authorization", auth_header(&token))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"success":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    // Should be 404 (route doesn't exist) or 405 (method not allowed)
    assert!(
        resp.status() == StatusCode::NOT_FOUND || resp.status() == StatusCode::METHOD_NOT_ALLOWED
    );
}

#[tokio::test]
async fn dispatch_requires_owner_or_admin() {
    let state = test_state();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, bob_token) = auth::create_token(&state, "bob", "developer")
        .await
        .unwrap();
    let (_, admin_token) = auth::create_token(&state, "admin", "admin").await.unwrap();

    let app = routes::router(state);

    // Alice creates request (auto_approved in development)
    let resp = app.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/api/requests")
            .header("authorization", auth_header(&alice_token))
            .header("content-type", "application/json")
            .body(Body::from(r#"{"operation":"execute_query","environment":"development","database":"default","detail":"SELECT 1"}"#))
            .unwrap(),
    ).await.unwrap();
    let body = body_json(resp).await;
    let id = body["id"].as_str().unwrap();

    // Bob (non-admin, non-owner) tries to dispatch -> 403
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/requests/{id}/dispatch"))
                .header("authorization", auth_header(&bob_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Admin can dispatch
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/requests/{id}/dispatch"))
                .header("authorization", auth_header(&admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn agent_capability_mismatch_blocks_claim() {
    let state = test_state();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, agent_token) = auth::create_token_with_type(&state, "agent-1", "admin", "agent")
        .await
        .unwrap();

    let app = routes::router(state);

    // Create and dispatch a production request
    let resp = app.clone().oneshot(
        Request::builder()
            .method("POST")
            .uri("/api/requests")
            .header("authorization", auth_header(&alice_token))
            .header("content-type", "application/json")
            .body(Body::from(r#"{"operation":"execute_query","environment":"development","database":"mydb","detail":"SELECT 1"}"#))
            .unwrap(),
    ).await.unwrap();
    let body = body_json(resp).await;
    let id = body["id"].as_str().unwrap();

    // Dispatch
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/requests/{id}/dispatch"))
                .header("authorization", auth_header(&alice_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Agent polls with limited capabilities (only "other-db")
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/agent/poll")
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"databases":["other-db"],"environments":["development"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Agent tries to claim job for "mydb" -> 403
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/agent/jobs/{id}/claim"))
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn require_reason_blocks_request_without_reason() {
    let state = test_state();
    // Insert a workflow with require_reason=true for app:development
    {
        let conn = state.sqlite.lock().await;
        conn.execute(
            "INSERT OR REPLACE INTO workflows (id, database_name, environment, operations_json, steps_json, require_reason, source, created_at, updated_at)
             VALUES ('app:development', 'app', 'development', '[]', '[]', 1, 'api', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            [],
        ).unwrap();
    }
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();

    // Request without reason -> 400
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
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Request with reason -> success
    let app = routes::router(state);
    let resp = app
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&alice_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"operation": "execute_query", "environment": "development", "database": "app", "detail": "SELECT 1", "reason": "debugging issue #42"}).to_string(),
                ))
                .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn get_request_and_pending_for_me_include_reason() {
    let state = test_state_multistep();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, lead_token) = auth::create_token(&state, "lead1", "team-lead")
        .await
        .unwrap();

    let app = routes::router(state.clone());

    let reason = "urgent production investigation";
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&alice_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "operation": "execute_query",
                        "environment": "production",
                        "detail": "SELECT 1",
                        "reason": reason,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;
    let request_id = body["id"].as_str().unwrap().to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::get(format!("/api/requests/{request_id}"))
                .header("authorization", auth_header(&alice_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["reason"], reason);

    let resp = app
        .oneshot(
            Request::get("/api/requests?pending_for_me=true")
                .header("authorization", auth_header(&lead_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let requests = body["requests"].as_array().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["id"], request_id);
    assert_eq!(requests[0]["reason"], reason);
    assert!(requests[0].get("workflow_snapshot_json").is_none());
}

#[tokio::test]
async fn list_requests_shows_only_approvable_pending_requests_without_snapshot_leak() {
    let state = test_state_multistep();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, lead_token) = auth::create_token(&state, "lead1", "team-lead")
        .await
        .unwrap();
    let (_, dba_token) = auth::create_token(&state, "dba1", "dba").await.unwrap();
    let app = routes::router(state.clone());

    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&alice_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "operation": "execute_query",
                        "environment": "production",
                        "detail": "SELECT 1",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let request_id = body_json(resp).await["id"].as_str().unwrap().to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/requests")
                .header("authorization", auth_header(&lead_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let requests = body["requests"].as_array().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["id"], request_id);
    assert!(requests[0].get("workflow_snapshot_json").is_none());

    app.clone()
        .oneshot(
            Request::post(format!("/api/requests/{request_id}/approve"))
                .header("authorization", auth_header(&lead_token))
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/requests")
                .header("authorization", auth_header(&lead_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert!(body["requests"].as_array().unwrap().is_empty());

    let resp = app
        .oneshot(
            Request::get("/api/requests")
                .header("authorization", auth_header(&dba_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let requests = body["requests"].as_array().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["id"], request_id);
}

#[tokio::test]
async fn pending_for_me_returns_internal_error_when_approval_rows_are_malformed() {
    let state = test_state_multistep();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, lead_token) = auth::create_token(&state, "lead1", "team-lead")
        .await
        .unwrap();

    let app = routes::router(state.clone());
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&alice_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "operation": "execute_query",
                        "environment": "production",
                        "detail": "SELECT 1",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let request_id = body_json(resp).await["id"].as_str().unwrap().to_string();

    {
        let conn = state.sqlite.lock().await;
        conn.execute(
            "INSERT INTO approvals (id, request_id, action, actor_id, comment, step_index, actor_role, created_at)
             VALUES (?1, ?2, 'approve', 'broken', NULL, ?3, 'team-lead', ?4)",
            rusqlite::params![
                "bad-approval",
                request_id,
                "not-an-integer",
                "2026-05-04T00:00:00Z"
            ],
        )
        .unwrap();
    }

    let resp = app
        .oneshot(
            Request::get("/api/requests?pending_for_me=true")
                .header("authorization", auth_header(&lead_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = body_json(resp).await;
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("Invalid column type")
    );
    assert!(body["code"].is_null());
    assert!(body["hint"].is_null());
}

#[tokio::test]
async fn authz_errors_use_structured_json_shape() {
    let state = test_state();
    let (_, user_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let app = routes::router(state);

    let resp = app
        .oneshot(
            Request::post("/api/agent/poll")
                .header("authorization", auth_header(&user_token))
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = body_json(resp).await;
    assert_eq!(
        body,
        json!({
            "error": "agent poll is not allowed",
            "code": null,
            "hint": null,
        })
    );
}

#[tokio::test]
async fn auth_errors_use_structured_json_shape() {
    let app = routes::router(test_state());
    let resp = app
        .oneshot(
            Request::post("/api/requests")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"operation": "execute_query", "environment": "staging", "detail": "SELECT 1"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = body_json(resp).await;
    assert_eq!(
        body,
        json!({
            "error": "missing Authorization header",
            "code": null,
            "hint": null,
        })
    );
}

// ---------------------------------------------------------------------------
// Phase 2: Multi-step workflow approval tests
// ---------------------------------------------------------------------------

fn test_state_multistep() -> AppState {
    let conn = Connection::open_in_memory().unwrap();
    db::init(&conn).unwrap();
    let workflows = vec![
        dbward_server::server_config::WorkflowDef {
            database: "*".into(),
            environment: "development".into(),
            operations: vec![],
            steps: vec![],
            require_reason: false,
        },
        // 2-step: team-lead then dba
        dbward_server::server_config::WorkflowDef {
            database: "*".into(),
            environment: "production".into(),
            operations: vec![],
            steps: vec![
                dbward_server::server_config::WorkflowStep {
                    step_type: "approval".into(),
                    mode: "all".into(),
                    approvers: vec![dbward_server::server_config::ApproverGroup {
                        role: Some("team-lead".into()),
                        group: None,
                        min: 1,
                    }],
                    require_distinct_actors: true,
                },
                dbward_server::server_config::WorkflowStep {
                    step_type: "approval".into(),
                    mode: "all".into(),
                    approvers: vec![dbward_server::server_config::ApproverGroup {
                        role: Some("dba".into()),
                        group: None,
                        min: 1,
                    }],
                    require_distinct_actors: true,
                },
            ],
            require_reason: false,
        },
        // mode=any: either team-lead or dba
        dbward_server::server_config::WorkflowDef {
            database: "*".into(),
            environment: "staging".into(),
            operations: vec![],
            steps: vec![dbward_server::server_config::WorkflowStep {
                step_type: "approval".into(),
                mode: "any".into(),
                approvers: vec![
                    dbward_server::server_config::ApproverGroup {
                        role: Some("team-lead".into()),
                        group: None,
                        min: 1,
                    },
                    dbward_server::server_config::ApproverGroup {
                        role: Some("dba".into()),
                        group: None,
                        min: 1,
                    },
                ],
                require_distinct_actors: true,
            }],
            require_reason: false,
        },
    ];
    db::policy_repo::sync_workflows(&conn, &workflows).unwrap();
    AppState {
        sqlite: Arc::new(Mutex::new(conn)),
        token_signer: Arc::new(TokenSigner::generate()),
        webhooks: Arc::new(dbward_server::webhook::WebhookDispatcher::empty()),
        oidc: None,
        auth_mode: "token".to_string(),
        policy: Arc::new(Default::default()),
        result_channels: Arc::new(ResultChannels::new()),
        retention: Default::default(),
        request_notifier: Arc::new(dbward_server::RequestNotifier::new()),
    result_store: None,
        }
}

#[tokio::test]
async fn multi_step_approval_team_lead_then_dba() {
    let state = test_state_multistep();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, lead_token) = auth::create_token(&state, "lead1", "team-lead")
        .await
        .unwrap();
    let (_, dba_token) = auth::create_token(&state, "dba1", "dba").await.unwrap();

    let app = routes::router(state.clone());

    // Alice creates production request → pending
    let resp = app.clone().oneshot(
        Request::post("/api/requests")
            .header("authorization", auth_header(&alice_token))
            .header("content-type", "application/json")
            .body(Body::from(json!({"operation": "execute_query", "environment": "production", "detail": "DELETE FROM old"}).to_string()))
            .unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), 201);
    let body = body_json(resp).await;
    assert_eq!(body["status"], "pending");
    let request_id = body["id"].as_str().unwrap().to_string();

    // DBA tries to approve step 0 (needs team-lead) → 403
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{request_id}/approve"))
                .header("authorization", auth_header(&dba_token))
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Team-lead approves step 0 → still pending (step 1 remains)
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{request_id}/approve"))
                .header("authorization", auth_header(&lead_token))
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["status"], "pending");
    assert_eq!(body["step_completed"], 0);
    assert_eq!(body["current_step"], 1);
    assert_eq!(body["total_steps"], 2);
    assert!(body["execution_token"].is_null());

    // DBA approves step 1 → approved with token
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{request_id}/approve"))
                .header("authorization", auth_header(&dba_token))
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["status"], "approved");
    assert_eq!(body["approved_by"], "dba1");
    assert_eq!(body["step_completed"], 1);
    assert_eq!(body["current_step"], 2);
    assert_eq!(body["total_steps"], 2);
    assert!(body["execution_token"].is_object());
}

#[tokio::test]
async fn mode_any_either_role_can_approve() {
    let state = test_state_multistep();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, dba_token) = auth::create_token(&state, "dba1", "dba").await.unwrap();

    let app = routes::router(state.clone());

    // Alice creates staging request → pending (mode=any step)
    let resp = app.clone().oneshot(
        Request::post("/api/requests")
            .header("authorization", auth_header(&alice_token))
            .header("content-type", "application/json")
            .body(Body::from(json!({"operation": "execute_query", "environment": "staging", "detail": "SELECT 1"}).to_string()))
            .unwrap(),
    ).await.unwrap();
    assert_eq!(resp.status(), 201);
    let body = body_json(resp).await;
    assert_eq!(body["status"], "pending");
    let request_id = body["id"].as_str().unwrap().to_string();

    // DBA approves (mode=any, so dba alone is enough) → approved
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{request_id}/approve"))
                .header("authorization", auth_header(&dba_token))
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["status"], "approved");
    assert_eq!(body["approved_by"], "dba1");
    assert_eq!(body["step_completed"], 0);
    assert_eq!(body["current_step"], 1);
    assert_eq!(body["total_steps"], 1);
    assert!(body["execution_token"].is_object());
}

#[tokio::test]
async fn same_user_cannot_approve_twice_in_same_step() {
    let state = test_state_multistep();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, lead_token) = auth::create_token(&state, "lead1", "team-lead")
        .await
        .unwrap();

    let app = routes::router(state.clone());

    let resp = app.clone().oneshot(
        Request::post("/api/requests")
            .header("authorization", auth_header(&alice_token))
            .header("content-type", "application/json")
            .body(Body::from(json!({"operation": "execute_query", "environment": "production", "detail": "DELETE FROM old"}).to_string()))
            .unwrap(),
    ).await.unwrap();
    let body = body_json(resp).await;
    let request_id = body["id"].as_str().unwrap().to_string();

    // Lead approves step 0
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{request_id}/approve"))
                .header("authorization", auth_header(&lead_token))
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Lead tries to approve again (now step 1, but lead doesn't have dba role) → 403
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{request_id}/approve"))
                .header("authorization", auth_header(&lead_token))
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn wrong_role_cannot_approve_current_step() {
    let state = test_state_multistep();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, dev_token) = auth::create_token(&state, "dev1", "developer")
        .await
        .unwrap();

    let app = routes::router(state.clone());

    let resp = app.clone().oneshot(
        Request::post("/api/requests")
            .header("authorization", auth_header(&alice_token))
            .header("content-type", "application/json")
            .body(Body::from(json!({"operation": "execute_query", "environment": "production", "detail": "DELETE FROM old"}).to_string()))
            .unwrap(),
    ).await.unwrap();
    let body = body_json(resp).await;
    let request_id = body["id"].as_str().unwrap().to_string();

    // Developer (not team-lead or dba) tries to approve → 403
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{request_id}/approve"))
                .header("authorization", auth_header(&dev_token))
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn get_request_includes_approval_progress() {
    let state = test_state_multistep();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, lead_token) = auth::create_token(&state, "lead1", "team-lead")
        .await
        .unwrap();

    let app = routes::router(state.clone());

    let resp = app.clone().oneshot(
        Request::post("/api/requests")
            .header("authorization", auth_header(&alice_token))
            .header("content-type", "application/json")
            .body(Body::from(json!({"operation": "execute_query", "environment": "production", "detail": "SELECT 1"}).to_string()))
            .unwrap(),
    ).await.unwrap();
    let body = body_json(resp).await;
    let request_id = body["id"].as_str().unwrap().to_string();

    // Check progress before any approvals
    let resp = app
        .clone()
        .oneshot(
            Request::get(format!("/api/requests/{request_id}"))
                .header("authorization", auth_header(&alice_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = body_json(resp).await;
    let progress = &body["approval_progress"];
    assert_eq!(progress["current_step"], 0);
    assert_eq!(progress["total_steps"], 2);
    assert_eq!(progress["steps"][0]["satisfied"], false);
    assert_eq!(progress["steps"][1]["satisfied"], false);

    // Lead approves step 0
    app.clone()
        .oneshot(
            Request::post(format!("/api/requests/{request_id}/approve"))
                .header("authorization", auth_header(&lead_token))
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Check progress after step 0 approved
    let resp = app
        .clone()
        .oneshot(
            Request::get(format!("/api/requests/{request_id}"))
                .header("authorization", auth_header(&alice_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = body_json(resp).await;
    let progress = &body["approval_progress"];
    assert_eq!(progress["current_step"], 1);
    assert_eq!(progress["steps"][0]["satisfied"], true);
    assert_eq!(progress["steps"][1]["satisfied"], false);
}
