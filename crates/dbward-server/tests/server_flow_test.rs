use axum::body::Body;
use axum::http::StatusCode;
use http_body_util::BodyExt;
use hyper::Request;
use rusqlite::Connection;
use serde_json::{Value, json};
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::Mutex;
use tower::ServiceExt;

use dbward_server::{AppState, Metrics, ResultChannels, auth, db, routes, token::TokenSigner};

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
            allow_same_approver_across_steps: false,
            allow_self_approve: false,
        },
        dbward_server::server_config::WorkflowDef {
            database: "*".into(),
            environment: "staging".into(),
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
        result_store: None,
        draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        break_glass_roles: dbward_server::server_config::default_break_glass_roles(),
        audit_config: Default::default(),
        trusted_proxies: vec![],
        update_available: Arc::new(Mutex::new(None)),
    }
}

fn test_state_with_store() -> (AppState, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let mut state = test_state();
    state.result_store = Some(Arc::new(
        dbward_server::result_storage::ResultStore::new_local(dir.path().to_str().unwrap())
            .unwrap()
            .with_prefix("shared"),
    ));
    (state, dir)
}

fn test_state_group_approval_with_store() -> (AppState, TempDir) {
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
                    role: None,
                    group: Some("prod-approvers".into()),
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

    let dir = tempfile::tempdir().unwrap();
    let result_store = Arc::new(
        dbward_server::result_storage::ResultStore::new_local(dir.path().to_str().unwrap())
            .unwrap()
            .with_prefix("shared"),
    );

    let state = AppState {
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
        result_store: Some(result_store),
        draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        break_glass_roles: dbward_server::server_config::default_break_glass_roles(),
        audit_config: Default::default(),
        trusted_proxies: vec![],
        update_available: Arc::new(Mutex::new(None)),
    };
    (state, dir)
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
async fn ready_check() {
    let app = routes::router(test_state());
    let resp = app
        .oneshot(Request::get("/ready").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn metrics_endpoint_returns_prometheus_text() {
    let state = test_state();
    let (_, admin_token) = auth::create_token_with_type(&state, "admin", "admin", "user")
        .await
        .unwrap();
    let app = routes::router(state);
    let resp = app
        .oneshot(
            Request::get("/metrics")
                .header("authorization", format!("Bearer {admin_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("text/plain; version=0.0.4; charset=utf-8")
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(text.contains("# HELP dbward_http_requests_total"));
    assert!(text.contains("# TYPE dbward_http_request_duration_seconds histogram"));
    assert!(text.contains("dbward_break_glass_total 0"));
}

#[tokio::test]
async fn ready_returns_503_while_draining() {
    let state = test_state();
    state
        .draining
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let app = routes::router(state);

    let resp = app
        .oneshot(Request::get("/ready").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn create_request_returns_503_while_draining() {
    let state = test_state();
    let (_, token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    state
        .draining
        .store(true, std::sync::atomic::Ordering::SeqCst);
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

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = body_json(resp).await;
    assert_eq!(body["error"], "server is shutting down");
    assert_eq!(body["code"], "server_shutting_down");
}

#[tokio::test]
async fn stream_result_returns_503_while_draining() {
    let state = test_state();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
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
                    json!({"operation": "execute_query", "environment": "staging", "detail": "SELECT 1"}).to_string(),
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

    state
        .draining
        .store(true, std::sync::atomic::Ordering::SeqCst);

    let resp = app
        .oneshot(
            Request::get(format!("/api/requests/{request_id}/result/stream"))
                .header("authorization", auth_header(&alice_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = body_json(resp).await;
    assert_eq!(body["error"], "server is shutting down");
    assert_eq!(body["code"], "server_shutting_down");
    assert_eq!(body["hint"], format!("dbward request resume {request_id}"));
}

#[tokio::test]
async fn drain_notifies_waiting_stream_result() {
    let state = test_state();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
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
                    json!({"operation": "execute_query", "environment": "staging", "detail": "SELECT 1"}).to_string(),
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

    let wait_app = app.clone();
    let wait_token = alice_token.clone();
    let wait_id = request_id.clone();
    let waiter = tokio::spawn(async move {
        wait_app
            .oneshot(
                Request::get(format!("/api/requests/{wait_id}/result/stream"))
                    .header("authorization", auth_header(&wait_token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    state
        .draining
        .store(true, std::sync::atomic::Ordering::SeqCst);
    state.result_channels.notify_all().await;

    let resp = tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
        .await
        .expect("waiting result stream should be notified during drain")
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = body_json(resp).await;
    assert_eq!(body["code"], "server_shutting_down");
    assert_eq!(body["hint"], format!("dbward request resume {request_id}"));
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
    assert_eq!(body["status"], "dispatched");
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
    assert_eq!(body["status"], "dispatched");
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
async fn shared_result_content_requires_matching_result_access() {
    let (state, _dir) = test_state_with_store();
    let (_, owner_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, other_token) = auth::create_token(&state, "bob", "developer")
        .await
        .unwrap();
    let request_id = "11111111-1111-4111-8111-111111111111";

    {
        let conn = state.sqlite.lock().await;
        conn.execute(
            "INSERT INTO requests (id, created_by, operation, environment, database_name, status, detail, share_with_json, created_at, updated_at)
             VALUES (?1, 'alice', 'execute_query', 'staging', 'app', 'executed', 'SELECT 1', '[\"group:data\"]', 't1', 't1')",
            [request_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO request_results (request_id, storage_backend, storage_key, content_length, checksum_sha256, retention_days, status, stored_at, expires_at)
             VALUES (?1, 'local', ?2, 12, 'abc', 30, 'stored', '2026-01-01T00:00:00Z', '2099-01-01T00:00:00Z')",
            [request_id, "shared/11111111-1111-4111-8111-111111111111.json"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO result_access (request_id, selector_type, selector_value) VALUES (?1, 'requester', '')",
            [request_id],
        )
        .unwrap();
    }
    state
        .result_store
        .as_ref()
        .unwrap()
        .put(request_id, br#"{"rows":[1]}"#)
        .await
        .unwrap();

    let app = routes::router(state.clone());

    let owner_resp = app
        .clone()
        .oneshot(
            Request::get(format!("/api/requests/{request_id}/result/content"))
                .header("authorization", auth_header(&owner_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(owner_resp.status(), StatusCode::OK);
    let owner_bytes = owner_resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&owner_bytes[..], br#"{"rows":[1]}"#);

    let other_resp = app
        .oneshot(
            Request::get(format!("/api/requests/{request_id}/result/content"))
                .header("authorization", auth_header(&other_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(other_resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn list_results_only_returns_accessible_rows() {
    let state = test_state();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();

    {
        let conn = state.sqlite.lock().await;
        conn.execute(
            "INSERT INTO requests (id, created_by, operation, environment, database_name, status, detail, created_at, updated_at)
             VALUES (?1, 'alice', 'execute_query', 'staging', 'app', 'executed', 'SELECT 1', 't1', 't1')",
            ["req-visible"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO requests (id, created_by, operation, environment, database_name, status, detail, created_at, updated_at)
             VALUES (?1, 'carol', 'execute_query', 'staging', 'app', 'executed', 'SELECT 2', 't1', 't1')",
            ["req-hidden"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO request_results (request_id, storage_backend, storage_key, content_length, checksum_sha256, retention_days, status, stored_at, expires_at)
             VALUES (?1, 'local', 'shared/req-visible.json', 12, 'abc', 30, 'stored', '2026-01-01T00:00:00Z', '2099-01-01T00:00:00Z')",
            ["req-visible"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO request_results (request_id, storage_backend, storage_key, content_length, checksum_sha256, retention_days, status, stored_at, expires_at)
             VALUES (?1, 'local', 'shared/req-hidden.json', 12, 'abc', 30, 'stored', '2026-01-01T00:00:00Z', '2099-01-01T00:00:00Z')",
            ["req-hidden"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO result_access (request_id, selector_type, selector_value) VALUES (?1, 'requester', '')",
            ["req-visible"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO result_access (request_id, selector_type, selector_value) VALUES (?1, 'group', 'finance')",
            ["req-hidden"],
        )
        .unwrap();
    }

    let app = routes::router(state);
    let resp = app
        .oneshot(
            Request::get("/api/results")
                .header("authorization", auth_header(&alice_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let results = body["results"].as_array().unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["request_id"], "req-visible");
}

#[tokio::test]
async fn shared_results_are_stored_and_exposed_only_to_shared_users() {
    let (state, dir) = test_state_with_store();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, bob_token) = auth::create_token(&state, "bob", "developer")
        .await
        .unwrap();
    let (_, carol_token) = auth::create_token(&state, "carol", "developer")
        .await
        .unwrap();
    let (_, agent_token) = auth::create_token_with_type(&state, "agent-1", "admin", "agent")
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
                        "environment": "staging",
                        "database": "app",
                        "detail": "SELECT 1",
                        "share_with": ["user:bob"]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;
    let shared_request_id = body["id"].as_str().unwrap().to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{shared_request_id}/dispatch"))
                .header("authorization", auth_header(&alice_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/agent/jobs/{shared_request_id}/claim"))
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let shared_exec_id = body["execution_id"].as_str().unwrap().to_string();

    let shared_result = json!({"rows": [{"value": 1}]});
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/agent/jobs/{shared_exec_id}/result"))
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"success": true, "result": shared_result.clone()}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    {
        let conn = state.sqlite.lock().await;
        let (status, storage_key, content_length): (String, String, i64) = conn
            .query_row(
                "SELECT status, storage_key, content_length FROM request_results WHERE request_id = ?1",
                [&shared_request_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(status, "stored");
        assert_eq!(storage_key, format!("shared/{shared_request_id}.json"));
        assert!(content_length > 0);

        let selectors: Vec<(String, String)> = {
            let mut stmt = conn
                .prepare(
                    "SELECT selector_type, selector_value FROM result_access WHERE request_id = ?1 ORDER BY selector_type, selector_value",
                )
                .unwrap();
            stmt.query_map([&shared_request_id], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .map(|row| row.unwrap())
                .collect()
        };
        assert_eq!(
            selectors,
            vec![
                ("requester".to_string(), "".to_string()),
                ("role".to_string(), "admin".to_string()),
                ("user".to_string(), "bob".to_string()),
            ]
        );
    }

    let shared_path = dir
        .path()
        .join("shared")
        .join(format!("{shared_request_id}.json"));
    assert!(shared_path.exists());

    let resp = app
        .clone()
        .oneshot(
            Request::get(format!("/api/requests/{shared_request_id}/result/content"))
                .header("authorization", auth_header(&bob_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body, shared_result);

    let resp = app
        .clone()
        .oneshot(
            Request::get(format!("/api/requests/{shared_request_id}/result/content"))
                .header("authorization", auth_header(&carol_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/results")
                .header("authorization", auth_header(&bob_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let results = body["results"].as_array().unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["request_id"], shared_request_id);

    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&alice_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "operation": "execute_query",
                        "environment": "staging",
                        "database": "app",
                        "detail": "SELECT 2"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;
    let direct_request_id = body["id"].as_str().unwrap().to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{direct_request_id}/dispatch"))
                .header("authorization", auth_header(&alice_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/agent/jobs/{direct_request_id}/claim"))
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let direct_exec_id = body["execution_id"].as_str().unwrap().to_string();

    let resp = app
        .oneshot(
            Request::post(format!("/api/agent/jobs/{direct_exec_id}/result"))
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"success": true, "result": {"rows": [{"value": 2}]}}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    {
        let conn = state.sqlite.lock().await;
        let stored_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM request_results WHERE request_id = ?1",
                [&direct_request_id],
                |row| row.get(0),
            )
            .unwrap();
        // With result_storage configured, all results are auto-persisted
        assert_eq!(stored_count, 1);
    }
    // Auto-persisted result file exists (default access: requester + admin)
    assert!(
        dir.path()
            .join("shared")
            .join(format!("{direct_request_id}.json"))
            .exists()
    );
}

#[tokio::test]
async fn group_approver_can_execute_and_read_group_shared_result() {
    let (state, _dir) = test_state_group_approval_with_store();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, bob_token) =
        auth::create_token_with_groups(&state, "bob", "readonly", &["prod-approvers", "data-team"])
            .await
            .unwrap();
    let (_, agent_token) = auth::create_token_with_type(&state, "agent-1", "admin", "agent")
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
                        "database": "app",
                        "detail": "SELECT 42",
                        "share_with": ["group:data-team"]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp).await;
    assert_eq!(body["status"], "pending");
    let request_id = body["id"].as_str().unwrap().to_string();

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
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["status"], "dispatched");

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
        .clone()
        .oneshot(
            Request::post(format!("/api/agent/jobs/{request_id}/claim"))
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let exec_id = body["execution_id"].as_str().unwrap().to_string();

    let stored_result = json!({"rows": [{"value": 42}]});
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/agent/jobs/{exec_id}/result"))
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"success": true, "result": stored_result.clone()}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    {
        let conn = state.sqlite.lock().await;
        let selectors: Vec<(String, String)> = {
            let mut stmt = conn
                .prepare(
                    "SELECT selector_type, selector_value FROM result_access WHERE request_id = ?1 ORDER BY selector_type, selector_value",
                )
                .unwrap();
            stmt.query_map([&request_id], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .map(|row| row.unwrap())
                .collect()
        };
        assert_eq!(
            selectors,
            vec![
                ("group".to_string(), "data-team".to_string()),
                ("requester".to_string(), "".to_string()),
                ("role".to_string(), "admin".to_string()),
            ]
        );
    }

    let resp = app
        .clone()
        .oneshot(
            Request::get(format!("/api/requests/{request_id}/result/content"))
                .header("authorization", auth_header(&bob_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body, stored_result);

    let resp = app
        .oneshot(
            Request::get("/api/results")
                .header("authorization", auth_header(&bob_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let results = body["results"].as_array().unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["request_id"], request_id);
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
async fn current_step_approver_can_read_request_and_see_approval_comment() {
    let state = test_state_multistep();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, lead_token) = auth::create_token(&state, "lead1", "team-lead")
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
    let request_id = body_json(resp).await["id"].as_str().unwrap().to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::get(format!("/api/requests/{request_id}"))
                .header("authorization", auth_header(&lead_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{request_id}/approve"))
                .header("authorization", auth_header(&lead_token))
                .header("content-type", "application/json")
                .body(Body::from(json!({ "comment": "LGTM" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["status"], "pending");

    let resp = app
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
    assert_eq!(
        body["approval_progress"]["steps"][0]["approvals"][0]["comment"],
        "LGTM"
    );
}

#[tokio::test]
async fn reject_comment_is_saved() {
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
    let request_id = body_json(resp).await["id"].as_str().unwrap().to_string();

    let resp = app
        .oneshot(
            Request::post(format!("/api/requests/{request_id}/reject"))
                .header("authorization", auth_header(&lead_token))
                .header("content-type", "application/json")
                .body(Body::from(json!({ "comment": "Denied" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let conn = state.sqlite.lock().await;
    let stored: Option<String> = conn
        .query_row(
            "SELECT comment FROM approvals WHERE request_id = ?1 AND action = 'reject'",
            rusqlite::params![request_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored.as_deref(), Some("Denied"));
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

    // 1. Alice creates a request (development → auto-dispatched)
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
    assert_eq!(body["status"], "dispatched");

    // 2. Agent polls — should immediately see the dispatched request
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
    assert_eq!(body["jobs"].as_array().unwrap().len(), 1);

    // 3. Alice dispatches the request again — still idempotently dispatched
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

    // 4. Agent polls — request remains dispatchable until claimed
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
async fn agent_result_recreates_missing_result_slot() {
    let state = test_state();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, agent_token) = auth::create_token_with_type(&state, "agent-1", "admin", "agent")
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

    drop(state.result_channels.remove(&request_id).await);

    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/agent/jobs/{request_id}/claim"))
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from(json!({"agent_id": "agent-1"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let exec_id = body_json(resp).await["execution_id"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/agent/jobs/{exec_id}/result"))
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"success": true, "result": {"recovered": true}}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .oneshot(
            Request::get(format!("/api/requests/{request_id}/result/stream"))
                .header("authorization", auth_header(&alice_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["success"], true);
    assert_eq!(body["result"], json!({"recovered": true}));
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
    assert_eq!(body["status"], "dispatched");
}

#[tokio::test]
async fn create_request_falls_back_to_static_policy_when_no_workflow_matches() {
    let conn = Connection::open_in_memory().unwrap();
    db::init(&conn).unwrap();
    let state = AppState {
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
        result_store: None,
        draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        break_glass_roles: dbward_server::server_config::default_break_glass_roles(),
        audit_config: Default::default(),
        trusted_proxies: vec![],
        update_available: Arc::new(Mutex::new(None)),
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
    assert_eq!(body["status"], "dispatched");
}

#[tokio::test]
async fn emergency_request_respects_admin_only_break_glass_roles() {
    let mut state = test_state();
    state.break_glass_roles = vec!["admin".into()];
    let (_, dev_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let app = routes::router(state);

    let resp = app
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&dev_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "operation": "execute_query",
                        "environment": "production",
                        "detail": "SELECT 1",
                        "emergency": true,
                        "reason": "urgent fix"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = body_json(resp).await;
    assert_eq!(body["code"], "break_glass_forbidden");
}

#[tokio::test]
async fn emergency_request_is_disabled_when_break_glass_roles_is_empty() {
    let mut state = test_state();
    state.break_glass_roles = vec![];
    let (_, admin_token) = auth::create_token(&state, "alice", "admin").await.unwrap();
    let app = routes::router(state);

    let resp = app
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&admin_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "operation": "execute_query",
                        "environment": "production",
                        "detail": "SELECT 1",
                        "emergency": true,
                        "reason": "urgent fix"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = body_json(resp).await;
    assert_eq!(body["code"], "break_glass_forbidden");
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
async fn cancel_requires_requester_or_admin() {
    let state = test_state();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, bob_token) = auth::create_token(&state, "bob", "developer")
        .await
        .unwrap();
    let (_, admin_token) = auth::create_token(&state, "admin", "admin").await.unwrap();

    let app = routes::router(state);

    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&alice_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"operation":"execute_query","environment":"development","database":"default","detail":"SELECT 1"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = body_json(resp).await;
    let id = body["id"].as_str().unwrap().to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{id}/cancel"))
                .header("authorization", auth_header(&bob_token))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"reason":"nope"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{id}/cancel"))
                .header("authorization", auth_header(&admin_token))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"reason":"stop"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["status"], "cancelled");
}

#[tokio::test]
async fn cancel_allows_pending_approved_dispatched_and_running() {
    let state = test_state();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, approver_token) = auth::create_token(&state, "approver", "admin")
        .await
        .unwrap();
    let (_, agent_token) = auth::create_token_with_type(&state, "agent-1", "admin", "agent")
        .await
        .unwrap();
    let app = routes::router(state.clone());

    let pending_resp = app
        .clone()
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&alice_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"operation":"execute_query","environment":"production","database":"default","detail":"SELECT 1"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let pending_id = body_json(pending_resp).await["id"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{pending_id}/cancel"))
                .header("authorization", auth_header(&alice_token))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"reason":"pending"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let approved_resp = app
        .clone()
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&alice_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"operation":"execute_query","environment":"production","database":"default","detail":"SELECT 2"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let approved_id = body_json(approved_resp).await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let _ = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{approved_id}/approve"))
                .header("authorization", auth_header(&approver_token))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{approved_id}/cancel"))
                .header("authorization", auth_header(&alice_token))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"reason":"approved"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let dispatched_resp = app
        .clone()
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&alice_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"operation":"execute_query","environment":"development","database":"default","detail":"SELECT 3"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let dispatched_id = body_json(dispatched_resp).await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let _ = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{dispatched_id}/dispatch"))
                .header("authorization", auth_header(&alice_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{dispatched_id}/cancel"))
                .header("authorization", auth_header(&alice_token))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"reason":"dispatched"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let running_resp = app
        .clone()
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&alice_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"operation":"execute_query","environment":"development","database":"default","detail":"SELECT 4"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let running_id = body_json(running_resp).await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let _ = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{running_id}/dispatch"))
                .header("authorization", auth_header(&alice_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let _ = app
        .clone()
        .oneshot(
            Request::post("/api/agent/poll")
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"databases":["default"],"environments":["development"],"operations":["execute_query"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let claim_resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/agent/jobs/{running_id}/claim"))
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(claim_resp.status(), StatusCode::OK);
    let execution_id = body_json(claim_resp).await["execution_id"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{running_id}/cancel"))
                .header("authorization", auth_header(&alice_token))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"reason":"running"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let result_resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/agent/jobs/{execution_id}/result"))
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"success":true,"result":{"ok":true}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(result_resp.status(), StatusCode::OK);

    let request_resp = app
        .oneshot(
            Request::get(format!("/api/requests/{running_id}"))
                .header("authorization", auth_header(&alice_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let request_body = body_json(request_resp).await;
    assert_eq!(request_body["status"], "cancelled");
}

#[tokio::test]
async fn cancel_rejects_terminal_states() {
    let state = test_state();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, admin_token) = auth::create_token(&state, "admin", "admin").await.unwrap();
    let (_, agent_token) = auth::create_token_with_type(&state, "agent-1", "admin", "agent")
        .await
        .unwrap();
    let app = routes::router(state.clone());

    let rejected_resp = app
        .clone()
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&alice_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"operation":"execute_query","environment":"production","database":"default","detail":"SELECT 1"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let rejected_id = body_json(rejected_resp).await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let _ = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{rejected_id}/reject"))
                .header("authorization", auth_header(&admin_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let executed_resp = app
        .clone()
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&alice_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"operation":"execute_query","environment":"development","database":"default","detail":"SELECT 2"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let executed_id = body_json(executed_resp).await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let _ = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{executed_id}/dispatch"))
                .header("authorization", auth_header(&alice_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let _ = app
        .clone()
        .oneshot(
            Request::post("/api/agent/poll")
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"databases":["default"],"environments":["development"],"operations":["execute_query"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let executed_claim = app
        .clone()
        .oneshot(
            Request::post(format!("/api/agent/jobs/{executed_id}/claim"))
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    let executed_execution_id = body_json(executed_claim).await["execution_id"]
        .as_str()
        .unwrap()
        .to_string();
    let _ = app
        .clone()
        .oneshot(
            Request::post(format!("/api/agent/jobs/{executed_execution_id}/result"))
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"success":true,"result":{"ok":true}}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    let failed_resp = app
        .clone()
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&alice_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"operation":"execute_query","environment":"development","database":"default","detail":"SELECT 3"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let failed_id = body_json(failed_resp).await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let _ = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{failed_id}/dispatch"))
                .header("authorization", auth_header(&alice_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let _ = app
        .clone()
        .oneshot(
            Request::post("/api/agent/poll")
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"databases":["default"],"environments":["development"],"operations":["execute_query"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let failed_claim = app
        .clone()
        .oneshot(
            Request::post(format!("/api/agent/jobs/{failed_id}/claim"))
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    let failed_execution_id = body_json(failed_claim).await["execution_id"]
        .as_str()
        .unwrap()
        .to_string();
    let _ = app
        .clone()
        .oneshot(
            Request::post(format!("/api/agent/jobs/{failed_execution_id}/result"))
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"success":false,"error":"boom"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    let cancelled_resp = app
        .clone()
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&alice_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"operation":"execute_query","environment":"development","database":"default","detail":"SELECT 4"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let cancelled_id = body_json(cancelled_resp).await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let _ = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{cancelled_id}/cancel"))
                .header("authorization", auth_header(&alice_token))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"reason":"once"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    for id in [&rejected_id, &executed_id, &failed_id, &cancelled_id] {
        let resp = app
            .clone()
            .oneshot(
                Request::post(format!("/api/requests/{id}/cancel"))
                    .header("authorization", auth_header(&alice_token))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"reason":"again"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }
}

#[tokio::test]
async fn cancel_notifies_waiting_get_request() {
    let state = test_state();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
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
                    r#"{"operation":"execute_query","environment":"production","database":"default","detail":"SELECT wait"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let id = body_json(resp).await["id"].as_str().unwrap().to_string();

    let wait_app = app.clone();
    let wait_token = alice_token.clone();
    let wait_id = id.clone();
    let waiter = tokio::spawn(async move {
        wait_app
            .oneshot(
                Request::get(format!("/api/requests/{wait_id}?wait=5"))
                    .header("authorization", auth_header(&wait_token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let cancel_resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{id}/cancel"))
                .header("authorization", auth_header(&alice_token))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"reason":"wake waiter"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cancel_resp.status(), StatusCode::OK);

    let wait_resp = tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
        .await
        .expect("waiting GET should be notified")
        .unwrap();
    assert_eq!(wait_resp.status(), StatusCode::OK);
    let body = body_json(wait_resp).await;
    assert_eq!(body["status"], "cancelled");
}

#[tokio::test]
async fn claim_race_returns_conflict_for_second_claim() {
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
                    r#"{"operation":"execute_query","environment":"development","database":"default","detail":"SELECT race"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let id = body_json(resp).await["id"].as_str().unwrap().to_string();

    let _ = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{id}/dispatch"))
                .header("authorization", auth_header(&alice_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let first = app
        .clone()
        .oneshot(
            Request::post(format!("/api/agent/jobs/{id}/claim"))
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    let second = app
        .oneshot(
            Request::post(format!("/api/agent/jobs/{id}/claim"))
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::CONFLICT);
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
async fn get_request_includes_metadata_and_idempotency_key() {
    let state = test_state();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
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
                        "environment": "development",
                        "detail": "SELECT 1",
                        "metadata": {"ticket": "ABC-123", "repo": "dbward"},
                        "idempotency_key": "idem-123",
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
    assert_eq!(
        body["metadata"],
        json!({"ticket": "ABC-123", "repo": "dbward"})
    );
    assert_eq!(body["idempotency_key"], "idem-123");
}

#[tokio::test]
async fn create_request_rejects_invalid_or_oversized_metadata() {
    let state = test_state();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
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
                        "environment": "development",
                        "detail": "SELECT 1",
                        "metadata": ["not", "an", "object"],
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert_eq!(body["code"], "invalid_metadata");

    let oversized = "x".repeat(8 * 1024);
    let resp = app
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&alice_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "operation": "execute_query",
                        "environment": "development",
                        "detail": "SELECT 1",
                        "metadata": {"blob": oversized},
                    })
                    .to_string(),
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
            allow_same_approver_across_steps: false,
            allow_self_approve: false,
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
            allow_same_approver_across_steps: false,
            allow_self_approve: false,
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
        result_store: None,
        draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        break_glass_roles: dbward_server::server_config::default_break_glass_roles(),
        audit_config: Default::default(),
        trusted_proxies: vec![],
        update_available: Arc::new(Mutex::new(None)),
    }
}

fn test_state_multistep_allow_same() -> AppState {
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
            steps: vec![
                dbward_server::server_config::WorkflowStep {
                    step_type: "approval".into(),
                    mode: "all".into(),
                    approvers: vec![dbward_server::server_config::ApproverGroup {
                        role: Some("admin".into()),
                        group: None,
                        min: 1,
                    }],
                    require_distinct_actors: true,
                },
                dbward_server::server_config::WorkflowStep {
                    step_type: "approval".into(),
                    mode: "all".into(),
                    approvers: vec![dbward_server::server_config::ApproverGroup {
                        role: Some("admin".into()),
                        group: None,
                        min: 1,
                    }],
                    require_distinct_actors: true,
                },
            ],
            require_reason: false,
            allow_same_approver_across_steps: true,
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
        result_store: None,
        draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        break_glass_roles: dbward_server::server_config::default_break_glass_roles(),
        audit_config: Default::default(),
        trusted_proxies: vec![],
        update_available: Arc::new(Mutex::new(None)),
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
    assert_eq!(body["status"], "dispatched");
    assert_eq!(body["approved_by"], "dba1");
    assert_eq!(body["step_completed"], 1);
    assert_eq!(body["current_step"], 2);
    assert_eq!(body["total_steps"], 2);
    assert!(body["execution_token"].is_object());
}

#[tokio::test]
async fn same_approver_across_steps_returns_forbidden_error() {
    let state = test_state_multistep_allow_same();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, admin_token) = auth::create_token(&state, "admin1", "admin").await.unwrap();

    {
        let conn = state.sqlite.lock().await;
        conn.execute(
            "UPDATE workflows SET allow_same_approver_across_steps = 0 WHERE environment = 'production'",
            [],
        )
        .unwrap();
    }

    let app = routes::router(state.clone());
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&alice_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"operation": "execute_query", "environment": "production", "detail": "DELETE FROM old"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let request_id = body_json(resp).await["id"].as_str().unwrap().to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{request_id}/approve"))
                .header("authorization", auth_header(&admin_token))
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{request_id}/approve"))
                .header("authorization", auth_header(&admin_token))
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
            "error": "you already approved a previous step of this request",
            "code": "same_approver_across_steps",
            "hint": null,
        })
    );
}

#[tokio::test]
async fn allow_same_approver_across_steps_true_allows_second_step() {
    let state = test_state_multistep_allow_same();
    let (_, alice_token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, admin_token) = auth::create_token(&state, "admin1", "admin").await.unwrap();

    let app = routes::router(state.clone());
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&alice_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"operation": "execute_query", "environment": "production", "detail": "DELETE FROM old"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let request_id = body_json(resp).await["id"].as_str().unwrap().to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{request_id}/approve"))
                .header("authorization", auth_header(&admin_token))
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["status"], "pending");
    assert_eq!(body["current_step"], 1);

    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{request_id}/approve"))
                .header("authorization", auth_header(&admin_token))
                .header("content-type", "application/json")
                .body(Body::from(json!({}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = body_json(resp).await;
    assert_eq!(body["status"], "dispatched");
    assert_eq!(body["approved_by"], "admin1");
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
    assert_eq!(body["status"], "dispatched");
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

#[tokio::test]
async fn heartbeat_extends_lease() {
    let state = test_state();
    let app = routes::router(state.clone());
    let (_, token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, agent_token) = auth::create_token_with_type(&state, "agent-1", "admin", "agent")
        .await
        .unwrap();

    // Create + dispatch
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"operation":"execute_query","environment":"development","database":"primary","detail":"SELECT 1"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = body_json(resp).await;
    let request_id = body["id"].as_str().unwrap().to_string();

    app.clone()
        .oneshot(
            Request::post(format!("/api/requests/{request_id}/dispatch"))
                .header("authorization", auth_header(&token))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    // Claim
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/agent/jobs/{request_id}/claim"))
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    let exec_id = body["execution_id"].as_str().unwrap().to_string();

    // Get initial lease
    let initial_lease: String = {
        let conn = state.sqlite.lock().await;
        conn.query_row(
            "SELECT lease_expires_at FROM agent_executions WHERE id = ?1",
            rusqlite::params![exec_id],
            |row| row.get(0),
        )
        .unwrap()
    };

    // Heartbeat
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/agent/jobs/{exec_id}/heartbeat"))
                .header("authorization", auth_header(&agent_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify lease was extended
    let new_lease: String = {
        let conn = state.sqlite.lock().await;
        conn.query_row(
            "SELECT lease_expires_at FROM agent_executions WHERE id = ?1",
            rusqlite::params![exec_id],
            |row| row.get(0),
        )
        .unwrap()
    };
    assert!(new_lease > initial_lease, "lease should be extended");
}

#[tokio::test]
async fn stream_result_works_with_short_id() {
    let state = test_state();
    let app = routes::router(state.clone());
    let (_, token) = auth::create_token(&state, "alice", "developer")
        .await
        .unwrap();
    let (_, agent_token) = auth::create_token_with_type(&state, "agent-1", "admin", "agent")
        .await
        .unwrap();

    // Create + dispatch
    let resp = app
        .clone()
        .oneshot(
            Request::post("/api/requests")
                .header("authorization", auth_header(&token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"operation":"execute_query","environment":"development","database":"primary","detail":"SELECT 1"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = body_json(resp).await;
    let full_id = body["id"].as_str().unwrap().to_string();
    let short_id = &full_id[..8];

    // Dispatch with short ID
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/requests/{short_id}/dispatch"))
                .header("authorization", auth_header(&token))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Claim + submit result
    let resp = app
        .clone()
        .oneshot(
            Request::post(format!("/api/agent/jobs/{full_id}/claim"))
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    let body = body_json(resp).await;
    let exec_id = body["execution_id"].as_str().unwrap().to_string();

    app.clone()
        .oneshot(
            Request::post(format!("/api/agent/jobs/{exec_id}/result"))
                .header("authorization", auth_header(&agent_token))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"success": true, "result": {"answer": 42}}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Stream with short ID — should find the channel
    let resp = app
        .clone()
        .oneshot(
            Request::get(format!("/api/requests/{short_id}/result/stream"))
                .header("authorization", auth_header(&token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["success"], true);
}
