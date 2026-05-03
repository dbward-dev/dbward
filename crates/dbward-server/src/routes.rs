use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;
use std::sync::Arc;
use std::time::Instant;

use crate::auth;
use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/requests", get(list_requests).post(create_request))
        .route("/api/requests/{id}", get(get_request))
        .route(
            "/api/requests/{id}/approve",
            axum::routing::post(approve_request),
        )
        .route(
            "/api/requests/{id}/reject",
            axum::routing::post(reject_request),
        )
        .route(
            "/api/requests/{id}/complete",
            axum::routing::post(complete_request),
        )
        .route(
            "/api/requests/{id}/dispatch",
            axum::routing::post(dispatch_request),
        )
        .route("/api/requests/{id}/result/stream", get(stream_result))
        .route("/api/agent/poll", axum::routing::post(agent_poll))
        .route(
            "/api/agent/jobs/{id}/claim",
            axum::routing::post(agent_claim),
        )
        .route(
            "/api/agent/jobs/{id}/result",
            axum::routing::post(agent_result),
        )
        .route("/api/audit", get(list_audit))
        .route("/api/public-key", get(get_public_key))
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    Json(json!({"status": "ok"}))
}

async fn get_public_key(State(state): State<AppState>) -> impl IntoResponse {
    let bytes = state.token_signer.verifying_key().to_bytes();
    (
        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
        bytes.to_vec(),
    )
}

async fn list_requests(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let _user = auth::authenticate(&headers, &state).await?;

    let conn = state.sqlite.lock().await;
    let mut stmt = conn
        .prepare("SELECT id, created_by, operation, environment, database_name, detail, status, emergency, created_at, updated_at, resolved_at FROM requests ORDER BY created_at DESC")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let rows: Vec<serde_json::Value> = stmt
        .query_map([], |row| {
            Ok(json!({
                "id": row.get::<_, String>(0)?,
                "created_by": row.get::<_, String>(1)?,
                "operation": row.get::<_, String>(2)?,
                "environment": row.get::<_, String>(3)?,
                "database_name": row.get::<_, String>(4)?,
                "detail": row.get::<_, String>(5)?,
                "status": row.get::<_, String>(6)?,
                "emergency": row.get::<_, bool>(7)?,
                "created_at": row.get::<_, String>(8)?,
                "updated_at": row.get::<_, String>(9)?,
                "resolved_at": row.get::<_, Option<String>>(10)?,
            }))
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .filter_map(|r| r.ok())
        .collect();

    Ok(Json(json!({"requests": rows})))
}

async fn create_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;

    let operation = body["operation"]
        .as_str()
        .ok_or((StatusCode::BAD_REQUEST, "operation required".into()))?;
    let environment = body["environment"]
        .as_str()
        .ok_or((StatusCode::BAD_REQUEST, "environment required".into()))?;
    let detail = body["detail"].as_str().unwrap_or("");
    let database_name = body["database"].as_str().unwrap_or("default");
    let emergency = body["emergency"].as_bool().unwrap_or(false);
    let reason = body["reason"].as_str().map(|s| s.to_string());

    if emergency && reason.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "reason is required for emergency requests".into(),
        ));
    }
    // Readonly cannot use break-glass
    if emergency && user.role == dbward_core::Role::Readonly {
        return Err((
            StatusCode::FORBIDDEN,
            "readonly users cannot use break-glass".into(),
        ));
    }

    // Policy evaluation
    let needs_approval = !emergency
        && state
            .policy
            .evaluate(environment, operation, &user.role.to_string())
            == "require_approval";

    let status = if emergency {
        "break_glass"
    } else if needs_approval {
        "pending"
    } else {
        "auto_approved"
    };

    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    let conn = state.sqlite.lock().await;
    conn.execute(
        "INSERT INTO requests (id, created_by, operation, environment, database_name, detail, status, created_at, updated_at, emergency, reason) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        rusqlite::params![id, user.user, operation, environment, database_name, detail, status, now, now, emergency, reason],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if emergency {
        let token = state
            .token_signer
            .issue(&id, operation, environment, database_name, detail);
        state.webhooks.dispatch(crate::webhook::WebhookEvent {
            event: "break_glass".into(),
            request_id: id.clone(),
            user: user.user.clone(),
            operation: operation.into(),
            environment: environment.into(),
            detail: detail.into(),
            approved_by: None,
            reason: reason.clone(),
        });
        Ok((
            StatusCode::CREATED,
            Json(json!({"id": id, "status": "break_glass", "execution_token": token})),
        ))
    } else if needs_approval {
        state.webhooks.dispatch(crate::webhook::WebhookEvent {
            event: "request_created".into(),
            request_id: id.clone(),
            user: user.user.clone(),
            operation: operation.into(),
            environment: environment.into(),
            detail: detail.into(),
            approved_by: None,
            reason: None,
        });
        Ok((
            StatusCode::CREATED,
            Json(json!({"id": id, "status": "pending"})),
        ))
    } else {
        let token = state
            .token_signer
            .issue(&id, operation, environment, database_name, detail);
        Ok((
            StatusCode::CREATED,
            Json(json!({"id": id, "status": "auto_approved", "execution_token": token})),
        ))
    }
}

async fn approve_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let approver = auth::authenticate(&headers, &state).await?;

    let conn = state.sqlite.lock().await;

    // Fetch request
    let (req_user, status, operation, environment, database_name, detail): (String, String, String, String, String, String) = conn
        .query_row(
            "SELECT created_by, status, operation, environment, database_name, detail FROM requests WHERE id = ?1",
            rusqlite::params![id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "request not found".into()))?;

    if status != "pending" {
        return Err((StatusCode::CONFLICT, format!("request is already {status}")));
    }

    // Requester ≠ approver
    if req_user == approver.user {
        return Err((
            StatusCode::FORBIDDEN,
            "requester cannot approve their own request".into(),
        ));
    }

    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "UPDATE requests SET status = 'approved', updated_at = ?1, resolved_at = ?2 WHERE id = ?3",
        rusqlite::params![now, now, id],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let approval_id = uuid::Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO approvals (id, request_id, action, actor_id, comment, created_at) VALUES (?1, ?2, 'approve', ?3, NULL, ?4)",
        rusqlite::params![approval_id, id, approver.user, now],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let token = state
        .token_signer
        .issue(&id, &operation, &environment, &database_name, &detail);

    state.webhooks.dispatch(crate::webhook::WebhookEvent {
        event: "request_approved".into(),
        request_id: id.clone(),
        user: req_user.clone(),
        operation: operation.clone(),
        environment: environment.clone(),
        detail: detail.clone(),
        approved_by: Some(approver.user.clone()),
        reason: None,
    });

    Ok(Json(
        json!({"id": id, "status": "approved", "approved_by": approver.user, "execution_token": token}),
    ))
}

async fn reject_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;

    let conn = state.sqlite.lock().await;

    let (req_user, status): (String, String) = conn
        .query_row(
            "SELECT created_by, status FROM requests WHERE id = ?1",
            rusqlite::params![id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "request not found".into()))?;

    if status != "pending" {
        return Err((StatusCode::CONFLICT, format!("request is already {status}")));
    }

    // Only admin or the requester can reject
    if user.role != dbward_core::Role::Admin && user.user != req_user {
        return Err((
            StatusCode::FORBIDDEN,
            "only admin or the requester can reject".into(),
        ));
    }

    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "UPDATE requests SET status = 'rejected', updated_at = ?1, resolved_at = ?2 WHERE id = ?3",
        rusqlite::params![now, now, id],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let approval_id = uuid::Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO approvals (id, request_id, action, actor_id, comment, created_at) VALUES (?1, ?2, 'reject', ?3, NULL, ?4)",
        rusqlite::params![approval_id, id, user.user, now],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    state.webhooks.dispatch(crate::webhook::WebhookEvent {
        event: "request_rejected".into(),
        request_id: id.clone(),
        user: user.user.clone(),
        operation: "".into(),
        environment: "".into(),
        detail: "".into(),
        approved_by: None,
        reason: None,
    });

    Ok(Json(json!({"id": id, "status": "rejected"})))
}

async fn get_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let _user = auth::authenticate(&headers, &state).await?;

    let conn = state.sqlite.lock().await;

    let (id_val, created_by, operation, environment, database_name, detail, status, created_at, updated_at, resolved_at): (String, String, String, String, String, String, String, String, String, Option<String>) = conn
        .query_row(
            "SELECT id, created_by, operation, environment, database_name, detail, status, created_at, updated_at, resolved_at FROM requests WHERE id = ?1",
            rusqlite::params![id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?)),
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "request not found".into()))?;

    let mut resp = json!({
        "id": id_val, "created_by": created_by, "operation": operation,
        "environment": environment, "database_name": database_name, "detail": detail, "status": status,
        "created_at": created_at, "updated_at": updated_at, "resolved_at": resolved_at,
    });

    // Only issue token for approved/auto_approved (not executed/failed/rejected)
    if status == "approved" || status == "auto_approved" || status == "break_glass" {
        let token =
            state
                .token_signer
                .issue(&id, &operation, &environment, &database_name, &detail);
        resp["execution_token"] = serde_json::to_value(token)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    Ok(Json(resp))
}

async fn complete_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;

    let conn = state.sqlite.lock().await;

    let (req_user, status): (String, String) = conn
        .query_row(
            "SELECT created_by, status FROM requests WHERE id = ?1",
            rusqlite::params![id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "request not found".into()))?;

    // Only the requester (or admin) can report completion
    if req_user != user.user && user.role != dbward_core::Role::Admin {
        return Err((
            StatusCode::FORBIDDEN,
            "only the requester can report completion".into(),
        ));
    }

    if status != "approved" && status != "auto_approved" {
        return Err((
            StatusCode::CONFLICT,
            format!("request status is {status}, expected approved"),
        ));
    }

    let success = body["success"].as_bool().unwrap_or(false);
    let new_status = if success { "executed" } else { "failed" };
    let now = chrono::Utc::now().to_rfc3339();
    let error_msg = body["error_message"].as_str().map(|s| s.to_string());

    conn.execute(
        "UPDATE requests SET status = ?1, updated_at = ?2, resolved_at = ?3 WHERE id = ?4",
        rusqlite::params![new_status, now, now, id],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Write audit log
    let audit_id = uuid::Uuid::new_v4().to_string();
    let (operation, environment, database_name, detail) = conn
        .query_row(
            "SELECT operation, environment, database_name, detail FROM requests WHERE id = ?1",
            rusqlite::params![id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .unwrap_or_default();

    conn.execute(
        "INSERT INTO audit_log (id, request_id, execution_id, actor_id, operation, environment, database_name, detail, status, result_summary, error_message, created_at) VALUES (?1, ?2, NULL, ?3, ?4, ?5, ?6, ?7, ?8, NULL, ?9, ?10)",
        rusqlite::params![
            audit_id, id, req_user, operation, environment, database_name, detail, new_status, error_msg, now
        ],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    state.webhooks.dispatch(crate::webhook::WebhookEvent {
        event: "request_completed".into(),
        request_id: id.clone(),
        user: req_user.clone(),
        operation: operation.clone(),
        environment: environment.clone(),
        detail: detail.clone(),
        approved_by: None,
        reason: None,
    });

    Ok(Json(json!({"id": id, "status": new_status})))
}

async fn list_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let _user = auth::authenticate(&headers, &state).await?;

    let conn = state.sqlite.lock().await;
    let mut stmt = conn
        .prepare("SELECT id, request_id, execution_id, actor_id, operation, environment, database_name, detail, status, result_summary, error_message, created_at FROM audit_log ORDER BY created_at DESC LIMIT 100")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let rows: Vec<serde_json::Value> = stmt
        .query_map([], |row| {
            Ok(json!({
                "id": row.get::<_, String>(0)?,
                "request_id": row.get::<_, Option<String>>(1)?,
                "execution_id": row.get::<_, Option<String>>(2)?,
                "actor_id": row.get::<_, String>(3)?,
                "operation": row.get::<_, String>(4)?,
                "environment": row.get::<_, String>(5)?,
                "database_name": row.get::<_, String>(6)?,
                "detail": row.get::<_, String>(7)?,
                "status": row.get::<_, String>(8)?,
                "result_summary": row.get::<_, Option<String>>(9)?,
                "error_message": row.get::<_, Option<String>>(10)?,
                "created_at": row.get::<_, String>(11)?,
            }))
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .filter_map(|r| r.ok())
        .collect();

    Ok(Json(json!({"audit_log": rows})))
}

// ---------------------------------------------------------------------------
// On-demand execution: dispatch + result stream
// ---------------------------------------------------------------------------

/// Client dispatches a request for execution. Creates a result channel.
async fn dispatch_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let _user = auth::authenticate(&headers, &state).await?;

    let status: String = {
        let conn = state.sqlite.lock().await;
        conn.query_row(
            "SELECT status FROM requests WHERE id = ?1",
            rusqlite::params![id],
            |row| row.get(0),
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "request not found".into()))?
    };

    match status.as_str() {
        "approved" | "auto_approved" | "break_glass" => {}
        "dispatched" | "running" => {
            return Err((StatusCode::CONFLICT, format!("request already {status}")));
        }
        _ => {
            return Err((
                StatusCode::CONFLICT,
                format!("request status is {status}, cannot dispatch"),
            ));
        }
    }

    let slot = Arc::new(crate::state::ResultSlot {
        result: tokio::sync::Mutex::new(None),
        notify: tokio::sync::Notify::new(),
        created_at: Instant::now(),
    });
    state.result_channels.insert(id.clone(), slot).await;

    let now = chrono::Utc::now().to_rfc3339();
    let update_result = {
        let conn = state.sqlite.lock().await;
        conn.execute(
            "UPDATE requests SET status = 'dispatched', updated_at = ?1 WHERE id = ?2",
            rusqlite::params![now, id],
        )
    };
    if let Err(e) = update_result {
        let _ = state.result_channels.remove(&id).await;
        return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()));
    }

    Ok(Json(json!({"id": id, "status": "dispatched"})))
}

/// Client waits for execution result (long poll).
async fn stream_result(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let _user = auth::authenticate(&headers, &state).await?;

    let slot = match state.result_channels.get(&id).await {
        Some(slot) => slot,
        None => {
            let conn = state.sqlite.lock().await;
            let status: String = conn
                .query_row(
                    "SELECT status FROM requests WHERE id = ?1",
                    rusqlite::params![id],
                    |row| row.get(0),
                )
                .map_err(|_| (StatusCode::NOT_FOUND, "request not found".into()))?;
            let msg = match status.as_str() {
                "executed" | "failed" => {
                    "result relay is no longer available for this request".to_string()
                }
                "approved" | "auto_approved" | "break_glass" => {
                    "request is approved but not dispatched".to_string()
                }
                "dispatched" | "running" => {
                    "result relay state is missing; retry dispatch".to_string()
                }
                _ => format!("request status is {status}"),
            };
            return Err((StatusCode::CONFLICT, msg));
        }
    };

    if let Some(payload) = slot.result.lock().await.clone() {
        let _ = state.result_channels.remove(&id).await;
        return Ok(Json(payload));
    }

    // Wait up to 5 minutes for agent to deliver result
    let wait = tokio::time::timeout(std::time::Duration::from_secs(300), async {
        loop {
            slot.notify.notified().await;
            if slot.result.lock().await.is_some() {
                break;
            }
        }
    })
    .await;
    if wait.is_err() {
        return Err((
            StatusCode::GATEWAY_TIMEOUT,
            "timed out waiting for result".into(),
        ));
    }

    let result = slot.result.lock().await.clone();
    let _ = state.result_channels.remove(&id).await;

    match result {
        Some(payload) => Ok(Json(payload)),
        None => Err((StatusCode::INTERNAL_SERVER_ERROR, "result was empty".into())),
    }
}

// ---------------------------------------------------------------------------
// Agent endpoints
// ---------------------------------------------------------------------------

/// Agent polls for dispatchable jobs (approved / auto_approved / break_glass).
async fn agent_poll(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let _user = auth::authenticate(&headers, &state).await?;

    let databases: Vec<String> = body["databases"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let environments: Vec<String> = body["environments"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let conn = state.sqlite.lock().await;
    let mut stmt = conn
        .prepare(
            "SELECT id, created_by, operation, environment, database_name, detail
             FROM requests
             WHERE status = 'dispatched'
             ORDER BY created_at ASC
             LIMIT 10",
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let rows: Vec<serde_json::Value> = stmt
        .query_map([], |row| {
            Ok(json!({
                "id": row.get::<_, String>(0)?,
                "created_by": row.get::<_, String>(1)?,
                "operation": row.get::<_, String>(2)?,
                "environment": row.get::<_, String>(3)?,
                "database_name": row.get::<_, String>(4)?,
                "detail": row.get::<_, String>(5)?,
            }))
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .filter_map(|r| r.ok())
        .filter(|r| {
            let db = r["database_name"].as_str().unwrap_or("");
            let env = r["environment"].as_str().unwrap_or("");
            (databases.is_empty() || databases.iter().any(|d| d == db))
                && (environments.is_empty() || environments.iter().any(|e| e == env))
        })
        .collect();

    Ok(Json(json!({"jobs": rows})))
}

/// Agent claims a job for execution.
async fn agent_claim(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    let agent_id = body["agent_id"].as_str().unwrap_or(&user.user);

    let conn = state.sqlite.lock().await;

    let (operation, environment, database, detail, status): (String, String, String, String, String) = conn
        .query_row(
            "SELECT operation, environment, database_name, detail, status FROM requests WHERE id = ?1",
            rusqlite::params![id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "request not found".into()))?;

    if status != "dispatched" {
        return Err((
            StatusCode::CONFLICT,
            format!("request status is {status}, cannot claim"),
        ));
    }

    let now = chrono::Utc::now().to_rfc3339();
    let lease_expires = (chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339();
    let exec_id = uuid::Uuid::new_v4().to_string();

    let token = state
        .token_signer
        .issue(&id, &operation, &environment, &database, &detail);
    let token_json = serde_json::to_string(&token)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    conn.execute(
        "INSERT INTO agent_executions (id, request_id, agent_id, status, execution_token_json, lease_expires_at, started_at, created_at)
         VALUES (?1, ?2, ?3, 'claimed', ?4, ?5, ?6, ?6)",
        rusqlite::params![exec_id, id, agent_id, token_json, lease_expires, now],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    conn.execute(
        "UPDATE requests SET status = 'running', updated_at = ?1 WHERE id = ?2",
        rusqlite::params![now, id],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(json!({
        "execution_id": exec_id,
        "request_id": id,
        "operation": operation,
        "environment": environment,
        "database": database,
        "detail": detail,
        "execution_token": token,
    })))
}

/// Agent sends execution result. Server relays to waiting CLI via channel.
async fn agent_result(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let _user = auth::authenticate(&headers, &state).await?;

    let success = body["success"].as_bool().unwrap_or(false);
    let result = body["result"].clone();
    let error_msg = body["error"].as_str().map(|s| s.to_string());

    let conn = state.sqlite.lock().await;
    let now = chrono::Utc::now().to_rfc3339();

    let (request_id, exec_status): (String, String) = conn
        .query_row(
            "SELECT request_id, status FROM agent_executions WHERE id = ?1",
            rusqlite::params![id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "execution not found".into()))?;

    if exec_status != "claimed" {
        return Err((
            StatusCode::CONFLICT,
            format!("execution status is {exec_status}"),
        ));
    }

    let new_status = if success { "completed" } else { "failed" };
    conn.execute(
        "UPDATE agent_executions SET status = ?1, finished_at = ?2, error_message = ?3 WHERE id = ?4",
        rusqlite::params![new_status, now, error_msg, id],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let req_status = if success { "executed" } else { "failed" };
    conn.execute(
        "UPDATE requests SET status = ?1, updated_at = ?2, resolved_at = ?2 WHERE id = ?3",
        rusqlite::params![req_status, now, request_id],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Write audit log
    let audit_id = uuid::Uuid::new_v4().to_string();
    let (operation, environment, database_name, detail, actor) = conn
        .query_row(
            "SELECT operation, environment, database_name, detail, created_by FROM requests WHERE id = ?1",
            rusqlite::params![request_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, String>(4)?)),
        )
        .unwrap_or_default();

    conn.execute(
        "INSERT INTO audit_log (id, request_id, execution_id, actor_id, operation, environment, database_name, detail, status, result_summary, error_message, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, ?10, ?11)",
        rusqlite::params![audit_id, request_id, id, actor, operation, environment, database_name, detail, req_status, error_msg, now],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Drop the SQLite lock before touching the channel
    drop(conn);

    // Relay result to waiting CLI
    let payload = json!({
        "success": success,
        "result": result,
        "error": error_msg,
        "request_id": request_id,
    });

    if let Some(slot) = state.result_channels.get(&request_id).await {
        let mut r = slot.result.lock().await;
        *r = Some(payload);
        slot.notify.notify_waiters();
    }

    Ok(Json(
        json!({"status": req_status, "request_id": request_id}),
    ))
}
