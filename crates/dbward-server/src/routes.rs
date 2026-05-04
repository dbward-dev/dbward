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

fn require_admin_role(user: &crate::state::AuthUser) -> Result<(), (StatusCode, String)> {
    if user.role == dbward_core::Role::Admin {
        Ok(())
    } else {
        Err((StatusCode::FORBIDDEN, "admin only".into()))
    }
}

fn can_access_result(
    user: &crate::state::AuthUser,
    requester: &str,
    access_roles: &[String],
) -> bool {
    access_roles.iter().any(|role| {
        (role == "requester" && user.user == requester) || role == &user.role.to_string()
    })
}

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
        .route(
            "/api/workflows",
            get(list_workflows).post(create_workflow),
        )
        .route(
            "/api/workflows/{id}",
            get(get_workflow)
                .put(update_workflow)
                .delete(delete_workflow),
        )
        .route(
            "/api/execution-policies",
            get(list_execution_policies).post(create_execution_policy),
        )
        .route(
            "/api/execution-policies/{id}",
            get(get_execution_policy_handler)
                .put(update_execution_policy)
                .delete(delete_execution_policy),
        )
        .route(
            "/api/result-policies",
            get(list_result_policies).post(create_result_policy),
        )
        .route(
            "/api/result-policies/{id}",
            get(get_result_policy_handler)
                .put(update_result_policy)
                .delete(delete_result_policy),
        )
        .route(
            "/api/notification-policies",
            get(list_notification_policies).post(create_notification_policy),
        )
        .route(
            "/api/notification-policies/{id}",
            get(get_notification_policy)
                .put(update_notification_policy)
                .delete(delete_notification_policy),
        )
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
    let user = auth::authenticate(&headers, &state).await?;

    let conn = state.sqlite.lock().await;
    let rows: Vec<serde_json::Value> = if user.role == dbward_core::Role::Admin {
        let mut stmt = conn
            .prepare("SELECT id, created_by, operation, environment, database_name, detail, status, emergency, created_at, updated_at, resolved_at FROM requests ORDER BY created_at DESC")
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        stmt.query_map([], |row| {
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
        .collect()
    } else {
        let mut stmt = conn
            .prepare("SELECT id, created_by, operation, environment, database_name, detail, status, emergency, created_at, updated_at, resolved_at FROM requests WHERE created_by = ?1 ORDER BY created_at DESC")
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        stmt.query_map(rusqlite::params![user.user], |row| {
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
        .collect()
    };

    Ok(Json(json!({"requests": rows})))
}

async fn create_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    auth::require_human(&user)?;

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

    // Workflow evaluation: check workflows table first, then fall back to static policy
    let conn = state.sqlite.lock().await;
    let policy_action = crate::db::evaluate_workflow(&conn, database_name, environment, operation)
        .unwrap_or_else(|| {
            state
                .policy
                .evaluate(environment, operation, &user.role.to_string())
                .to_string()
        });
    let needs_approval = !emergency && policy_action == "require_approval";

    let status = if emergency {
        "break_glass"
    } else if needs_approval {
        "pending"
    } else {
        "auto_approved"
    };

    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

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
            database: database_name.into(),
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
            database: database_name.into(),
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
    auth::require_human(&approver)?;
    require_admin_role(&approver)?;

    let mut conn = state.sqlite.lock().await;

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
    let tx = conn.transaction().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tx.execute(
        "UPDATE requests SET status = 'approved', updated_at = ?1, resolved_at = ?2 WHERE id = ?3",
        rusqlite::params![now, now, id],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let approval_id = uuid::Uuid::new_v4().to_string();
    tx.execute(
        "INSERT INTO approvals (id, request_id, action, actor_id, comment, created_at) VALUES (?1, ?2, 'approve', ?3, NULL, ?4)",
        rusqlite::params![approval_id, id, approver.user, now],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tx.commit().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

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
            database: database_name.clone(),
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
    auth::require_human(&user)?;

    let mut conn = state.sqlite.lock().await;

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
    let tx = conn.transaction().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tx.execute(
        "UPDATE requests SET status = 'rejected', updated_at = ?1, resolved_at = ?2 WHERE id = ?3",
        rusqlite::params![now, now, id],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let approval_id = uuid::Uuid::new_v4().to_string();
    tx.execute(
        "INSERT INTO approvals (id, request_id, action, actor_id, comment, created_at) VALUES (?1, ?2, 'reject', ?3, NULL, ?4)",
        rusqlite::params![approval_id, id, user.user, now],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tx.commit().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    state.webhooks.dispatch(crate::webhook::WebhookEvent {
        event: "request_rejected".into(),
        request_id: id.clone(),
        user: user.user.clone(),
        operation: "".into(),
        environment: "".into(),
        database: "".into(),
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
    let user = auth::authenticate(&headers, &state).await?;

    let conn = state.sqlite.lock().await;

    let (id_val, created_by, operation, environment, database_name, detail, status, created_at, updated_at, resolved_at): (String, String, String, String, String, String, String, String, String, Option<String>) = conn
        .query_row(
            "SELECT id, created_by, operation, environment, database_name, detail, status, created_at, updated_at, resolved_at FROM requests WHERE id = ?1",
            rusqlite::params![id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?)),
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "request not found".into()))?;

    if user.role != dbward_core::Role::Admin && user.user != created_by {
        return Err((StatusCode::FORBIDDEN, "request access denied".into()));
    }

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

async fn list_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    require_admin_role(&user)?;

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
    let user = auth::authenticate(&headers, &state).await?;
    auth::require_human(&user)?;

    let (requester, status, database_name, environment, resolved_at): (
        String,
        String,
        String,
        String,
        Option<String>,
    ) = {
        let conn = state.sqlite.lock().await;
        conn.query_row(
            "SELECT created_by, status, database_name, environment, resolved_at FROM requests WHERE id = ?1",
            rusqlite::params![id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "request not found".into()))?
    };

    if user.user != requester && user.role != dbward_core::Role::Admin {
        return Err((
            StatusCode::FORBIDDEN,
            "only the requester can dispatch this request".into(),
        ));
    }

    match status.as_str() {
        "approved" | "auto_approved" | "break_glass" => {}
        "dispatched" | "running" => {
            return Err((StatusCode::CONFLICT, format!("request already {status}")));
        }
        "executed" | "failed" => {
            // Check execution policy for re-execution
            let conn = state.sqlite.lock().await;
            let (max_exec, window_secs, retry) = crate::db::get_execution_policy(&conn, &database_name, &environment);

            // Check execution window
            if let Some(ref resolved) = resolved_at {
                if let Ok(resolved_time) = chrono::DateTime::parse_from_rfc3339(resolved) {
                    let elapsed = chrono::Utc::now().signed_duration_since(resolved_time);
                    if elapsed.num_seconds() as u64 > window_secs {
                        return Err((StatusCode::GONE, "execution window expired".into()));
                    }
                }
            }

            // Check execution count
            let exec_count: u32 = conn
                .query_row(
                    "SELECT COUNT(*) FROM agent_executions WHERE request_id = ?1",
                    rusqlite::params![id],
                    |row| row.get(0),
                )
                .unwrap_or(0);
            if status == "failed" && !retry {
                return Err((StatusCode::CONFLICT, "retry on failure is disabled".into()));
            }
            if exec_count >= max_exec {
                return Err((StatusCode::CONFLICT, format!("max executions ({max_exec}) reached")));
            }
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
    let user = auth::authenticate(&headers, &state).await?;
    auth::require_human(&user)?;

    let (requester, database_name, environment, status): (String, String, String, String) = {
        let conn = state.sqlite.lock().await;
        conn.query_row(
            "SELECT created_by, database_name, environment, status FROM requests WHERE id = ?1",
            rusqlite::params![id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "request not found".into()))?
    };

    let access_roles = {
        let conn = state.sqlite.lock().await;
        let (_, access_roles) = crate::db::get_result_policy(&conn, &database_name, &environment);
        access_roles
    };

    if !can_access_result(&user, &requester, &access_roles) {
        return Err((StatusCode::FORBIDDEN, "result access denied".into()));
    }

    let slot = match state.result_channels.get(&id).await {
        Some(slot) => slot,
        None => {
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
    let user = auth::authenticate(&headers, &state).await?;
    auth::require_agent(&user)?;
    require_admin_role(&user)?;

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
    let operations: Vec<String> = body["operations"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let conn = state.sqlite.lock().await;

    // Record agent capabilities for claim-time verification
    let now = chrono::Utc::now().to_rfc3339();
    let caps_json = serde_json::to_string(&json!({
        "databases": databases,
        "environments": environments,
        "operations": operations,
    })).unwrap_or_else(|_| "{}".into());
    conn.execute(
        "INSERT INTO agents (id, token_id, capabilities_json, last_seen_at, created_at)
         VALUES (?1, ?2, ?3, ?4, ?4)
         ON CONFLICT(id) DO UPDATE SET capabilities_json = ?3, last_seen_at = ?4",
        rusqlite::params![user.user, user.token_id, caps_json, now],
    ).ok();

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
    Json(_body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    auth::require_agent(&user)?;
    require_admin_role(&user)?;
    let agent_id = user.user.clone();

    let mut conn = state.sqlite.lock().await;

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

    // Verify agent has capability for this job
    if let Ok(caps_json) = conn.query_row(
        "SELECT capabilities_json FROM agents WHERE id = ?1",
        rusqlite::params![agent_id],
        |row| row.get::<_, String>(0),
    ) {
        if let Ok(caps) = serde_json::from_str::<serde_json::Value>(&caps_json) {
            let matches = |arr: &serde_json::Value, val: &str| -> bool {
                arr.as_array().map_or(true, |a| a.is_empty() || a.iter().any(|v| v.as_str() == Some(val) || v.as_str() == Some("*")))
            };
            if !matches(&caps["databases"], &database)
                || !matches(&caps["environments"], &environment)
                || !matches(&caps["operations"], &operation)
            {
                return Err((StatusCode::FORBIDDEN, "agent lacks capability for this job".into()));
            }
        }
    }

    let now = chrono::Utc::now().to_rfc3339();
    let lease_expires = (chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339();
    let exec_id = uuid::Uuid::new_v4().to_string();

    let token = state
        .token_signer
        .issue(&id, &operation, &environment, &database, &detail);
    let token_json = serde_json::to_string(&token)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let tx = conn.transaction().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tx.execute(
        "INSERT INTO agent_executions (id, request_id, agent_id, status, execution_token_json, lease_expires_at, started_at, created_at)
         VALUES (?1, ?2, ?3, 'claimed', ?4, ?5, ?6, ?6)",
        rusqlite::params![exec_id, id, agent_id, token_json, lease_expires, now],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    tx.execute(
        "UPDATE requests SET status = 'running', updated_at = ?1 WHERE id = ?2",
        rusqlite::params![now, id],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tx.commit().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

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
    let user = auth::authenticate(&headers, &state).await?;
    auth::require_agent(&user)?;
    require_admin_role(&user)?;

    let success = body["success"].as_bool().unwrap_or(false);
    let result = body["result"].clone();
    let error_msg = body["error"].as_str().map(|s| s.to_string());

    let (request_id, req_status) = {
        let mut conn = state.sqlite.lock().await;
        let now = chrono::Utc::now().to_rfc3339();

        let (request_id, exec_status, agent_id): (String, String, String) = conn
            .query_row(
                "SELECT request_id, status, agent_id FROM agent_executions WHERE id = ?1",
                rusqlite::params![id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|_| (StatusCode::NOT_FOUND, "execution not found".into()))?;

        if exec_status != "claimed" {
            return Err((
                StatusCode::CONFLICT,
                format!("execution status is {exec_status}"),
            ));
        }

        if user.user != agent_id {
            return Err((
                StatusCode::FORBIDDEN,
                "only the claiming agent can submit this result".into(),
            ));
        }

        let new_status = if success { "completed" } else { "failed" };
        let req_status = if success { "executed" } else { "failed" };

        let (operation, environment, database_name, detail, actor) = conn
            .query_row(
                "SELECT operation, environment, database_name, detail, created_by FROM requests WHERE id = ?1",
                rusqlite::params![request_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, String>(4)?)),
            )
            .unwrap_or_default();

        let audit_id = uuid::Uuid::new_v4().to_string();
        let tx = conn.transaction().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        tx.execute(
            "UPDATE agent_executions SET status = ?1, finished_at = ?2, error_message = ?3 WHERE id = ?4",
            rusqlite::params![new_status, now, error_msg, id],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        tx.execute(
            "UPDATE requests SET status = ?1, updated_at = ?2, resolved_at = ?2 WHERE id = ?3",
            rusqlite::params![req_status, now, request_id],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        tx.execute(
            "INSERT INTO audit_log (id, request_id, execution_id, actor_id, operation, environment, database_name, detail, status, result_summary, error_message, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, ?10, ?11)",
            rusqlite::params![audit_id, request_id, id, actor, operation, environment, database_name, detail, req_status, error_msg, now],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        tx.commit().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        (request_id, req_status.to_string())
    };

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

// ---------------------------------------------------------------------------
// Workflow CRUD (admin only)
// ---------------------------------------------------------------------------

async fn list_workflows(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    require_admin_role(&user)?;

    let conn = state.sqlite.lock().await;
    let mut stmt = conn
        .prepare("SELECT id, database_name, environment, operations_json, steps_json, source, created_at, updated_at FROM workflows ORDER BY database_name, environment")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let rows: Vec<serde_json::Value> = stmt
        .query_map([], |row| {
            let ops: serde_json::Value = serde_json::from_str(row.get::<_, String>(3)?.as_str()).unwrap_or_default();
            let steps: serde_json::Value = serde_json::from_str(row.get::<_, String>(4)?.as_str()).unwrap_or_default();
            Ok(json!({
                "id": row.get::<_, String>(0)?,
                "database": row.get::<_, String>(1)?,
                "environment": row.get::<_, String>(2)?,
                "operations": ops,
                "steps": steps,
                "source": row.get::<_, String>(5)?,
                "created_at": row.get::<_, String>(6)?,
                "updated_at": row.get::<_, String>(7)?,
            }))
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .filter_map(|r| r.ok())
        .collect();

    Ok(Json(json!({"workflows": rows})))
}

async fn get_workflow(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    require_admin_role(&user)?;

    let conn = state.sqlite.lock().await;
    let row = conn
        .query_row(
            "SELECT id, database_name, environment, operations_json, steps_json, source, created_at, updated_at FROM workflows WHERE id = ?1",
            rusqlite::params![id],
            |row| {
                let ops: serde_json::Value = serde_json::from_str(row.get::<_, String>(3)?.as_str()).unwrap_or_default();
                let steps: serde_json::Value = serde_json::from_str(row.get::<_, String>(4)?.as_str()).unwrap_or_default();
                Ok(json!({
                    "id": row.get::<_, String>(0)?,
                    "database": row.get::<_, String>(1)?,
                    "environment": row.get::<_, String>(2)?,
                    "operations": ops,
                    "steps": steps,
                    "source": row.get::<_, String>(5)?,
                    "created_at": row.get::<_, String>(6)?,
                    "updated_at": row.get::<_, String>(7)?,
                }))
            },
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "workflow not found".into()))?;

    Ok(Json(row))
}

async fn create_workflow(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    auth::require_human(&user)?;
    require_admin_role(&user)?;

    let database = body["database"].as_str()
        .ok_or((StatusCode::BAD_REQUEST, "database required".into()))?;
    let environment = body["environment"].as_str()
        .ok_or((StatusCode::BAD_REQUEST, "environment required".into()))?;
    let operations = body.get("operations").cloned().unwrap_or(json!([]));
    let steps = body.get("steps").cloned().unwrap_or(json!([]));

    let id = format!("{database}:{environment}");
    let ops_json = operations.to_string();
    let steps_json = steps.to_string();
    let now = chrono::Utc::now().to_rfc3339();

    let conn = state.sqlite.lock().await;
    conn.execute(
        "INSERT INTO workflows (id, database_name, environment, operations_json, steps_json, source, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, 'api', ?6, ?6)",
        rusqlite::params![id, database, environment, ops_json, steps_json, now],
    )
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            (StatusCode::CONFLICT, format!("workflow for {database}:{environment} already exists"))
        } else {
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        }
    })?;

    Ok((StatusCode::CREATED, Json(json!({"id": id, "database": database, "environment": environment}))))
}

async fn update_workflow(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    auth::require_human(&user)?;
    require_admin_role(&user)?;

    let conn = state.sqlite.lock().await;
    let now = chrono::Utc::now().to_rfc3339();

    // Check exists
    conn.query_row("SELECT id FROM workflows WHERE id = ?1", rusqlite::params![id], |_| Ok(()))
        .map_err(|_| (StatusCode::NOT_FOUND, "workflow not found".into()))?;

    if let Some(steps) = body.get("steps") {
        conn.execute(
            "UPDATE workflows SET steps_json = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
            rusqlite::params![steps.to_string(), now, id],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    if let Some(ops) = body.get("operations") {
        conn.execute(
            "UPDATE workflows SET operations_json = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
            rusqlite::params![ops.to_string(), now, id],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    Ok(Json(json!({"id": id, "updated": true})))
}

async fn delete_workflow(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    auth::require_human(&user)?;
    require_admin_role(&user)?;

    let conn = state.sqlite.lock().await;
    let changes = conn
        .execute("DELETE FROM workflows WHERE id = ?1", rusqlite::params![id])
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if changes == 0 {
        return Err((StatusCode::NOT_FOUND, "workflow not found".into()));
    }

    Ok(Json(json!({"id": id, "deleted": true})))
}

// ---------------------------------------------------------------------------
// Execution Policy CRUD (admin only for mutations)
// ---------------------------------------------------------------------------

async fn list_execution_policies(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    require_admin_role(&user)?;

    let conn = state.sqlite.lock().await;
    let mut stmt = conn
        .prepare("SELECT id, database_name, environment, max_executions, execution_window_secs, retry_on_failure, source, created_at, updated_at FROM execution_policies ORDER BY database_name, environment")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let rows: Vec<serde_json::Value> = stmt
        .query_map([], |row| {
            Ok(json!({
                "id": row.get::<_, String>(0)?,
                "database": row.get::<_, String>(1)?,
                "environment": row.get::<_, String>(2)?,
                "max_executions": row.get::<_, i64>(3)?,
                "execution_window_secs": row.get::<_, i64>(4)?,
                "retry_on_failure": row.get::<_, bool>(5)?,
                "source": row.get::<_, String>(6)?,
                "created_at": row.get::<_, String>(7)?,
                "updated_at": row.get::<_, String>(8)?,
            }))
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .filter_map(|r| r.ok())
        .collect();

    Ok(Json(json!({"execution_policies": rows})))
}

async fn get_execution_policy_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    require_admin_role(&user)?;

    let conn = state.sqlite.lock().await;
    let row = conn
        .query_row(
            "SELECT id, database_name, environment, max_executions, execution_window_secs, retry_on_failure, source, created_at, updated_at FROM execution_policies WHERE id = ?1",
            rusqlite::params![id],
            |row| {
                Ok(json!({
                    "id": row.get::<_, String>(0)?,
                    "database": row.get::<_, String>(1)?,
                    "environment": row.get::<_, String>(2)?,
                    "max_executions": row.get::<_, i64>(3)?,
                    "execution_window_secs": row.get::<_, i64>(4)?,
                    "retry_on_failure": row.get::<_, bool>(5)?,
                    "source": row.get::<_, String>(6)?,
                    "created_at": row.get::<_, String>(7)?,
                    "updated_at": row.get::<_, String>(8)?,
                }))
            },
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "execution policy not found".into()))?;

    Ok(Json(row))
}

async fn create_execution_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    auth::require_human(&user)?;
    require_admin_role(&user)?;

    let database = body["database"].as_str()
        .ok_or((StatusCode::BAD_REQUEST, "database required".into()))?;
    let environment = body["environment"].as_str()
        .ok_or((StatusCode::BAD_REQUEST, "environment required".into()))?;
    let max_executions = body["max_executions"].as_i64().unwrap_or(1);
    let execution_window_secs = body["execution_window_secs"].as_i64().unwrap_or(3600);
    let retry_on_failure = body["retry_on_failure"].as_bool().unwrap_or(false);

    let id = format!("{database}:{environment}");
    let now = chrono::Utc::now().to_rfc3339();

    let conn = state.sqlite.lock().await;
    conn.execute(
        "INSERT INTO execution_policies (id, database_name, environment, max_executions, execution_window_secs, retry_on_failure, source, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'api', ?7, ?7)",
        rusqlite::params![id, database, environment, max_executions, execution_window_secs, retry_on_failure, now],
    )
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            (StatusCode::CONFLICT, format!("execution policy for {database}:{environment} already exists"))
        } else {
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        }
    })?;

    Ok((StatusCode::CREATED, Json(json!({"id": id, "database": database, "environment": environment}))))
}

async fn update_execution_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    auth::require_human(&user)?;
    require_admin_role(&user)?;

    let conn = state.sqlite.lock().await;
    let now = chrono::Utc::now().to_rfc3339();

    conn.query_row("SELECT id FROM execution_policies WHERE id = ?1", rusqlite::params![id], |_| Ok(()))
        .map_err(|_| (StatusCode::NOT_FOUND, "execution policy not found".into()))?;

    if let Some(v) = body.get("max_executions").and_then(|v| v.as_i64()) {
        conn.execute(
            "UPDATE execution_policies SET max_executions = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
            rusqlite::params![v, now, id],
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    if let Some(v) = body.get("execution_window_secs").and_then(|v| v.as_i64()) {
        conn.execute(
            "UPDATE execution_policies SET execution_window_secs = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
            rusqlite::params![v, now, id],
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    if let Some(v) = body.get("retry_on_failure").and_then(|v| v.as_bool()) {
        conn.execute(
            "UPDATE execution_policies SET retry_on_failure = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
            rusqlite::params![v, now, id],
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    Ok(Json(json!({"id": id, "updated": true})))
}

async fn delete_execution_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    auth::require_human(&user)?;
    require_admin_role(&user)?;

    let conn = state.sqlite.lock().await;
    let changes = conn
        .execute("DELETE FROM execution_policies WHERE id = ?1", rusqlite::params![id])
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if changes == 0 {
        return Err((StatusCode::NOT_FOUND, "execution policy not found".into()));
    }

    Ok(Json(json!({"id": id, "deleted": true})))
}

// ---------------------------------------------------------------------------
// Result Policy CRUD (admin only for mutations)
// ---------------------------------------------------------------------------

async fn list_result_policies(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    require_admin_role(&user)?;

    let conn = state.sqlite.lock().await;
    let mut stmt = conn
        .prepare("SELECT id, database_name, environment, delivery_mode, storage_config_json, access_json, source, created_at, updated_at FROM result_policies ORDER BY database_name, environment")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let rows: Vec<serde_json::Value> = stmt
        .query_map([], |row| {
            let storage: serde_json::Value = serde_json::from_str(row.get::<_, String>(4)?.as_str()).unwrap_or_default();
            let access: serde_json::Value = serde_json::from_str(row.get::<_, String>(5)?.as_str()).unwrap_or_default();
            Ok(json!({
                "id": row.get::<_, String>(0)?,
                "database": row.get::<_, String>(1)?,
                "environment": row.get::<_, String>(2)?,
                "delivery_mode": row.get::<_, String>(3)?,
                "storage_config": storage,
                "access": access,
                "source": row.get::<_, String>(6)?,
                "created_at": row.get::<_, String>(7)?,
                "updated_at": row.get::<_, String>(8)?,
            }))
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .filter_map(|r| r.ok())
        .collect();

    Ok(Json(json!({"result_policies": rows})))
}

async fn get_result_policy_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    require_admin_role(&user)?;

    let conn = state.sqlite.lock().await;
    let row = conn
        .query_row(
            "SELECT id, database_name, environment, delivery_mode, storage_config_json, access_json, source, created_at, updated_at FROM result_policies WHERE id = ?1",
            rusqlite::params![id],
            |row| {
                let storage: serde_json::Value = serde_json::from_str(row.get::<_, String>(4)?.as_str()).unwrap_or_default();
                let access: serde_json::Value = serde_json::from_str(row.get::<_, String>(5)?.as_str()).unwrap_or_default();
                Ok(json!({
                    "id": row.get::<_, String>(0)?,
                    "database": row.get::<_, String>(1)?,
                    "environment": row.get::<_, String>(2)?,
                    "delivery_mode": row.get::<_, String>(3)?,
                    "storage_config": storage,
                    "access": access,
                    "source": row.get::<_, String>(6)?,
                    "created_at": row.get::<_, String>(7)?,
                    "updated_at": row.get::<_, String>(8)?,
                }))
            },
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "result policy not found".into()))?;

    Ok(Json(row))
}

async fn create_result_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    auth::require_human(&user)?;
    require_admin_role(&user)?;

    let database = body["database"].as_str()
        .ok_or((StatusCode::BAD_REQUEST, "database required".into()))?;
    let environment = body["environment"].as_str()
        .ok_or((StatusCode::BAD_REQUEST, "environment required".into()))?;
    let delivery_mode = body["delivery_mode"].as_str().unwrap_or("stream");
    let storage_config = body.get("storage_config").cloned().unwrap_or(json!({}));
    let access = body.get("access").cloned().unwrap_or(json!({}));

    let id = format!("{database}:{environment}");
    let storage_json = storage_config.to_string();
    let access_json = access.to_string();
    let now = chrono::Utc::now().to_rfc3339();

    let conn = state.sqlite.lock().await;
    conn.execute(
        "INSERT INTO result_policies (id, database_name, environment, delivery_mode, storage_config_json, access_json, source, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'api', ?7, ?7)",
        rusqlite::params![id, database, environment, delivery_mode, storage_json, access_json, now],
    )
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            (StatusCode::CONFLICT, format!("result policy for {database}:{environment} already exists"))
        } else {
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        }
    })?;

    Ok((StatusCode::CREATED, Json(json!({"id": id, "database": database, "environment": environment}))))
}

async fn update_result_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    auth::require_human(&user)?;
    require_admin_role(&user)?;

    let conn = state.sqlite.lock().await;
    let now = chrono::Utc::now().to_rfc3339();

    conn.query_row("SELECT id FROM result_policies WHERE id = ?1", rusqlite::params![id], |_| Ok(()))
        .map_err(|_| (StatusCode::NOT_FOUND, "result policy not found".into()))?;

    if let Some(v) = body.get("delivery_mode").and_then(|v| v.as_str()) {
        conn.execute(
            "UPDATE result_policies SET delivery_mode = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
            rusqlite::params![v, now, id],
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    if let Some(v) = body.get("storage_config") {
        conn.execute(
            "UPDATE result_policies SET storage_config_json = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
            rusqlite::params![v.to_string(), now, id],
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    if let Some(v) = body.get("access") {
        conn.execute(
            "UPDATE result_policies SET access_json = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
            rusqlite::params![v.to_string(), now, id],
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    Ok(Json(json!({"id": id, "updated": true})))
}

async fn delete_result_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    auth::require_human(&user)?;
    require_admin_role(&user)?;

    let conn = state.sqlite.lock().await;
    let changes = conn
        .execute("DELETE FROM result_policies WHERE id = ?1", rusqlite::params![id])
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if changes == 0 {
        return Err((StatusCode::NOT_FOUND, "result policy not found".into()));
    }

    Ok(Json(json!({"id": id, "deleted": true})))
}

// ---------------------------------------------------------------------------
// Notification Policy CRUD (admin only for mutations)
// ---------------------------------------------------------------------------

async fn list_notification_policies(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    require_admin_role(&user)?;

    let conn = state.sqlite.lock().await;
    let mut stmt = conn
        .prepare("SELECT id, database_name, environment, webhooks_json, source, created_at, updated_at FROM notification_policies ORDER BY database_name, environment")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let rows: Vec<serde_json::Value> = stmt
        .query_map([], |row| {
            let webhooks: serde_json::Value = serde_json::from_str(row.get::<_, String>(3)?.as_str()).unwrap_or_default();
            Ok(json!({
                "id": row.get::<_, String>(0)?,
                "database": row.get::<_, String>(1)?,
                "environment": row.get::<_, String>(2)?,
                "webhooks": webhooks,
                "source": row.get::<_, String>(4)?,
                "created_at": row.get::<_, String>(5)?,
                "updated_at": row.get::<_, String>(6)?,
            }))
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .filter_map(|r| r.ok())
        .collect();

    Ok(Json(json!({"notification_policies": rows})))
}

async fn get_notification_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    require_admin_role(&user)?;

    let conn = state.sqlite.lock().await;
    let row = conn
        .query_row(
            "SELECT id, database_name, environment, webhooks_json, source, created_at, updated_at FROM notification_policies WHERE id = ?1",
            rusqlite::params![id],
            |row| {
                let webhooks: serde_json::Value = serde_json::from_str(row.get::<_, String>(3)?.as_str()).unwrap_or_default();
                Ok(json!({
                    "id": row.get::<_, String>(0)?,
                    "database": row.get::<_, String>(1)?,
                    "environment": row.get::<_, String>(2)?,
                    "webhooks": webhooks,
                    "source": row.get::<_, String>(4)?,
                    "created_at": row.get::<_, String>(5)?,
                    "updated_at": row.get::<_, String>(6)?,
                }))
            },
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "notification policy not found".into()))?;

    Ok(Json(row))
}

async fn create_notification_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    auth::require_human(&user)?;
    require_admin_role(&user)?;

    let database = body["database"].as_str()
        .ok_or((StatusCode::BAD_REQUEST, "database required".into()))?;
    let environment = body["environment"].as_str()
        .ok_or((StatusCode::BAD_REQUEST, "environment required".into()))?;
    let webhooks = body.get("webhooks").cloned().unwrap_or(json!([]));

    let id = format!("{database}:{environment}");
    let webhooks_json = webhooks.to_string();
    let now = chrono::Utc::now().to_rfc3339();

    let conn = state.sqlite.lock().await;
    conn.execute(
        "INSERT INTO notification_policies (id, database_name, environment, webhooks_json, source, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, 'api', ?5, ?5)",
        rusqlite::params![id, database, environment, webhooks_json, now],
    )
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            (StatusCode::CONFLICT, format!("notification policy for {database}:{environment} already exists"))
        } else {
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        }
    })?;

    Ok((StatusCode::CREATED, Json(json!({"id": id, "database": database, "environment": environment}))))
}

async fn update_notification_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    auth::require_human(&user)?;
    require_admin_role(&user)?;

    let conn = state.sqlite.lock().await;
    let now = chrono::Utc::now().to_rfc3339();

    conn.query_row("SELECT id FROM notification_policies WHERE id = ?1", rusqlite::params![id], |_| Ok(()))
        .map_err(|_| (StatusCode::NOT_FOUND, "notification policy not found".into()))?;

    if let Some(v) = body.get("webhooks") {
        conn.execute(
            "UPDATE notification_policies SET webhooks_json = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
            rusqlite::params![v.to_string(), now, id],
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    Ok(Json(json!({"id": id, "updated": true})))
}

async fn delete_notification_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    auth::require_human(&user)?;
    require_admin_role(&user)?;

    let conn = state.sqlite.lock().await;
    let changes = conn
        .execute("DELETE FROM notification_policies WHERE id = ?1", rusqlite::params![id])
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if changes == 0 {
        return Err((StatusCode::NOT_FOUND, "notification policy not found".into()));
    }

    Ok(Json(json!({"id": id, "deleted": true})))
}