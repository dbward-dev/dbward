use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use crate::auth;
use crate::authz::{self, Action, Resource};
use crate::state::AppState;

fn insert_policy_audit(
    conn: &rusqlite::Connection,
    user: &str,
    op_type: &str,
    policy_type: &str,
    id: &str,
) -> Result<(), (StatusCode, String)> {
    let (db, env) = id.split_once(':').unwrap_or((id, ""));
    let audit_id = uuid::Uuid::new_v4().to_string();
    let detail_json = serde_json::json!({"type": policy_type, "id": id}).to_string();
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO audit_log (id, request_id, actor_id, operation, environment, database_name, detail, status, created_at) VALUES (?1, NULL, ?2, ?3, ?4, ?5, ?6, 'policy_change', ?7)",
        rusqlite::params![audit_id, user, op_type, env, db, detail_json, now],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(())
}

fn compute_next_step(steps: &[serde_json::Value], current_step_index: usize) -> Option<serde_json::Value> {
    steps.get(current_step_index).map(|step| {
        json!({
            "index": current_step_index,
            "approvers": step["approvers"]
        })
    })
}

fn request_resource(
    requester_id: String,
    status: String,
    database: String,
    environment: String,
) -> Resource {
    Resource::Request {
        requester_id,
        status,
        database,
        environment,
    }
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

fn parse_pagination(params: &HashMap<String, String>) -> (i64, i64) {
    let limit = params
        .get("limit")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(50)
        .clamp(1, 200);
    let offset = params
        .get("offset")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(0)
        .max(0);
    (limit, offset)
}

async fn list_requests(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::ListRequests, Resource::Global).await?;
    let (limit, offset) = parse_pagination(&params);
    let status_filter = params.get("status").filter(|s| !s.is_empty());
    let database_filter = params.get("database").filter(|s| !s.is_empty());
    let environment_filter = params.get("environment").filter(|s| !s.is_empty());
    let pending_for_me = params.get("pending_for_me").map(|v| v == "true").unwrap_or(false);

    let conn = state.sqlite.lock().await;

    if pending_for_me {
        return list_requests_pending_for_me(&conn, &user, limit, offset);
    }

    let mut where_clauses: Vec<String> = Vec::new();
    let mut bind_values: Vec<String> = Vec::new();
    if let Some(s) = status_filter {
        bind_values.push(s.clone());
        where_clauses.push(format!("status = ?{}", bind_values.len()));
    }
    if let Some(d) = database_filter {
        bind_values.push(d.clone());
        where_clauses.push(format!("database_name = ?{}", bind_values.len()));
    }
    if let Some(e) = environment_filter {
        bind_values.push(e.clone());
        where_clauses.push(format!("environment = ?{}", bind_values.len()));
    }

    let where_sql = if where_clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", where_clauses.join(" AND "))
    };

    let query_sql = format!(
        "SELECT id, created_by, operation, environment, database_name, detail, status, emergency, created_at, updated_at, resolved_at FROM requests {where_sql} ORDER BY created_at DESC",
    );
    let mut stmt = conn
        .prepare(&query_sql)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let candidates: Vec<serde_json::Value> = stmt
        .query_map(rusqlite::params_from_iter(&bind_values), |row| {
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
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut filtered = Vec::new();
    for row in candidates {
        let resource = request_resource(
            row["created_by"].as_str().unwrap_or("").to_string(),
            row["status"].as_str().unwrap_or("").to_string(),
            row["database_name"].as_str().unwrap_or("").to_string(),
            row["environment"].as_str().unwrap_or("").to_string(),
        );
        if authz::authorize_sync(&user, Action::ListRequests, resource).is_ok() {
            filtered.push(row);
        }
    }

    let total = filtered.len() as i64;
    let start = (offset as usize).min(filtered.len());
    let end = (start + limit as usize).min(filtered.len());
    let page = filtered[start..end].to_vec();

    Ok(Json(json!({"requests": page, "total": total, "limit": limit, "offset": offset})))
}

fn list_requests_pending_for_me(
    conn: &rusqlite::Connection,
    user: &crate::state::AuthUser,
    limit: i64,
    offset: i64,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Fetch all pending requests with workflow snapshots
    let mut stmt = conn
        .prepare(
            "SELECT id, created_by, operation, environment, database_name, detail, status, emergency, created_at, updated_at, resolved_at, workflow_snapshot_json FROM requests WHERE status = 'pending' ORDER BY created_at DESC",
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let candidates: Vec<(serde_json::Value, String, Option<String>)> = stmt
        .query_map([], |row| {
            let id: String = row.get(0)?;
            let created_by: String = row.get(1)?;
            let ws: Option<String> = row.get(11)?;
            Ok((
                json!({
                    "id": id,
                    "created_by": created_by,
                    "operation": row.get::<_, String>(2)?,
                    "environment": row.get::<_, String>(3)?,
                    "database_name": row.get::<_, String>(4)?,
                    "detail": row.get::<_, String>(5)?,
                    "status": row.get::<_, String>(6)?,
                    "emergency": row.get::<_, bool>(7)?,
                    "created_at": row.get::<_, String>(8)?,
                    "updated_at": row.get::<_, String>(9)?,
                    "resolved_at": row.get::<_, Option<String>>(10)?,
                }),
                created_by,
                ws,
            ))
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .filter_map(|r| r.ok())
        .collect();

    let mut filtered: Vec<serde_json::Value> = Vec::new();
    for (row, created_by, ws_json) in &candidates {
        let req_id = row["id"].as_str().unwrap_or("");
        let approvals = get_approvals_for_request(conn, req_id)?;
        let (approval_resource, _, _, _) =
            current_approval_resource(conn, req_id, created_by.clone(), ws_json.as_deref())?;
        if authz::authorize_sync(user, Action::ApproveRequest, approval_resource).is_ok() {
            let steps: Vec<crate::server_config::WorkflowStep> = ws_json
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default();
            let current_step = steps.iter().enumerate().find_map(|(i, step)| {
                if !is_step_satisfied(step, &approvals, i as i64) {
                    Some(i)
                } else {
                    None
                }
            });
            if let Some(idx) = current_step {
                let already_approved = approvals
                    .iter()
                    .any(|(si, aid, _)| *si == idx as i64 && aid == &user.user);
                if !already_approved {
                    filtered.push(row.clone());
                }
            } else if steps.is_empty() {
                filtered.push(row.clone());
            }
        }
    }

    let total = filtered.len() as i64;
    let start = (offset as usize).min(filtered.len());
    let end = (start + limit as usize).min(filtered.len());
    let page = filtered[start..end].to_vec();

    Ok(Json(json!({"requests": page, "total": total, "limit": limit, "offset": offset})))
}

fn get_approvals_for_request(
    conn: &rusqlite::Connection,
    request_id: &str,
) -> Result<Vec<(i64, String, String)>, (StatusCode, String)> {
    let mut stmt = conn
        .prepare("SELECT step_index, actor_id, actor_role FROM approvals WHERE request_id = ?1 AND action = 'approve'")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    stmt.query_map(rusqlite::params![request_id], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
    })
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .collect::<Result<Vec<_>, _>>()
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

fn current_approval_resource(
    conn: &rusqlite::Connection,
    request_id: &str,
    requester_id: String,
    workflow_snapshot_json: Option<&str>,
) -> Result<(Resource, usize, Vec<String>, usize), (StatusCode, String)> {
    let steps: Vec<crate::server_config::WorkflowStep> = workflow_snapshot_json
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();

    if steps.is_empty() {
        return Ok((
            Resource::ApprovalStep {
                requester_id,
                allowed_roles: Vec::new(),
            },
            0,
            Vec::new(),
            0,
        ));
    }

    let approvals = get_approvals_for_request(conn, request_id)?;
    let current_step = steps
        .iter()
        .enumerate()
        .find_map(|(i, step)| {
            if !is_step_satisfied(step, &approvals, i as i64) {
                Some(i)
            } else {
                None
            }
        })
        .unwrap_or(steps.len());

    let allowed_roles: Vec<String> = steps
        .get(current_step)
        .map(|step| step.approvers.iter().map(|group| group.role.clone()).collect())
        .unwrap_or_default();

    Ok((
        Resource::ApprovalStep {
            requester_id,
            allowed_roles: allowed_roles.clone(),
        },
        current_step,
        allowed_roles,
        steps.len(),
    ))
}

async fn create_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::CreateRequest, Resource::Global).await?;

    let operation = body["operation"]
        .as_str()
        .ok_or((StatusCode::BAD_REQUEST, "operation required".into()))?;

    const VALID_OPERATIONS: &[&str] = &[
        "execute_query", "migrate_up", "migrate_down", "migrate_status",
    ];
    if !VALID_OPERATIONS.contains(&operation) {
        return Err((StatusCode::BAD_REQUEST, format!("unknown operation: {operation}")));
    }

    let environment = body["environment"]
        .as_str()
        .ok_or((StatusCode::BAD_REQUEST, "environment required".into()))?;
    let detail = body["detail"].as_str().unwrap_or("");
    let database_name = body["database"].as_str().unwrap_or("default");
    let emergency = body["emergency"].as_bool().unwrap_or(false);
    let reason = body["reason"].as_str().map(|s| s.to_string());

    authz::authorize(
        &user,
        Action::CreateRequest,
        request_resource(
            user.user.clone(),
            "new".into(),
            database_name.into(),
            environment.into(),
        ),
    )
    .await?;

    if emergency && reason.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "reason is required for emergency requests".into(),
        ));
    }
    // Readonly and approver-only roles cannot use break-glass
    if emergency && (user.effective_permission() == "readonly" || user.effective_permission() == "approver") {
        return Err((
            StatusCode::FORBIDDEN,
            "insufficient permissions for break-glass".into(),
        ));
    }

    // Approver-only roles cannot create requests
    if user.effective_permission() == "approver" {
        return Err((
            StatusCode::FORBIDDEN,
            "approver-only roles cannot create requests".into(),
        ));
    }

    // Workflow evaluation: check workflows table first, then fall back to static policy
    let conn = state.sqlite.lock().await;
    let workflow_eval = crate::db::evaluate_workflow(&conn, database_name, environment, operation);
    let (policy_action, workflow_require_reason, workflow_id, workflow_snapshot_json) = match &workflow_eval {
        Some((wf_id, steps, require_reason)) => {
            let action = if steps.is_empty() { "auto_approve" } else { "require_approval" };
            let snapshot = serde_json::to_string(steps).unwrap_or_else(|_| "[]".into());
            (action.to_string(), *require_reason, Some(wf_id.clone()), Some(snapshot))
        }
        None => {
            (state.policy.evaluate(environment, operation, user.effective_permission()).to_string(), false, None, None)
        }
    };

    if !emergency && workflow_require_reason && reason.as_ref().map_or(true, |r| r.is_empty()) {
        return Err((
            StatusCode::BAD_REQUEST,
            "reason is required by workflow policy".into(),
        ));
    }

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
        "INSERT INTO requests (id, created_by, operation, environment, database_name, detail, status, created_at, updated_at, emergency, reason, workflow_id, workflow_snapshot_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        rusqlite::params![id, user.user, operation, environment, database_name, detail, status, now, now, emergency, reason, workflow_id, workflow_snapshot_json],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if emergency {
        let token = state
            .token_signer
            .issue(&id, operation, environment, database_name, detail);
        let notif_hooks = crate::db::get_notification_webhooks(&conn, database_name, environment);
        state.webhooks.dispatch_with_policy(notif_hooks, crate::webhook::WebhookEvent {
            event: "break_glass".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            request_id: id.clone(),
            status: "break_glass".into(),
            requester: user.user.clone(),
            actor: user.user.clone(),
            actor_role: Some(user.effective_permission().into()),
            operation: operation.into(),
            environment: environment.into(),
            detail: detail.into(),
            database: database_name.into(),
            reason: reason.clone(),
            next_step: None,
            cli_command: Some(format!("dbward resume {id}")),
        });
        Ok((
            StatusCode::CREATED,
            Json(json!({"id": id, "status": "break_glass", "execution_token": token})),
        ))
    } else if needs_approval {
        let next_step = workflow_snapshot_json.as_deref()
            .and_then(|s| serde_json::from_str::<Vec<serde_json::Value>>(s).ok())
            .and_then(|steps| compute_next_step(&steps, 0));
        let notif_hooks = crate::db::get_notification_webhooks(&conn, database_name, environment);
        state.webhooks.dispatch_with_policy(notif_hooks, crate::webhook::WebhookEvent {
            event: "request_created".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            request_id: id.clone(),
            status: "pending".into(),
            requester: user.user.clone(),
            actor: user.user.clone(),
            actor_role: Some(user.effective_permission().into()),
            operation: operation.into(),
            environment: environment.into(),
            detail: detail.into(),
            database: database_name.into(),
            reason: None,
            next_step,
            cli_command: Some(format!("dbward approve {id}")),
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
    body_str: String,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let approver = auth::authenticate(&headers, &state).await?;
    authz::authorize(&approver, Action::ApproveRequest, Resource::Global).await?;

    let body_val: serde_json::Value = serde_json::from_str(&body_str).unwrap_or(json!({}));

    let result = approve_request_inner(&state, &id, &approver, &body_val).await?;

    // Post-transaction async work
    if let Some(event) = result.webhook_event {
        state.webhooks.dispatch_with_policy(result.notif_hooks, event);
    }
    state.request_notifier.notify(&id).await;

    Ok(Json(result.response))
}

struct ApproveResult {
    response: serde_json::Value,
    notif_hooks: Vec<crate::webhook::WebhookConfig>,
    webhook_event: Option<crate::webhook::WebhookEvent>,
}

async fn approve_request_inner(
    state: &AppState,
    id: &str,
    approver: &crate::state::AuthUser,
    body_val: &serde_json::Value,
) -> Result<ApproveResult, (StatusCode, String)> {
    let mut conn = state.sqlite.lock().await;

    let (req_user, status, operation, environment, database_name, detail, workflow_snapshot_json): (String, String, String, String, String, String, Option<String>) = conn
        .query_row(
            "SELECT created_by, status, operation, environment, database_name, detail, workflow_snapshot_json FROM requests WHERE id = ?1",
            rusqlite::params![id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "request not found".into()))?;

    if status != "pending" {
        return Err((StatusCode::CONFLICT, format!("request is already {status}")));
    }

    // Parse workflow steps from snapshot
    let steps: Vec<crate::server_config::WorkflowStep> = workflow_snapshot_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();

    if steps.is_empty() {
        authz::authorize_sync(
            approver,
            Action::ApproveRequest,
            Resource::ApprovalStep {
                requester_id: req_user.clone(),
                allowed_roles: Vec::new(),
            },
        )?;
        let now = chrono::Utc::now().to_rfc3339();
        let tx = conn.transaction().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        tx.execute(
            "UPDATE requests SET status = 'approved', updated_at = ?1, resolved_at = ?2 WHERE id = ?3",
            rusqlite::params![now, now, id],
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let approval_id = uuid::Uuid::new_v4().to_string();
        tx.execute(
            "INSERT INTO approvals (id, request_id, action, actor_id, step_index, actor_role, comment, created_at) VALUES (?1, ?2, 'approve', ?3, 0, ?4, NULL, ?5)",
            rusqlite::params![approval_id, id, approver.user, approver.effective_permission(), now],
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        tx.commit().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let token = state.token_signer.issue(id, &operation, &environment, &database_name, &detail);
        let notif_hooks = crate::db::get_notification_webhooks(&conn, &database_name, &environment);
        return Ok(ApproveResult {
            response: json!({"id": id, "status": "approved", "approved_by": approver.user, "execution_token": token}),
            notif_hooks,
            webhook_event: Some(crate::webhook::WebhookEvent {
                event: "request_approved".into(), timestamp: chrono::Utc::now().to_rfc3339(),
                request_id: id.into(), status: "approved".into(),
                requester: req_user, actor: approver.user.clone(),
                actor_role: Some(approver.effective_permission().into()),
                operation, environment, detail, database: database_name,
                reason: None, next_step: None,
                cli_command: Some(format!("dbward resume {}", id)),
            }),
        });
    }

    // Read existing approvals
    let existing_approvals: Vec<(i64, String, String)> = {
        let mut stmt = conn.prepare(
            "SELECT step_index, actor_id, actor_role FROM approvals WHERE request_id = ?1 AND action = 'approve'"
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        stmt.query_map(rusqlite::params![id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .filter_map(|r| r.ok())
            .collect()
    };

    // Calculate current step index (first unsatisfied step)
    let current_step = steps.iter().enumerate().find_map(|(i, step)| {
        if !is_step_satisfied(step, &existing_approvals, i as i64) { Some(i) } else { None }
    }).unwrap_or(steps.len());

    if current_step >= steps.len() {
        return Err((StatusCode::CONFLICT, "all steps already satisfied".into()));
    }

    let step = &steps[current_step];

    authz::authorize_sync(
        approver,
        Action::ApproveRequest,
        Resource::ApprovalStep {
            requester_id: req_user.clone(),
            allowed_roles: step.approvers.iter().map(|group| group.role.clone()).collect(),
        },
    )?;

    // Determine approver's role
    let as_role = body_val.get("as_role").and_then(|v| v.as_str()).map(String::from);
    let actor_role = if let Some(ref role) = as_role {
        if !approver.has_role(role) {
            return Err((StatusCode::FORBIDDEN, format!("you do not have role '{role}'")));
        }
        if !step.approvers.iter().any(|g| g.role == *role) {
            return Err((StatusCode::FORBIDDEN, format!("role '{role}' is not an approver for current step")));
        }
        role.clone()
    } else {
        let found = step.approvers.iter().find_map(|g| {
            if approver.has_role(&g.role) { Some(g.role.clone()) } else { None }
        });
        found.or_else(|| {
            if approver.effective_permission() == "admin" {
                step.approvers.first().map(|g| g.role.clone())
            } else {
                None
            }
        }).ok_or((StatusCode::FORBIDDEN, "you do not have a matching role for this step".into()))?
    };

    if step.require_distinct_actors {
        // Distinct actors: same user cannot approve same step at all
        if existing_approvals.iter().any(|(si, aid, _)| *si == current_step as i64 && aid == &approver.user) {
            return Err((StatusCode::CONFLICT, "you already approved this step".into()));
        }
    } else {
        // Non-distinct: same user cannot approve same step with the same role (prevent exact duplicates)
        if existing_approvals.iter().any(|(si, aid, role)| *si == current_step as i64 && aid == &approver.user && role == &actor_role) {
            return Err((StatusCode::CONFLICT, "you already approved this step with this role".into()));
        }
    }

    let now = chrono::Utc::now().to_rfc3339();
    let approval_id = uuid::Uuid::new_v4().to_string();
    let tx = conn.transaction().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tx.execute(
        "INSERT INTO approvals (id, request_id, action, actor_id, step_index, actor_role, comment, created_at) VALUES (?1, ?2, 'approve', ?3, ?4, ?5, NULL, ?6)",
        rusqlite::params![approval_id, id, approver.user, current_step as i64, actor_role, now],
    ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut updated_approvals = existing_approvals.clone();
    updated_approvals.push((current_step as i64, approver.user.clone(), actor_role.clone()));

    let step_now_satisfied = is_step_satisfied(step, &updated_approvals, current_step as i64);
    let all_satisfied = step_now_satisfied && steps.iter().enumerate().all(|(i, s)| {
        is_step_satisfied(s, &updated_approvals, i as i64)
    });

    if all_satisfied {
        tx.execute(
            "UPDATE requests SET status = 'approved', updated_at = ?1, resolved_at = ?2 WHERE id = ?3",
            rusqlite::params![now, now, id],
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        tx.commit().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let token = state.token_signer.issue(id, &operation, &environment, &database_name, &detail);
        let notif_hooks = crate::db::get_notification_webhooks(&conn, &database_name, &environment);
        Ok(ApproveResult {
            response: json!({"id": id, "status": "approved", "approved_by": approver.user, "execution_token": token}),
            notif_hooks,
            webhook_event: Some(crate::webhook::WebhookEvent {
                event: "request_approved".into(), timestamp: chrono::Utc::now().to_rfc3339(),
                request_id: id.into(), status: "approved".into(),
                requester: req_user, actor: approver.user.clone(),
                actor_role: Some(actor_role.clone()),
                operation, environment, detail, database: database_name,
                reason: None, next_step: None,
                cli_command: Some(format!("dbward resume {}", id)),
            }),
        })
    } else {
        tx.execute(
            "UPDATE requests SET updated_at = ?1 WHERE id = ?2",
            rusqlite::params![now, id],
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        tx.commit().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let notif_hooks = crate::db::get_notification_webhooks(&conn, &database_name, &environment);

        let new_current = steps.iter().enumerate().find_map(|(i, s)| {
            if !is_step_satisfied(s, &updated_approvals, i as i64) { Some(i) } else { None }
        }).unwrap_or(steps.len());

        let webhook_event = if step_now_satisfied {
            let steps_json_val: Vec<serde_json::Value> = workflow_snapshot_json
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default();
            let next_step = compute_next_step(&steps_json_val, new_current);
            Some(crate::webhook::WebhookEvent {
                event: "step_approved".into(), timestamp: chrono::Utc::now().to_rfc3339(),
                request_id: id.into(), status: "pending".into(),
                requester: req_user, actor: approver.user.clone(),
                actor_role: Some(actor_role.clone()),
                operation: operation.clone(), environment: environment.clone(),
                detail: detail.clone(), database: database_name.clone(),
                reason: None, next_step,
                cli_command: Some(format!("dbward approve {}", id)),
            })
        } else {
            None
        };

        Ok(ApproveResult {
            response: json!({
                "id": id, "status": "pending",
                "step_completed": current_step, "current_step": new_current,
                "total_steps": steps.len(),
                "message": format!("Step {}/{} approved. Waiting for further approvals.", current_step + 1, steps.len()),
            }),
            notif_hooks,
            webhook_event,
        })
    }
}

fn is_step_satisfied(
    step: &crate::server_config::WorkflowStep,
    approvals: &[(i64, String, String)],
    step_index: i64,
) -> bool {
    let step_approvals: Vec<&(i64, String, String)> = approvals.iter()
        .filter(|(si, _, _)| *si == step_index)
        .collect();

    match step.mode.as_str() {
        "any" => step.approvers.iter().any(|g| {
            step_approvals.iter().filter(|(_, _, role)| role == &g.role).count() >= g.min as usize
        }),
        _ => step.approvers.iter().all(|g| {
            step_approvals.iter().filter(|(_, _, role)| role == &g.role).count() >= g.min as usize
        }),
    }
}

async fn reject_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::RejectRequest, Resource::Global).await?;

    {
        let mut conn = state.sqlite.lock().await;

        let (req_user, status, database_name, environment): (String, String, String, String) = conn
            .query_row(
                "SELECT created_by, status, database_name, environment FROM requests WHERE id = ?1",
                rusqlite::params![id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(|_| (StatusCode::NOT_FOUND, "request not found".into()))?;

        if status != "pending" {
            return Err((StatusCode::CONFLICT, format!("request is already {status}")));
        }

        let workflow_snapshot_json = conn
            .query_row(
                "SELECT workflow_snapshot_json FROM requests WHERE id = ?1",
                rusqlite::params![id],
                |row| row.get::<_, Option<String>>(0),
            )
            .ok()
            .flatten();
        let (approval_resource, step_idx, step_roles, total_steps) = current_approval_resource(
            &conn,
            &id,
            req_user.clone(),
            workflow_snapshot_json.as_deref(),
        )?;
        if let Err(_) = authz::authorize_sync(&user, Action::RejectRequest, approval_resource) {
            let roles_str = step_roles.join(", ");
            return Err((
                StatusCode::FORBIDDEN,
                format!("you are not an approver for the current step (step {}/{}: {})", step_idx + 1, total_steps, roles_str),
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
            "INSERT INTO approvals (id, request_id, action, actor_id, step_index, actor_role, comment, created_at) VALUES (?1, ?2, 'reject', ?3, 0, ?4, NULL, ?5)",
            rusqlite::params![approval_id, id, user.user, user.effective_permission(), now],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        tx.commit().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let notif_hooks = crate::db::get_notification_webhooks(&conn, &database_name, &environment);
        state.webhooks.dispatch_with_policy(notif_hooks, crate::webhook::WebhookEvent {
            event: "request_rejected".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            request_id: id.clone(),
            status: "rejected".into(),
            requester: req_user.clone(),
            actor: user.user.clone(),
            actor_role: Some(user.effective_permission().into()),
            operation: "".into(),
            environment: environment.clone().into(),
            database: database_name.clone().into(),
            detail: "".into(),
            reason: None,
            next_step: None,
            cli_command: None,
        });
    }

    state.request_notifier.notify(&id).await;

    Ok(Json(json!({"id": id, "status": "rejected"})))
}

async fn get_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::GetRequest, Resource::Global).await?;
    let wait: u64 = params
        .get("wait")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
        .min(60);

    let build_response = |conn: &rusqlite::Connection, id: &str, state: &AppState| -> Result<serde_json::Value, (StatusCode, String)> {
        let (id_val, created_by, operation, environment, database_name, detail, status, created_at, updated_at, resolved_at, workflow_snapshot_json): (String, String, String, String, String, String, String, String, String, Option<String>, Option<String>) = conn
            .query_row(
                "SELECT id, created_by, operation, environment, database_name, detail, status, created_at, updated_at, resolved_at, workflow_snapshot_json FROM requests WHERE id = ?1",
                rusqlite::params![id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?, row.get(10)?)),
            )
            .map_err(|_| (StatusCode::NOT_FOUND, "request not found".into()))?;

        let mut resp = json!({
            "id": id_val, "created_by": created_by, "operation": operation,
            "environment": environment, "database_name": database_name, "detail": detail, "status": status,
            "created_at": created_at, "updated_at": updated_at, "resolved_at": resolved_at,
        });

        if status == "approved" || status == "auto_approved" || status == "break_glass" {
            let token = state.token_signer.issue(id, &operation, &environment, &database_name, &detail);
            resp["execution_token"] = serde_json::to_value(token)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }

        // Include approval_progress when workflow snapshot exists
        if let Some(ref snapshot) = workflow_snapshot_json {
            if let Ok(steps) = serde_json::from_str::<Vec<crate::server_config::WorkflowStep>>(snapshot) {
                if !steps.is_empty() {
                    let approvals: Vec<(i64, String, String, String)> = conn
                        .prepare("SELECT step_index, actor_id, actor_role, created_at FROM approvals WHERE request_id = ?1 AND action = 'approve'")
                        .and_then(|mut stmt| {
                            stmt.query_map(rusqlite::params![id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
                                .map(|rows| rows.filter_map(|r| r.ok()).collect())
                        })
                        .unwrap_or_default();

                    let step_views: Vec<serde_json::Value> = steps.iter().enumerate().map(|(i, step)| {
                        let step_apprs: Vec<serde_json::Value> = approvals.iter()
                            .filter(|(si, _, _, _)| *si == i as i64)
                            .map(|(_, user, role, at)| json!({"user": user, "role": role, "at": at}))
                            .collect();
                        let simple_approvals: Vec<(i64, String, String)> = approvals.iter()
                            .map(|(si, uid, role, _)| (*si, uid.clone(), role.clone()))
                            .collect();
                        json!({
                            "index": i,
                            "mode": step.mode,
                            "satisfied": is_step_satisfied(step, &simple_approvals, i as i64),
                            "approvers_required": step.approvers.iter().map(|g| json!({"role": g.role, "min": g.min})).collect::<Vec<_>>(),
                            "approvals": step_apprs,
                        })
                    }).collect();

                    let current = steps.iter().enumerate().find_map(|(i, step)| {
                        let simple: Vec<(i64, String, String)> = approvals.iter()
                            .map(|(si, uid, role, _)| (*si, uid.clone(), role.clone()))
                            .collect();
                        if !is_step_satisfied(step, &simple, i as i64) { Some(i) } else { None }
                    }).unwrap_or(steps.len());

                    resp["approval_progress"] = json!({
                        "current_step": current,
                        "total_steps": steps.len(),
                        "steps": step_views,
                    });
                }
            }
        }

        Ok(resp)
    };

    // First read
    let (resp, status) = {
        let conn = state.sqlite.lock().await;
        let resp = build_response(&conn, &id, &state)?;
        authz::authorize_sync(
            &user,
            Action::GetRequest,
            request_resource(
                resp["created_by"].as_str().unwrap_or("").to_string(),
                resp["status"].as_str().unwrap_or("").to_string(),
                resp["database_name"].as_str().unwrap_or("").to_string(),
                resp["environment"].as_str().unwrap_or("").to_string(),
            ),
        )?;
        let status = resp["status"].as_str().unwrap_or("").to_string();
        (resp, status)
    };

    // Long-poll: wait for status change on non-terminal states
    if wait > 0 && ["pending", "approved", "dispatched", "running"].contains(&status.as_str()) {
        let notify = state.request_notifier.subscribe(&id).await;
        tokio::select! {
            _ = notify.notified() => {},
            _ = tokio::time::sleep(std::time::Duration::from_secs(wait)) => {},
        }
        // Re-read after notification
        let conn = state.sqlite.lock().await;
        let resp = build_response(&conn, &id, &state)?;
        return Ok(Json(resp));
    }

    Ok(Json(resp))
}

async fn list_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(
        &user,
        Action::ListAudit,
        Resource::AuditQuery {
            requested_user: params.get("user").filter(|s| !s.is_empty()).cloned(),
        },
    )
    .await?;

    let (limit, offset) = parse_pagination(&params);
    // Developer: force filter to own user
    let user_filter = match user.effective_permission() {
        "admin" => params.get("user").filter(|s| !s.is_empty()).cloned(),
        _ => Some(user.user.clone()),
    };
    let user_filter = user_filter.as_deref();
    let operation_filter = params.get("operation").filter(|s| !s.is_empty());
    let status_filter = params.get("status").filter(|s| !s.is_empty());
    let database_filter = params.get("database").filter(|s| !s.is_empty());

    let conn = state.sqlite.lock().await;

    let mut where_clauses: Vec<String> = Vec::new();
    let mut bind_values: Vec<String> = Vec::new();

    if let Some(u) = user_filter {
        bind_values.push(u.to_string());
        where_clauses.push(format!("actor_id = ?{}", bind_values.len()));
    }
    if let Some(o) = operation_filter {
        bind_values.push(o.to_string());
        where_clauses.push(format!("operation = ?{}", bind_values.len()));
    }
    if let Some(s) = status_filter {
        bind_values.push(s.to_string());
        where_clauses.push(format!("status = ?{}", bind_values.len()));
    }
    if let Some(d) = database_filter {
        bind_values.push(d.to_string());
        where_clauses.push(format!("database_name = ?{}", bind_values.len()));
    }

    let where_sql = if where_clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", where_clauses.join(" AND "))
    };

    let count_sql = format!("SELECT COUNT(*) FROM audit_log {where_sql}");
    let mut count_stmt = conn
        .prepare(&count_sql)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let total: i64 = count_stmt
        .query_row(rusqlite::params_from_iter(&bind_values), |row| row.get(0))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let query_sql = format!(
        "SELECT id, request_id, execution_id, actor_id, operation, environment, database_name, detail, status, result_summary, error_message, created_at FROM audit_log {where_sql} ORDER BY created_at DESC LIMIT ?{} OFFSET ?{}",
        bind_values.len() + 1,
        bind_values.len() + 2,
    );
    let mut stmt = conn
        .prepare(&query_sql)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut all_params: Vec<Box<dyn rusqlite::types::ToSql>> = bind_values
        .iter()
        .map(|v| Box::new(v.clone()) as Box<dyn rusqlite::types::ToSql>)
        .collect();
    all_params.push(Box::new(limit));
    all_params.push(Box::new(offset));
    let param_refs: Vec<&dyn rusqlite::types::ToSql> = all_params.iter().map(|p| p.as_ref()).collect();

    let rows: Vec<serde_json::Value> = stmt
        .query_map(param_refs.as_slice(), |row| {
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
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(json!({"audit_log": rows, "total": total, "limit": limit, "offset": offset})))
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
    authz::authorize(&user, Action::DispatchRequest, Resource::Global).await?;

    let conn = state.sqlite.lock().await;

    // Check ownership
    let (requester, status, database_name, environment, resolved_at): (
        String,
        String,
        String,
        String,
        Option<String>,
    ) = conn
        .query_row(
            "SELECT created_by, status, database_name, environment, resolved_at FROM requests WHERE id = ?1",
            rusqlite::params![id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "request not found".into()))?;

    authz::authorize_sync(
        &user,
        Action::DispatchRequest,
        request_resource(
            requester.clone(),
            status.clone(),
            database_name.clone(),
            environment.clone(),
        ),
    )?;

    // For executed/failed: check re-execution policy before attempting atomic update
    if status == "executed" || status == "failed" {
        let (max_exec, window_secs, retry) = crate::db::get_execution_policy(&conn, &database_name, &environment);

        if let Some(ref resolved) = resolved_at {
            if let Ok(resolved_time) = chrono::DateTime::parse_from_rfc3339(resolved) {
                let elapsed = chrono::Utc::now().signed_duration_since(resolved_time);
                if elapsed.num_seconds() as u64 > window_secs {
                    return Err((StatusCode::GONE, "execution window expired".into()));
                }
            }
        }

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

    // Atomic status transition
    let now = chrono::Utc::now().to_rfc3339();
    let rows = conn.execute(
        "UPDATE requests SET status = 'dispatched', updated_at = ?1 WHERE id = ?2 AND status IN ('approved', 'auto_approved', 'break_glass', 'executed', 'failed')",
        rusqlite::params![now, id],
    ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if rows == 0 {
        return Err((StatusCode::CONFLICT, "request cannot be dispatched (wrong status)".into()));
    }

    drop(conn);

    let slot = Arc::new(crate::state::ResultSlot {
        result: tokio::sync::Mutex::new(None),
        notify: tokio::sync::Notify::new(),
        created_at: Instant::now(),
    });
    state.result_channels.insert(id.clone(), slot).await;

    Ok(Json(json!({"id": id, "status": "dispatched"})))
}

/// Client waits for execution result (long poll).
async fn stream_result(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::ReadResult, Resource::Global).await?;

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

    authz::authorize(
        &user,
        Action::ReadResult,
        Resource::Result {
            requester_id: requester.clone(),
            access_roles,
        },
    )
    .await?;

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
    authz::authorize(&user, Action::AgentPoll, Resource::Global).await?;

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
    ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("agent registration failed: {e}")))?;

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
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .into_iter()
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
    authz::authorize(&user, Action::AgentClaim, Resource::Global).await?;
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

    authz::authorize_sync(
        &user,
        Action::AgentClaim,
        Resource::AgentExecution {
            agent_id: agent_id.clone(),
        },
    )?;

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
    authz::authorize(&user, Action::AgentSubmitResult, Resource::Global).await?;

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

        authz::authorize_sync(
            &user,
            Action::AgentSubmitResult,
            Resource::AgentExecution {
                agent_id: agent_id.clone(),
            },
        )?;

        let new_status = if success { "completed" } else { "failed" };
        let req_status = if success { "executed" } else { "failed" };

        let (operation, environment, database_name, detail, actor) = conn
            .query_row(
                "SELECT operation, environment, database_name, detail, created_by FROM requests WHERE id = ?1",
                rusqlite::params![request_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, String>(4)?)),
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("request lookup failed: {e}")))?;

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

    state.request_notifier.notify(&request_id).await;

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
    authz::authorize(&user, Action::ListPolicy, Resource::PolicyObject).await?;

    let conn = state.sqlite.lock().await;
    let mut stmt = conn
        .prepare("SELECT id, database_name, environment, operations_json, steps_json, require_reason, source, created_at, updated_at FROM workflows ORDER BY database_name, environment")
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
                "require_reason": row.get::<_, bool>(5)?,
                "source": row.get::<_, String>(6)?,
                "created_at": row.get::<_, String>(7)?,
                "updated_at": row.get::<_, String>(8)?,
            }))
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(json!({"workflows": rows})))
}

async fn get_workflow(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::GetPolicy, Resource::PolicyObject).await?;

    let conn = state.sqlite.lock().await;
    let row = conn
        .query_row(
            "SELECT id, database_name, environment, operations_json, steps_json, require_reason, source, created_at, updated_at FROM workflows WHERE id = ?1",
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
                    "require_reason": row.get::<_, bool>(5)?,
                    "source": row.get::<_, String>(6)?,
                    "created_at": row.get::<_, String>(7)?,
                    "updated_at": row.get::<_, String>(8)?,
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
    authz::authorize(&user, Action::CreatePolicy, Resource::PolicyObject).await?;

    let database = body["database"].as_str()
        .ok_or((StatusCode::BAD_REQUEST, "database required".into()))?;
    let environment = body["environment"].as_str()
        .ok_or((StatusCode::BAD_REQUEST, "environment required".into()))?;
    let operations = body.get("operations").cloned().unwrap_or(json!([]));
    let steps = body.get("steps").cloned().unwrap_or(json!([]));
    let require_reason = body["require_reason"].as_bool().unwrap_or(false);

    let id = format!("{database}:{environment}");
    let ops_json = operations.to_string();
    let steps_json = steps.to_string();
    let now = chrono::Utc::now().to_rfc3339();

    let mut conn = state.sqlite.lock().await;
    {
        let tx = conn.transaction().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        tx.execute(
            "INSERT INTO workflows (id, database_name, environment, operations_json, steps_json, require_reason, source, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'api', ?7, ?7)",
            rusqlite::params![id, database, environment, ops_json, steps_json, require_reason, now],
        )
        .map_err(|e| {
            if e.to_string().contains("UNIQUE") {
                (StatusCode::CONFLICT, format!("workflow for {database}:{environment} already exists"))
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            }
        })?;

        insert_policy_audit(&tx, &user.user, "policy_create", "workflow", &id)?;
        tx.commit().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    Ok((StatusCode::CREATED, Json(json!({"id": id, "database": database, "environment": environment}))))
}

async fn update_workflow(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::UpdatePolicy, Resource::PolicyObject).await?;

    let mut conn = state.sqlite.lock().await;
    let now = chrono::Utc::now().to_rfc3339();

    // Check exists
    conn.query_row("SELECT id FROM workflows WHERE id = ?1", rusqlite::params![id], |_| Ok(()))
        .map_err(|_| (StatusCode::NOT_FOUND, "workflow not found".into()))?;

    // Block changes if pending requests reference this workflow
    let pending_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM requests WHERE workflow_id = ?1 AND status = 'pending'",
        rusqlite::params![id],
        |row| row.get(0),
    ).unwrap_or(0);
    if pending_count > 0 {
        return Err((StatusCode::CONFLICT, format!("{pending_count} pending request(s) reference this workflow")));
    }

    {
        let tx = conn.transaction().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if let Some(steps) = body.get("steps") {
            tx.execute(
                "UPDATE workflows SET steps_json = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
                rusqlite::params![steps.to_string(), now, id],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }
        if let Some(ops) = body.get("operations") {
            tx.execute(
                "UPDATE workflows SET operations_json = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
                rusqlite::params![ops.to_string(), now, id],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }
        if let Some(v) = body.get("require_reason").and_then(|v| v.as_bool()) {
            tx.execute(
                "UPDATE workflows SET require_reason = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
                rusqlite::params![v, now, id],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }

        insert_policy_audit(&tx, &user.user, "policy_update", "workflow", &id)?;
        tx.commit().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    Ok(Json(json!({"id": id, "updated": true})))
}

async fn delete_workflow(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::DeletePolicy, Resource::PolicyObject).await?;

    let mut conn = state.sqlite.lock().await;

    // Block deletion if pending requests reference this workflow
    let pending_count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM requests WHERE workflow_id = ?1 AND status = 'pending'",
        rusqlite::params![id],
        |row| row.get(0),
    ).unwrap_or(0);
    if pending_count > 0 {
        return Err((StatusCode::CONFLICT, format!("{pending_count} pending request(s) reference this workflow")));
    }

    {
        let tx = conn.transaction().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let changes = tx
            .execute("DELETE FROM workflows WHERE id = ?1", rusqlite::params![id])
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        if changes == 0 {
            return Err((StatusCode::NOT_FOUND, "workflow not found".into()));
        }

        insert_policy_audit(&tx, &user.user, "policy_delete", "workflow", &id)?;
        tx.commit().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
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
    authz::authorize(&user, Action::ListPolicy, Resource::PolicyObject).await?;

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
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(json!({"execution_policies": rows})))
}

async fn get_execution_policy_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::GetPolicy, Resource::PolicyObject).await?;

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
    authz::authorize(&user, Action::CreatePolicy, Resource::PolicyObject).await?;

    let database = body["database"].as_str()
        .ok_or((StatusCode::BAD_REQUEST, "database required".into()))?;
    let environment = body["environment"].as_str()
        .ok_or((StatusCode::BAD_REQUEST, "environment required".into()))?;
    let max_executions = body["max_executions"].as_i64().unwrap_or(1);
    let execution_window_secs = body["execution_window_secs"].as_i64().unwrap_or(3600);
    let retry_on_failure = body["retry_on_failure"].as_bool().unwrap_or(false);

    let id = format!("{database}:{environment}");
    let now = chrono::Utc::now().to_rfc3339();

    let mut conn = state.sqlite.lock().await;
    {
        let tx = conn.transaction().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        tx.execute(
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

        insert_policy_audit(&tx, &user.user, "policy_create", "execution_policy", &id)?;
        tx.commit().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    Ok((StatusCode::CREATED, Json(json!({"id": id, "database": database, "environment": environment}))))
}

async fn update_execution_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::UpdatePolicy, Resource::PolicyObject).await?;

    let mut conn = state.sqlite.lock().await;
    let now = chrono::Utc::now().to_rfc3339();

    conn.query_row("SELECT id FROM execution_policies WHERE id = ?1", rusqlite::params![id], |_| Ok(()))
        .map_err(|_| (StatusCode::NOT_FOUND, "execution policy not found".into()))?;

    {
        let tx = conn.transaction().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if let Some(v) = body.get("max_executions").and_then(|v| v.as_i64()) {
            tx.execute(
                "UPDATE execution_policies SET max_executions = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
                rusqlite::params![v, now, id],
            ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }
        if let Some(v) = body.get("execution_window_secs").and_then(|v| v.as_i64()) {
            tx.execute(
                "UPDATE execution_policies SET execution_window_secs = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
                rusqlite::params![v, now, id],
            ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }
        if let Some(v) = body.get("retry_on_failure").and_then(|v| v.as_bool()) {
            tx.execute(
                "UPDATE execution_policies SET retry_on_failure = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
                rusqlite::params![v, now, id],
            ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }

        insert_policy_audit(&tx, &user.user, "policy_update", "execution_policy", &id)?;
        tx.commit().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    Ok(Json(json!({"id": id, "updated": true})))
}

async fn delete_execution_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::DeletePolicy, Resource::PolicyObject).await?;

    let mut conn = state.sqlite.lock().await;
    {
        let tx = conn.transaction().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let changes = tx
            .execute("DELETE FROM execution_policies WHERE id = ?1", rusqlite::params![id])
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        if changes == 0 {
            return Err((StatusCode::NOT_FOUND, "execution policy not found".into()));
        }

        insert_policy_audit(&tx, &user.user, "policy_delete", "execution_policy", &id)?;
        tx.commit().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
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
    authz::authorize(&user, Action::ListPolicy, Resource::PolicyObject).await?;

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
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(json!({"result_policies": rows})))
}

async fn get_result_policy_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::GetPolicy, Resource::PolicyObject).await?;

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
    authz::authorize(&user, Action::CreatePolicy, Resource::PolicyObject).await?;

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

    let mut conn = state.sqlite.lock().await;
    {
        let tx = conn.transaction().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        tx.execute(
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

        insert_policy_audit(&tx, &user.user, "policy_create", "result_policy", &id)?;
        tx.commit().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    Ok((StatusCode::CREATED, Json(json!({"id": id, "database": database, "environment": environment}))))
}

async fn update_result_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::UpdatePolicy, Resource::PolicyObject).await?;

    let mut conn = state.sqlite.lock().await;
    let now = chrono::Utc::now().to_rfc3339();

    conn.query_row("SELECT id FROM result_policies WHERE id = ?1", rusqlite::params![id], |_| Ok(()))
        .map_err(|_| (StatusCode::NOT_FOUND, "result policy not found".into()))?;

    {
        let tx = conn.transaction().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if let Some(v) = body.get("delivery_mode").and_then(|v| v.as_str()) {
            tx.execute(
                "UPDATE result_policies SET delivery_mode = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
                rusqlite::params![v, now, id],
            ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }
        if let Some(v) = body.get("storage_config") {
            tx.execute(
                "UPDATE result_policies SET storage_config_json = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
                rusqlite::params![v.to_string(), now, id],
            ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }
        if let Some(v) = body.get("access") {
            tx.execute(
                "UPDATE result_policies SET access_json = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
                rusqlite::params![v.to_string(), now, id],
            ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }

        insert_policy_audit(&tx, &user.user, "policy_update", "result_policy", &id)?;
        tx.commit().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    Ok(Json(json!({"id": id, "updated": true})))
}

async fn delete_result_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::DeletePolicy, Resource::PolicyObject).await?;

    let mut conn = state.sqlite.lock().await;
    {
        let tx = conn.transaction().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let changes = tx
            .execute("DELETE FROM result_policies WHERE id = ?1", rusqlite::params![id])
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        if changes == 0 {
            return Err((StatusCode::NOT_FOUND, "result policy not found".into()));
        }

        insert_policy_audit(&tx, &user.user, "policy_delete", "result_policy", &id)?;
        tx.commit().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
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
    authz::authorize(&user, Action::ListPolicy, Resource::PolicyObject).await?;

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
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(json!({"notification_policies": rows})))
}

async fn get_notification_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::GetPolicy, Resource::PolicyObject).await?;

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
    authz::authorize(&user, Action::CreatePolicy, Resource::PolicyObject).await?;

    let database = body["database"].as_str()
        .ok_or((StatusCode::BAD_REQUEST, "database required".into()))?;
    let environment = body["environment"].as_str()
        .ok_or((StatusCode::BAD_REQUEST, "environment required".into()))?;
    let webhooks = body.get("webhooks").cloned().unwrap_or(json!([]));

    let id = format!("{database}:{environment}");
    let webhooks_json = webhooks.to_string();
    let now = chrono::Utc::now().to_rfc3339();

    let mut conn = state.sqlite.lock().await;
    {
        let tx = conn.transaction().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        tx.execute(
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

        insert_policy_audit(&tx, &user.user, "policy_create", "notification_policy", &id)?;
        tx.commit().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    Ok((StatusCode::CREATED, Json(json!({"id": id, "database": database, "environment": environment}))))
}

async fn update_notification_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::UpdatePolicy, Resource::PolicyObject).await?;

    let mut conn = state.sqlite.lock().await;
    let now = chrono::Utc::now().to_rfc3339();

    conn.query_row("SELECT id FROM notification_policies WHERE id = ?1", rusqlite::params![id], |_| Ok(()))
        .map_err(|_| (StatusCode::NOT_FOUND, "notification policy not found".into()))?;

    {
        let tx = conn.transaction().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if let Some(v) = body.get("webhooks") {
            tx.execute(
                "UPDATE notification_policies SET webhooks_json = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
                rusqlite::params![v.to_string(), now, id],
            ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }

        insert_policy_audit(&tx, &user.user, "policy_update", "notification_policy", &id)?;
        tx.commit().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    Ok(Json(json!({"id": id, "updated": true})))
}

async fn delete_notification_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::DeletePolicy, Resource::PolicyObject).await?;

    let mut conn = state.sqlite.lock().await;
    {
        let tx = conn.transaction().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let changes = tx
            .execute("DELETE FROM notification_policies WHERE id = ?1", rusqlite::params![id])
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        if changes == 0 {
            return Err((StatusCode::NOT_FOUND, "notification policy not found".into()));
        }

        insert_policy_audit(&tx, &user.user, "policy_delete", "notification_policy", &id)?;
        tx.commit().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    Ok(Json(json!({"id": id, "deleted": true})))
}
