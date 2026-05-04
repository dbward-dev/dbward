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

fn compute_next_step(
    steps: &[serde_json::Value],
    current_step_index: usize,
) -> Option<serde_json::Value> {
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

fn should_filter_capability(values: &[String]) -> bool {
    !values.is_empty() && !values.iter().any(|v| v == "*")
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
        .route("/api/workflows", get(list_workflows).post(create_workflow))
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
) -> Result<Json<serde_json::Value>, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::ListRequests, Resource::Global).await?;
    let (limit, offset) = parse_pagination(&params);
    let status_filter = params.get("status").filter(|s| !s.is_empty());
    let database_filter = params.get("database").filter(|s| !s.is_empty());
    let environment_filter = params.get("environment").filter(|s| !s.is_empty());
    let pending_for_me = params
        .get("pending_for_me")
        .map(|v| v == "true")
        .unwrap_or(false);

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
        "SELECT id, created_by, operation, environment, database_name, detail, status, emergency, created_at, updated_at, resolved_at, reason FROM requests {where_sql} ORDER BY created_at DESC",
    );
    let mut stmt = conn
        .prepare(&query_sql)
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

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
                "reason": row.get::<_, Option<String>>(11)?,
            }))
        })
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

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

    Ok(Json(
        json!({"requests": page, "total": total, "limit": limit, "offset": offset}),
    ))
}

fn list_requests_pending_for_me(
    conn: &rusqlite::Connection,
    user: &crate::state::AuthUser,
    limit: i64,
    offset: i64,
) -> Result<Json<serde_json::Value>, crate::api_error::ApiError> {
    // Fetch all pending requests with workflow snapshots
    let mut stmt = conn
        .prepare(
            "SELECT id, created_by, operation, environment, database_name, detail, status, emergency, created_at, updated_at, resolved_at, workflow_snapshot_json, reason FROM requests WHERE status = 'pending' ORDER BY created_at DESC",
        )
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

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
                    "reason": row.get::<_, Option<String>>(12)?,
                }),
                created_by,
                ws,
            ))
        })
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

    // Batch-load all approvals for pending requests (eliminates N+1)
    let all_approvals: HashMap<String, Vec<(i64, String, String)>> = {
        let mut stmt = conn
            .prepare("SELECT request_id, step_index, actor_id, actor_role FROM approvals WHERE action = 'approve' AND request_id IN (SELECT id FROM requests WHERE status = 'pending')")
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        let mut map: HashMap<String, Vec<(i64, String, String)>> = HashMap::new();
        for (req_id, step, actor, role) in rows {
            map.entry(req_id).or_default().push((step, actor, role));
        }
        map
    };

    let mut filtered: Vec<serde_json::Value> = Vec::new();
    for (row, created_by, ws_json) in &candidates {
        let req_id = row["id"].as_str().unwrap_or("");
        let approvals = all_approvals.get(req_id).cloned().unwrap_or_default();

        let steps: Vec<crate::server_config::WorkflowStep> = ws_json
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default();

        let current_step_idx = steps.iter().enumerate().find_map(|(i, step)| {
            if !is_step_satisfied(step, &approvals, i as i64) {
                Some(i)
            } else {
                None
            }
        });

        let allowed_roles: Vec<String> = current_step_idx
            .and_then(|i| steps.get(i))
            .map(|step| step.approvers.iter().map(|g| g.role.clone()).collect())
            .unwrap_or_default();

        let approval_resource = authz::Resource::ApprovalStep {
            requester_id: created_by.clone(),
            allowed_roles,
        };

        if authz::authorize_sync(user, Action::ApproveRequest, approval_resource).is_ok() {
            if let Some(idx) = current_step_idx {
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

    Ok(Json(
        json!({"requests": page, "total": total, "limit": limit, "offset": offset}),
    ))
}

fn get_approvals_for_request(
    conn: &rusqlite::Connection,
    request_id: &str,
) -> Result<Vec<(i64, String, String)>, crate::api_error::ApiError> {
    crate::db::request_repo::get_approvals(conn, request_id)
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))
}

fn current_approval_resource(
    conn: &rusqlite::Connection,
    request_id: &str,
    requester_id: String,
    workflow_snapshot_json: Option<&str>,
) -> Result<(Resource, usize, Vec<String>, usize), crate::api_error::ApiError> {
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
        .map(|step| {
            step.approvers
                .iter()
                .map(|group| group.role.clone())
                .collect()
        })
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
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::CreateRequest, Resource::Global).await?;

    let operation = body["operation"]
        .as_str()
        .ok_or((StatusCode::BAD_REQUEST, "operation required".into()))?;

    const VALID_OPERATIONS: &[&str] = &[
        "execute_query",
        "migrate_up",
        "migrate_down",
        "migrate_status",
    ];
    if !VALID_OPERATIONS.contains(&operation) {
        return Err(crate::api_error::ApiError::bad_request(format!(
            "unknown operation: {operation}"
        )));
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
        return Err(crate::api_error::ApiError::bad_request(
            "reason is required for emergency requests",
        ));
    }
    // Readonly and approver-only roles cannot use break-glass
    if emergency
        && (user.effective_permission() == "readonly" || user.effective_permission() == "approver")
    {
        return Err(crate::api_error::ApiError::forbidden(
            "insufficient permissions for break-glass",
        ));
    }

    // Approver-only roles cannot create requests
    if user.effective_permission() == "approver" {
        return Err(crate::api_error::ApiError::forbidden(
            "approver-only roles cannot create requests",
        ));
    }

    // Unified policy evaluation: workflows first, static policy fallback
    let conn = state.sqlite.lock().await;
    let decision = crate::db::policy_repo::evaluate_approval_policy(
        &conn,
        &state.policy,
        database_name,
        environment,
        operation,
        user.effective_permission(),
    );

    if !emergency && decision.require_reason && reason.as_ref().map_or(true, |r| r.is_empty()) {
        return Err(crate::api_error::ApiError::bad_request(
            "reason is required by workflow policy",
        ));
    }

    let needs_approval = !emergency && decision.needs_approval;

    let status = if emergency {
        "break_glass"
    } else if needs_approval {
        "pending"
    } else {
        "auto_approved"
    };

    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    crate::db::request_repo::insert_request(&conn, &crate::db::request_repo::NewRequest {
        id: &id, created_by: &user.user, operation, environment, database_name,
        detail, status, emergency, reason: reason.as_deref(),
        workflow_id: decision.workflow_id.as_deref(),
        workflow_snapshot_json: decision.workflow_snapshot_json.as_deref(),
    }, &now)
    .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

    if emergency {
        let token = state
            .token_signer
            .issue(&id, operation, environment, database_name, detail);
        let notif_hooks = crate::db::policy_repo::get_notification_webhooks(&conn, database_name, environment);
        state.webhooks.dispatch_with_policy(
            notif_hooks,
            crate::webhook::WebhookEvent {
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
            },
        );
        Ok((
            StatusCode::CREATED,
            Json(json!({"id": id, "status": "break_glass", "execution_token": token})),
        ))
    } else if needs_approval {
        let next_step = decision
            .workflow_snapshot_json
            .as_deref()
            .and_then(|s| serde_json::from_str::<Vec<serde_json::Value>>(s).ok())
            .and_then(|steps| compute_next_step(&steps, 0));
        let notif_hooks = crate::db::policy_repo::get_notification_webhooks(&conn, database_name, environment);
        state.webhooks.dispatch_with_policy(
            notif_hooks,
            crate::webhook::WebhookEvent {
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
            },
        );
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
) -> Result<Json<serde_json::Value>, crate::api_error::ApiError> {
    let approver = auth::authenticate(&headers, &state).await?;
    authz::authorize(&approver, Action::ApproveRequest, Resource::Global).await?;

    let body_val: serde_json::Value = serde_json::from_str(&body_str).unwrap_or(json!({}));

    let result = approve_request_inner(&state, &id, &approver, &body_val).await?;

    // Post-transaction async work
    if let Some(event) = result.webhook_event {
        state
            .webhooks
            .dispatch_with_policy(result.notif_hooks, event);
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
) -> Result<ApproveResult, crate::api_error::ApiError> {
    let mut conn = state.sqlite.lock().await;

    let ctx = crate::db::request_repo::get_request_context(&conn, id)
        .map_err(|_| crate::api_error::ApiError::not_found("request not found"))?;
    let (req_user, status, operation, environment, database_name, detail, workflow_snapshot_json) =
        (ctx.created_by, ctx.status, ctx.operation, ctx.environment, ctx.database_name, ctx.detail, ctx.workflow_snapshot_json);

    if status != "pending" {
        return Err(crate::api_error::ApiError::conflict(format!(
            "request is already {status}"
        )));
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
        let tx = conn
            .transaction()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        crate::db::request_repo::mark_approved(&tx, id, &now)
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        crate::db::request_repo::insert_approval(
            &tx,
            id,
            "approve",
            &approver.user,
            0,
            approver.effective_permission(),
            &now,
        )
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.commit()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

        let token = state
            .token_signer
            .issue(id, &operation, &environment, &database_name, &detail);
        let notif_hooks = crate::db::policy_repo::get_notification_webhooks(&conn, &database_name, &environment);
        return Ok(ApproveResult {
            response: json!({"id": id, "status": "approved", "approved_by": approver.user, "execution_token": token}),
            notif_hooks,
            webhook_event: Some(crate::webhook::WebhookEvent {
                event: "request_approved".into(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                request_id: id.into(),
                status: "approved".into(),
                requester: req_user,
                actor: approver.user.clone(),
                actor_role: Some(approver.effective_permission().into()),
                operation,
                environment,
                detail,
                database: database_name,
                reason: None,
                next_step: None,
                cli_command: Some(format!("dbward resume {}", id)),
            }),
        });
    }

    // Read existing approvals
    let existing_approvals: Vec<(i64, String, String)> = {
        let mut stmt = conn.prepare(
            "SELECT step_index, actor_id, actor_role FROM approvals WHERE request_id = ?1 AND action = 'approve'"
        ).map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        stmt.query_map(rusqlite::params![id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?
        .filter_map(|r| r.ok())
        .collect()
    };

    // Calculate current step index (first unsatisfied step)
    let current_step = steps
        .iter()
        .enumerate()
        .find_map(|(i, step)| {
            if !is_step_satisfied(step, &existing_approvals, i as i64) {
                Some(i)
            } else {
                None
            }
        })
        .unwrap_or(steps.len());

    if current_step >= steps.len() {
        return Err(crate::api_error::ApiError::conflict(
            "all steps already satisfied",
        ));
    }

    let step = &steps[current_step];

    authz::authorize_sync(
        approver,
        Action::ApproveRequest,
        Resource::ApprovalStep {
            requester_id: req_user.clone(),
            allowed_roles: step
                .approvers
                .iter()
                .map(|group| group.role.clone())
                .collect(),
        },
    )?;

    // Determine approver's role
    let as_role = body_val
        .get("as_role")
        .and_then(|v| v.as_str())
        .map(String::from);
    let actor_role = if let Some(ref role) = as_role {
        if !approver.has_role(role) {
            return Err(crate::api_error::ApiError::forbidden(format!(
                "you do not have role '{role}'"
            )));
        }
        if !step.approvers.iter().any(|g| g.role == *role) {
            return Err(crate::api_error::ApiError::forbidden(format!(
                "role '{role}' is not an approver for current step"
            )));
        }
        role.clone()
    } else {
        let found = step.approvers.iter().find_map(|g| {
            if approver.has_role(&g.role) {
                Some(g.role.clone())
            } else {
                None
            }
        });
        found
            .or_else(|| {
                if approver.effective_permission() == "admin" {
                    step.approvers.first().map(|g| g.role.clone())
                } else {
                    None
                }
            })
            .ok_or((
                StatusCode::FORBIDDEN,
                "you do not have a matching role for this step".into(),
            ))?
    };

    if step.require_distinct_actors {
        // Distinct actors: same user cannot approve same step at all
        if existing_approvals
            .iter()
            .any(|(si, aid, _)| *si == current_step as i64 && aid == &approver.user)
        {
            return Err(crate::api_error::ApiError::conflict(
                "you already approved this step",
            ));
        }
    } else {
        // Non-distinct: same user cannot approve same step with the same role (prevent exact duplicates)
        if existing_approvals.iter().any(|(si, aid, role)| {
            *si == current_step as i64 && aid == &approver.user && role == &actor_role
        }) {
            return Err(crate::api_error::ApiError::conflict(
                "you already approved this step with this role",
            ));
        }
    }

    let now = chrono::Utc::now().to_rfc3339();
    let tx = conn
        .transaction()
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
    crate::db::request_repo::insert_approval(
        &tx,
        id,
        "approve",
        &approver.user,
        current_step as i64,
        &actor_role,
        &now,
    )
    .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

    let mut updated_approvals = existing_approvals.clone();
    updated_approvals.push((
        current_step as i64,
        approver.user.clone(),
        actor_role.clone(),
    ));

    let step_now_satisfied = is_step_satisfied(step, &updated_approvals, current_step as i64);
    let all_satisfied = step_now_satisfied
        && steps
            .iter()
            .enumerate()
            .all(|(i, s)| is_step_satisfied(s, &updated_approvals, i as i64));

    if all_satisfied {
        crate::db::request_repo::mark_approved(&tx, id, &now)
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.commit()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

        let token = state
            .token_signer
            .issue(id, &operation, &environment, &database_name, &detail);
        let notif_hooks = crate::db::policy_repo::get_notification_webhooks(&conn, &database_name, &environment);
        Ok(ApproveResult {
            response: json!({"id": id, "status": "approved", "approved_by": approver.user, "execution_token": token}),
            notif_hooks,
            webhook_event: Some(crate::webhook::WebhookEvent {
                event: "request_approved".into(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                request_id: id.into(),
                status: "approved".into(),
                requester: req_user,
                actor: approver.user.clone(),
                actor_role: Some(actor_role.clone()),
                operation,
                environment,
                detail,
                database: database_name,
                reason: None,
                next_step: None,
                cli_command: Some(format!("dbward resume {}", id)),
            }),
        })
    } else {
        crate::db::request_repo::touch_updated_at(&tx, id, &now)
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.commit()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

        let notif_hooks = crate::db::policy_repo::get_notification_webhooks(&conn, &database_name, &environment);

        let new_current = steps
            .iter()
            .enumerate()
            .find_map(|(i, s)| {
                if !is_step_satisfied(s, &updated_approvals, i as i64) {
                    Some(i)
                } else {
                    None
                }
            })
            .unwrap_or(steps.len());

        let webhook_event = if step_now_satisfied {
            let steps_json_val: Vec<serde_json::Value> = workflow_snapshot_json
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default();
            let next_step = compute_next_step(&steps_json_val, new_current);
            Some(crate::webhook::WebhookEvent {
                event: "step_approved".into(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                request_id: id.into(),
                status: "pending".into(),
                requester: req_user,
                actor: approver.user.clone(),
                actor_role: Some(actor_role.clone()),
                operation: operation.clone(),
                environment: environment.clone(),
                detail: detail.clone(),
                database: database_name.clone(),
                reason: None,
                next_step,
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
    let step_approvals: Vec<&(i64, String, String)> = approvals
        .iter()
        .filter(|(si, _, _)| *si == step_index)
        .collect();

    match step.mode.as_str() {
        "any" => step.approvers.iter().any(|g| {
            step_approvals
                .iter()
                .filter(|(_, _, role)| role == &g.role)
                .count()
                >= g.min as usize
        }),
        _ => step.approvers.iter().all(|g| {
            step_approvals
                .iter()
                .filter(|(_, _, role)| role == &g.role)
                .count()
                >= g.min as usize
        }),
    }
}

async fn reject_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::RejectRequest, Resource::Global).await?;

    {
        let mut conn = state.sqlite.lock().await;

        let ctx = crate::db::request_repo::get_request_context(&conn, &id)
            .map_err(|_| crate::api_error::ApiError::not_found("request not found"))?;
        let req_user = ctx.created_by.clone();
        let status = ctx.status.clone();
        let database_name = ctx.database_name.clone();
        let environment = ctx.environment.clone();

        if status != "pending" {
            return Err(crate::api_error::ApiError::conflict(format!(
                "request is already {status}"
            )));
        }

        let workflow_snapshot_json = ctx.workflow_snapshot_json.clone();
        let (approval_resource, step_idx, step_roles, total_steps) = current_approval_resource(
            &conn,
            &id,
            req_user.clone(),
            workflow_snapshot_json.as_deref(),
        )?;
        if let Err(_) = authz::authorize_sync(&user, Action::RejectRequest, approval_resource) {
            let roles_str = step_roles.join(", ");
            return Err(crate::api_error::ApiError::forbidden(format!(
                "you are not an approver for the current step (step {}/{}: {})",
                step_idx + 1,
                total_steps,
                roles_str
            )));
        }

        let now = chrono::Utc::now().to_rfc3339();
        let tx = conn
            .transaction()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        crate::db::request_repo::mark_rejected(&tx, &id, &now)
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        crate::db::request_repo::insert_approval(
            &tx,
            &id,
            "reject",
            &user.user,
            0,
            user.effective_permission(),
            &now,
        )
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.commit()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

        let notif_hooks = crate::db::policy_repo::get_notification_webhooks(&conn, &database_name, &environment);
        state.webhooks.dispatch_with_policy(
            notif_hooks,
            crate::webhook::WebhookEvent {
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
            },
        );
    }

    state.request_notifier.notify(&id).await;

    Ok(Json(json!({"id": id, "status": "rejected"})))
}

async fn get_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::GetRequest, Resource::Global).await?;
    let wait: u64 = params
        .get("wait")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
        .min(60);

    let build_response = |conn: &rusqlite::Connection,
                          id: &str,
                          state: &AppState|
     -> Result<serde_json::Value, crate::api_error::ApiError> {
        let (id_val, created_by, operation, environment, database_name, detail, status, created_at, updated_at, resolved_at, workflow_snapshot_json, reason): (String, String, String, String, String, String, String, String, String, Option<String>, Option<String>, Option<String>) = conn
            .query_row(
                "SELECT id, created_by, operation, environment, database_name, detail, status, created_at, updated_at, resolved_at, workflow_snapshot_json, reason FROM requests WHERE id = ?1",
                rusqlite::params![id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?, row.get(10)?, row.get(11)?)),
            )
            .map_err(|_| crate::api_error::ApiError::not_found("request not found"))?;

        let mut resp = json!({
            "id": id_val, "created_by": created_by, "operation": operation,
            "environment": environment, "database_name": database_name, "detail": detail, "status": status,
            "created_at": created_at, "updated_at": updated_at, "resolved_at": resolved_at,
            "reason": reason,
        });

        if status == "approved" || status == "auto_approved" || status == "break_glass" {
            let token =
                state
                    .token_signer
                    .issue(id, &operation, &environment, &database_name, &detail);
            resp["execution_token"] = serde_json::to_value(token)
                .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        }

        // Include approval_progress when workflow snapshot exists
        if let Some(ref snapshot) = workflow_snapshot_json {
            if let Ok(steps) =
                serde_json::from_str::<Vec<crate::server_config::WorkflowStep>>(snapshot)
            {
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

                    let current = steps
                        .iter()
                        .enumerate()
                        .find_map(|(i, step)| {
                            let simple: Vec<(i64, String, String)> = approvals
                                .iter()
                                .map(|(si, uid, role, _)| (*si, uid.clone(), role.clone()))
                                .collect();
                            if !is_step_satisfied(step, &simple, i as i64) {
                                Some(i)
                            } else {
                                None
                            }
                        })
                        .unwrap_or(steps.len());

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
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
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
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
    let total: i64 = count_stmt
        .query_row(rusqlite::params_from_iter(&bind_values), |row| row.get(0))
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

    let query_sql = format!(
        "SELECT id, request_id, execution_id, actor_id, operation, environment, database_name, detail, status, result_summary, error_message, created_at FROM audit_log {where_sql} ORDER BY created_at DESC LIMIT ?{} OFFSET ?{}",
        bind_values.len() + 1,
        bind_values.len() + 2,
    );
    let mut stmt = conn
        .prepare(&query_sql)
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

    let mut all_params: Vec<Box<dyn rusqlite::types::ToSql>> = bind_values
        .iter()
        .map(|v| Box::new(v.clone()) as Box<dyn rusqlite::types::ToSql>)
        .collect();
    all_params.push(Box::new(limit));
    all_params.push(Box::new(offset));
    let param_refs: Vec<&dyn rusqlite::types::ToSql> =
        all_params.iter().map(|p| p.as_ref()).collect();

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
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

    Ok(Json(
        json!({"audit_log": rows, "total": total, "limit": limit, "offset": offset}),
    ))
}

// ---------------------------------------------------------------------------
// On-demand execution: dispatch + result stream
// ---------------------------------------------------------------------------

/// Client dispatches a request for execution. Creates a result channel.
async fn dispatch_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
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
    ) = {
        let ctx = crate::db::request_repo::get_request_context(&conn, &id)
            .map_err(|_| crate::api_error::ApiError::not_found("request not found"))?;
        (ctx.created_by, ctx.status, ctx.database_name, ctx.environment, ctx.resolved_at)
    };

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
        let (max_exec, window_secs, retry) =
            crate::db::policy_repo::get_execution_policy(&conn, &database_name, &environment);

        if let Some(ref resolved) = resolved_at {
            if let Ok(resolved_time) = chrono::DateTime::parse_from_rfc3339(resolved) {
                let elapsed = chrono::Utc::now().signed_duration_since(resolved_time);
                if elapsed.num_seconds() as u64 > window_secs {
                    return Err(crate::api_error::ApiError::new(
                        StatusCode::GONE,
                        "execution window expired",
                    ));
                }
            }
        }

        let exec_count = crate::db::request_repo::count_executions(&conn, &id);
        if status == "failed" && !retry {
            return Err(crate::api_error::ApiError::conflict(
                "retry on failure is disabled",
            ));
        }
        if exec_count >= max_exec {
            return Err(crate::api_error::ApiError::conflict(format!(
                "max executions ({max_exec}) reached"
            )));
        }
    }

    if !crate::db::request_repo::mark_dispatched(&conn, &id)
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?
    {
        return Err(crate::api_error::ApiError::conflict(
            "request cannot be dispatched (wrong status)",
        ));
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
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::ReadResult, Resource::Global).await?;

    let (requester, database_name, environment, status): (String, String, String, String) = {
        let conn = state.sqlite.lock().await;
        conn.query_row(
            "SELECT created_by, database_name, environment, status FROM requests WHERE id = ?1",
            rusqlite::params![id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| crate::api_error::ApiError::not_found("request not found"))?
    };

    let access_roles = {
        let conn = state.sqlite.lock().await;
        let (_, access_roles) = crate::db::policy_repo::get_result_policy(&conn, &database_name, &environment);
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
            return Err(crate::api_error::ApiError::conflict(msg));
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
        return Err(crate::api_error::ApiError::new(
            StatusCode::GATEWAY_TIMEOUT,
            "timed out waiting for result",
        ));
    }

    let result = slot.result.lock().await.clone();
    let _ = state.result_channels.remove(&id).await;

    match result {
        Some(payload) => Ok(Json(payload)),
        None => Err(crate::api_error::ApiError::internal("result was empty")),
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
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
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
    let caps_json = serde_json::to_string(&json!({
        "databases": databases,
        "environments": environments,
        "operations": operations,
    }))
    .unwrap_or_else(|_| "{}".into());
    crate::db::agent_repo::upsert_agent(&conn, &user.user, &user.token_id, &caps_json)
        .map_err(|e| crate::api_error::ApiError::internal(format!("agent registration failed: {e}")))?;

    // Build dynamic WHERE clause for capability filtering
    let mut where_clauses = vec!["status = 'dispatched'".to_string()];
    let mut bind_values: Vec<String> = Vec::new();

    if should_filter_capability(&databases) {
        let placeholders: Vec<String> = databases
            .iter()
            .enumerate()
            .map(|(i, _)| format!("?{}", bind_values.len() + i + 1))
            .collect();
        where_clauses.push(format!("database_name IN ({})", placeholders.join(",")));
        bind_values.extend(databases.clone());
    }
    if should_filter_capability(&environments) {
        let placeholders: Vec<String> = environments
            .iter()
            .enumerate()
            .map(|(i, _)| format!("?{}", bind_values.len() + i + 1))
            .collect();
        where_clauses.push(format!("environment IN ({})", placeholders.join(",")));
        bind_values.extend(environments.clone());
    }
    if should_filter_capability(&operations) {
        let placeholders: Vec<String> = operations
            .iter()
            .enumerate()
            .map(|(i, _)| format!("?{}", bind_values.len() + i + 1))
            .collect();
        where_clauses.push(format!("operation IN ({})", placeholders.join(",")));
        bind_values.extend(operations.clone());
    }

    let where_sql = where_clauses.join(" AND ");
    let query_sql = format!(
        "SELECT id, created_by, operation, environment, database_name, detail
         FROM requests WHERE {where_sql} ORDER BY created_at ASC LIMIT 10"
    );

    let mut stmt = conn
        .prepare(&query_sql)
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

    let rows: Vec<serde_json::Value> = stmt
        .query_map(rusqlite::params_from_iter(&bind_values), |row| {
            Ok(json!({
                "id": row.get::<_, String>(0)?,
                "created_by": row.get::<_, String>(1)?,
                "operation": row.get::<_, String>(2)?,
                "environment": row.get::<_, String>(3)?,
                "database_name": row.get::<_, String>(4)?,
                "detail": row.get::<_, String>(5)?,
            }))
        })
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

    Ok(Json(json!({"jobs": rows})))
}

/// Agent claims a job for execution.
async fn agent_claim(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(_body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::AgentClaim, Resource::Global).await?;
    let agent_id = user.user.clone();

    let mut conn = state.sqlite.lock().await;

    let ctx = crate::db::request_repo::get_request_context(&conn, &id)
        .map_err(|_| crate::api_error::ApiError::not_found("request not found"))?;
    let (operation, environment, database, detail, status) =
        (ctx.operation, ctx.environment, ctx.database_name, ctx.detail, ctx.status);

    if status != "dispatched" {
        return Err(crate::api_error::ApiError::conflict(format!(
            "request status is {status}, cannot claim"
        )));
    }

    authz::authorize_sync(
        &user,
        Action::AgentClaim,
        Resource::AgentExecution {
            agent_id: agent_id.clone(),
        },
    )?;

    // Verify agent has capability for this job
    if let Some(caps_json) = crate::db::agent_repo::get_agent_capabilities(&conn, &agent_id) {
        if let Ok(caps) = serde_json::from_str::<serde_json::Value>(&caps_json) {
            let matches = |arr: &serde_json::Value, val: &str| -> bool {
                arr.as_array().map_or(true, |a| {
                    a.is_empty()
                        || a.iter()
                            .any(|v| v.as_str() == Some(val) || v.as_str() == Some("*"))
                })
            };
            if !matches(&caps["databases"], &database)
                || !matches(&caps["environments"], &environment)
                || !matches(&caps["operations"], &operation)
            {
                return Err(crate::api_error::ApiError::forbidden(
                    "agent lacks capability for this job",
                ));
            }
        }
    }

    let token = state
        .token_signer
        .issue(&id, &operation, &environment, &database, &detail);
    let token_json = serde_json::to_string(&token)
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

    let exec_id = crate::db::agent_repo::create_execution_and_mark_running(
        &mut conn,
        &id,
        &agent_id,
        &token_json,
    )
    .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

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
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::AgentSubmitResult, Resource::Global).await?;

    let success = body["success"].as_bool().unwrap_or(false);
    let result = body["result"].clone();
    let error_msg = body["error"].as_str().map(|s| s.to_string());

    let (request_id, req_status) = {
        let mut conn = state.sqlite.lock().await;

        let exec_ctx = crate::db::agent_repo::get_execution_context(&conn, &id)
            .map_err(|_| crate::api_error::ApiError::not_found("execution not found"))?;

        if exec_ctx.status != "claimed" {
            return Err(crate::api_error::ApiError::conflict(format!(
                "execution status is {}", exec_ctx.status
            )));
        }

        authz::authorize_sync(
            &user,
            Action::AgentSubmitResult,
            Resource::AgentExecution {
                agent_id: exec_ctx.agent_id.clone(),
            },
        )?;

        let req_ctx = crate::db::request_repo::get_request_context(&conn, &exec_ctx.request_id)
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

        let req_status = crate::db::agent_repo::finish_execution(
            &mut conn, &id, &exec_ctx.request_id, success, error_msg.as_deref(),
            &req_ctx.operation, &req_ctx.environment, &req_ctx.database_name,
            &req_ctx.detail, &req_ctx.created_by,
        )
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

        (exec_ctx.request_id, req_status)
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
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::ListPolicy, Resource::PolicyObject).await?;

    let conn = state.sqlite.lock().await;
    let mut stmt = conn
        .prepare("SELECT id, database_name, environment, operations_json, steps_json, require_reason, source, created_at, updated_at FROM workflows ORDER BY database_name, environment")
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

    let rows: Vec<serde_json::Value> = stmt
        .query_map([], |row| {
            let ops: serde_json::Value =
                serde_json::from_str(row.get::<_, String>(3)?.as_str()).unwrap_or_default();
            let steps: serde_json::Value =
                serde_json::from_str(row.get::<_, String>(4)?.as_str()).unwrap_or_default();
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
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

    Ok(Json(json!({"workflows": rows})))
}

async fn get_workflow(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
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
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::CreatePolicy, Resource::PolicyObject).await?;

    let database = body["database"]
        .as_str()
        .ok_or((StatusCode::BAD_REQUEST, "database required".into()))?;
    let environment = body["environment"]
        .as_str()
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
        let tx = conn
            .transaction()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
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

        crate::db::audit_repo::insert_policy_change(&tx, &user.user, "policy_create", "workflow", &id)
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.commit()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
    }

    Ok((
        StatusCode::CREATED,
        Json(json!({"id": id, "database": database, "environment": environment})),
    ))
}

async fn update_workflow(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::UpdatePolicy, Resource::PolicyObject).await?;

    let mut conn = state.sqlite.lock().await;
    let now = chrono::Utc::now().to_rfc3339();

    // Check exists
    conn.query_row(
        "SELECT id FROM workflows WHERE id = ?1",
        rusqlite::params![id],
        |_| Ok(()),
    )
    .map_err(|_| (StatusCode::NOT_FOUND, "workflow not found".into()))?;

    // Block changes if pending requests reference this workflow
    let pending_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM requests WHERE workflow_id = ?1 AND status = 'pending'",
            rusqlite::params![id],
            |row| row.get(0),
        )
        .unwrap_or(0);
    if pending_count > 0 {
        return Err(crate::api_error::ApiError::conflict(format!(
            "{pending_count} pending request(s) reference this workflow"
        )));
    }

    {
        let tx = conn
            .transaction()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        if let Some(steps) = body.get("steps") {
            tx.execute(
                "UPDATE workflows SET steps_json = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
                rusqlite::params![steps.to_string(), now, id],
            )
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        }
        if let Some(ops) = body.get("operations") {
            tx.execute(
                "UPDATE workflows SET operations_json = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
                rusqlite::params![ops.to_string(), now, id],
            )
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        }
        if let Some(v) = body.get("require_reason").and_then(|v| v.as_bool()) {
            tx.execute(
                "UPDATE workflows SET require_reason = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
                rusqlite::params![v, now, id],
            )
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        }

        crate::db::audit_repo::insert_policy_change(&tx, &user.user, "policy_update", "workflow", &id)
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.commit()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
    }

    Ok(Json(json!({"id": id, "updated": true})))
}

async fn delete_workflow(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::DeletePolicy, Resource::PolicyObject).await?;

    let mut conn = state.sqlite.lock().await;

    // Block deletion if pending requests reference this workflow
    let pending_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM requests WHERE workflow_id = ?1 AND status = 'pending'",
            rusqlite::params![id],
            |row| row.get(0),
        )
        .unwrap_or(0);
    if pending_count > 0 {
        return Err(crate::api_error::ApiError::conflict(format!(
            "{pending_count} pending request(s) reference this workflow"
        )));
    }

    {
        let tx = conn
            .transaction()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        let changes = tx
            .execute("DELETE FROM workflows WHERE id = ?1", rusqlite::params![id])
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

        if changes == 0 {
            return Err(crate::api_error::ApiError::not_found("workflow not found"));
        }

        crate::db::audit_repo::insert_policy_change(&tx, &user.user, "policy_delete", "workflow", &id)
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.commit()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
    }

    Ok(Json(json!({"id": id, "deleted": true})))
}

// ---------------------------------------------------------------------------
// Execution Policy CRUD (admin only for mutations)
// ---------------------------------------------------------------------------

async fn list_execution_policies(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::ListPolicy, Resource::PolicyObject).await?;

    let conn = state.sqlite.lock().await;
    let mut stmt = conn
        .prepare("SELECT id, database_name, environment, max_executions, execution_window_secs, retry_on_failure, source, created_at, updated_at FROM execution_policies ORDER BY database_name, environment")
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

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
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

    Ok(Json(json!({"execution_policies": rows})))
}

async fn get_execution_policy_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
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
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::CreatePolicy, Resource::PolicyObject).await?;

    let database = body["database"]
        .as_str()
        .ok_or((StatusCode::BAD_REQUEST, "database required".into()))?;
    let environment = body["environment"]
        .as_str()
        .ok_or((StatusCode::BAD_REQUEST, "environment required".into()))?;
    let max_executions = body["max_executions"].as_i64().unwrap_or(1);
    let execution_window_secs = body["execution_window_secs"].as_i64().unwrap_or(3600);
    let retry_on_failure = body["retry_on_failure"].as_bool().unwrap_or(false);

    let id = format!("{database}:{environment}");
    let now = chrono::Utc::now().to_rfc3339();

    let mut conn = state.sqlite.lock().await;
    {
        let tx = conn
            .transaction()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
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

        crate::db::audit_repo::insert_policy_change(&tx, &user.user, "policy_create", "execution_policy", &id)
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.commit()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
    }

    Ok((
        StatusCode::CREATED,
        Json(json!({"id": id, "database": database, "environment": environment})),
    ))
}

async fn update_execution_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::UpdatePolicy, Resource::PolicyObject).await?;

    let mut conn = state.sqlite.lock().await;
    let now = chrono::Utc::now().to_rfc3339();

    conn.query_row(
        "SELECT id FROM execution_policies WHERE id = ?1",
        rusqlite::params![id],
        |_| Ok(()),
    )
    .map_err(|_| (StatusCode::NOT_FOUND, "execution policy not found".into()))?;

    {
        let tx = conn
            .transaction()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        if let Some(v) = body.get("max_executions").and_then(|v| v.as_i64()) {
            tx.execute(
                "UPDATE execution_policies SET max_executions = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
                rusqlite::params![v, now, id],
            ).map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        }
        if let Some(v) = body.get("execution_window_secs").and_then(|v| v.as_i64()) {
            tx.execute(
                "UPDATE execution_policies SET execution_window_secs = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
                rusqlite::params![v, now, id],
            ).map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        }
        if let Some(v) = body.get("retry_on_failure").and_then(|v| v.as_bool()) {
            tx.execute(
                "UPDATE execution_policies SET retry_on_failure = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
                rusqlite::params![v, now, id],
            ).map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        }

        crate::db::audit_repo::insert_policy_change(&tx, &user.user, "policy_update", "execution_policy", &id)
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.commit()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
    }

    Ok(Json(json!({"id": id, "updated": true})))
}

async fn delete_execution_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::DeletePolicy, Resource::PolicyObject).await?;

    let mut conn = state.sqlite.lock().await;
    {
        let tx = conn
            .transaction()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        let changes = tx
            .execute(
                "DELETE FROM execution_policies WHERE id = ?1",
                rusqlite::params![id],
            )
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

        if changes == 0 {
            return Err(crate::api_error::ApiError::not_found(
                "execution policy not found",
            ));
        }

        crate::db::audit_repo::insert_policy_change(&tx, &user.user, "policy_delete", "execution_policy", &id)
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.commit()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
    }

    Ok(Json(json!({"id": id, "deleted": true})))
}

// ---------------------------------------------------------------------------
// Result Policy CRUD (admin only for mutations)
// ---------------------------------------------------------------------------

async fn list_result_policies(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::ListPolicy, Resource::PolicyObject).await?;

    let conn = state.sqlite.lock().await;
    let mut stmt = conn
        .prepare("SELECT id, database_name, environment, delivery_mode, storage_config_json, access_json, source, created_at, updated_at FROM result_policies ORDER BY database_name, environment")
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

    let rows: Vec<serde_json::Value> = stmt
        .query_map([], |row| {
            let storage: serde_json::Value =
                serde_json::from_str(row.get::<_, String>(4)?.as_str()).unwrap_or_default();
            let access: serde_json::Value =
                serde_json::from_str(row.get::<_, String>(5)?.as_str()).unwrap_or_default();
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
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

    Ok(Json(json!({"result_policies": rows})))
}

async fn get_result_policy_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
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
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::CreatePolicy, Resource::PolicyObject).await?;

    let database = body["database"]
        .as_str()
        .ok_or((StatusCode::BAD_REQUEST, "database required".into()))?;
    let environment = body["environment"]
        .as_str()
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
        let tx = conn
            .transaction()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
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

        crate::db::audit_repo::insert_policy_change(&tx, &user.user, "policy_create", "result_policy", &id)
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.commit()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
    }

    Ok((
        StatusCode::CREATED,
        Json(json!({"id": id, "database": database, "environment": environment})),
    ))
}

async fn update_result_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::UpdatePolicy, Resource::PolicyObject).await?;

    let mut conn = state.sqlite.lock().await;
    let now = chrono::Utc::now().to_rfc3339();

    conn.query_row(
        "SELECT id FROM result_policies WHERE id = ?1",
        rusqlite::params![id],
        |_| Ok(()),
    )
    .map_err(|_| (StatusCode::NOT_FOUND, "result policy not found".into()))?;

    {
        let tx = conn
            .transaction()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        if let Some(v) = body.get("delivery_mode").and_then(|v| v.as_str()) {
            tx.execute(
                "UPDATE result_policies SET delivery_mode = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
                rusqlite::params![v, now, id],
            ).map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        }
        if let Some(v) = body.get("storage_config") {
            tx.execute(
                "UPDATE result_policies SET storage_config_json = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
                rusqlite::params![v.to_string(), now, id],
            ).map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        }
        if let Some(v) = body.get("access") {
            tx.execute(
                "UPDATE result_policies SET access_json = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
                rusqlite::params![v.to_string(), now, id],
            ).map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        }

        crate::db::audit_repo::insert_policy_change(&tx, &user.user, "policy_update", "result_policy", &id)
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.commit()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
    }

    Ok(Json(json!({"id": id, "updated": true})))
}

async fn delete_result_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::DeletePolicy, Resource::PolicyObject).await?;

    let mut conn = state.sqlite.lock().await;
    {
        let tx = conn
            .transaction()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        let changes = tx
            .execute(
                "DELETE FROM result_policies WHERE id = ?1",
                rusqlite::params![id],
            )
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

        if changes == 0 {
            return Err(crate::api_error::ApiError::not_found(
                "result policy not found",
            ));
        }

        crate::db::audit_repo::insert_policy_change(&tx, &user.user, "policy_delete", "result_policy", &id)
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.commit()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
    }

    Ok(Json(json!({"id": id, "deleted": true})))
}

// ---------------------------------------------------------------------------
// Notification Policy CRUD (admin only for mutations)
// ---------------------------------------------------------------------------

async fn list_notification_policies(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::ListPolicy, Resource::PolicyObject).await?;

    let conn = state.sqlite.lock().await;
    let mut stmt = conn
        .prepare("SELECT id, database_name, environment, webhooks_json, source, created_at, updated_at FROM notification_policies ORDER BY database_name, environment")
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

    let rows: Vec<serde_json::Value> = stmt
        .query_map([], |row| {
            let webhooks: serde_json::Value =
                serde_json::from_str(row.get::<_, String>(3)?.as_str()).unwrap_or_default();
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
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

    Ok(Json(json!({"notification_policies": rows})))
}

async fn get_notification_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
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
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::CreatePolicy, Resource::PolicyObject).await?;

    let database = body["database"]
        .as_str()
        .ok_or((StatusCode::BAD_REQUEST, "database required".into()))?;
    let environment = body["environment"]
        .as_str()
        .ok_or((StatusCode::BAD_REQUEST, "environment required".into()))?;
    let webhooks = body.get("webhooks").cloned().unwrap_or(json!([]));

    let id = format!("{database}:{environment}");
    let webhooks_json = webhooks.to_string();
    let now = chrono::Utc::now().to_rfc3339();

    let mut conn = state.sqlite.lock().await;
    {
        let tx = conn
            .transaction()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
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

        crate::db::audit_repo::insert_policy_change(&tx, &user.user, "policy_create", "notification_policy", &id)
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.commit()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
    }

    Ok((
        StatusCode::CREATED,
        Json(json!({"id": id, "database": database, "environment": environment})),
    ))
}

async fn update_notification_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::UpdatePolicy, Resource::PolicyObject).await?;

    let mut conn = state.sqlite.lock().await;
    let now = chrono::Utc::now().to_rfc3339();

    conn.query_row(
        "SELECT id FROM notification_policies WHERE id = ?1",
        rusqlite::params![id],
        |_| Ok(()),
    )
    .map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            "notification policy not found".into(),
        )
    })?;

    {
        let tx = conn
            .transaction()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        if let Some(v) = body.get("webhooks") {
            tx.execute(
                "UPDATE notification_policies SET webhooks_json = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
                rusqlite::params![v.to_string(), now, id],
            ).map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        }

        crate::db::audit_repo::insert_policy_change(&tx, &user.user, "policy_update", "notification_policy", &id)
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.commit()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
    }

    Ok(Json(json!({"id": id, "updated": true})))
}

async fn delete_notification_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::DeletePolicy, Resource::PolicyObject).await?;

    let mut conn = state.sqlite.lock().await;
    {
        let tx = conn
            .transaction()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        let changes = tx
            .execute(
                "DELETE FROM notification_policies WHERE id = ?1",
                rusqlite::params![id],
            )
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

        if changes == 0 {
            return Err(crate::api_error::ApiError::not_found(
                "notification policy not found",
            ));
        }

        crate::db::audit_repo::insert_policy_change(&tx, &user.user, "policy_delete", "notification_policy", &id)
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.commit()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
    }

    Ok(Json(json!({"id": id, "deleted": true})))
}
