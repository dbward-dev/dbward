use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use crate::auth;
use crate::authz::{self, Action, Resource};
use crate::state::AppState;

/// Resolve a short or full request ID, returning 404 if not found or ambiguous.
fn resolve_id(conn: &rusqlite::Connection, input: &str) -> Result<String, crate::api_error::ApiError> {
    crate::db::request_repo::resolve_request_id(conn, input)
        .map_err(|_| crate::api_error::ApiError::not_found(format!("request {input} not found")))
}

pub(crate) fn request_resource(
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

pub(crate) fn should_filter_capability(values: &[String]) -> bool {
    !values.is_empty() && !values.iter().any(|v| v == "*")
}

pub(crate) async fn health() -> impl IntoResponse {
    Json(json!({"status": "ok"}))
}

pub(crate) async fn get_public_key(State(state): State<AppState>) -> impl IntoResponse {
    let bytes = state.token_signer.verifying_key().to_bytes();
    (
        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
        bytes.to_vec(),
    )
}

pub(crate) fn parse_pagination(params: &HashMap<String, String>) -> (i64, i64) {
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

pub(crate) async fn list_requests(
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

pub(crate) fn list_requests_pending_for_me(
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
            if !crate::services::request_lifecycle::is_step_satisfied(step, &approvals, i as i64) {
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

pub(crate) fn get_approvals_for_request(
    conn: &rusqlite::Connection,
    request_id: &str,
) -> Result<Vec<(i64, String, String)>, crate::api_error::ApiError> {
    crate::db::request_repo::get_approvals(conn, request_id)
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))
}

pub(crate) fn current_approval_resource(
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
            if !crate::services::request_lifecycle::is_step_satisfied(step, &approvals, i as i64) {
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

pub(crate) async fn create_request(
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

    crate::db::request_repo::insert_request(
        &conn,
        &crate::db::request_repo::NewRequest {
            id: &id,
            created_by: &user.user,
            operation,
            environment,
            database_name,
            detail,
            status,
            emergency,
            reason: reason.as_deref(),
            workflow_id: decision.workflow_id.as_deref(),
            workflow_snapshot_json: decision.workflow_snapshot_json.as_deref(),
        },
        &now,
    )
    .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

    if emergency {
        let token = state
            .token_signer
            .issue(&id, operation, environment, database_name, detail);
        let notif_hooks =
            crate::db::policy_repo::get_notification_webhooks(&conn, database_name, environment);
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
            .and_then(|steps| crate::services::request_lifecycle::compute_next_step(&steps, 0));
        let notif_hooks =
            crate::db::policy_repo::get_notification_webhooks(&conn, database_name, environment);
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

pub(crate) async fn approve_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    body_str: String,
) -> Result<Json<serde_json::Value>, crate::api_error::ApiError> {
    let approver = auth::authenticate(&headers, &state).await?;
    authz::authorize(&approver, Action::ApproveRequest, Resource::Global).await?;
    let id = { let conn = state.sqlite.lock().await; resolve_id(&conn, &id)? };

    let body_val: serde_json::Value = serde_json::from_str(&body_str).unwrap_or(json!({}));

    let result = crate::services::request_lifecycle::approve_request_inner(
        &state.sqlite,
        state.token_signer.as_ref(),
        &id,
        &approver,
        &body_val,
    )
    .await?;

    // Post-transaction async work
    if let Some(event) = result.webhook_event {
        state
            .webhooks
            .dispatch_with_policy(result.notif_hooks, event);
    }
    state.request_notifier.notify(&id).await;

    Ok(Json(result.response))
}

pub(crate) async fn reject_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::RejectRequest, Resource::Global).await?;

    {
        let mut conn = state.sqlite.lock().await;
        let id = resolve_id(&conn, &id)?;

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

        let notif_hooks =
            crate::db::policy_repo::get_notification_webhooks(&conn, &database_name, &environment);
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

pub(crate) async fn get_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::GetRequest, Resource::Global).await?;
    let id = { let conn = state.sqlite.lock().await; resolve_id(&conn, &id)? };
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
                            "satisfied": crate::services::request_lifecycle::is_step_satisfied(step, &simple_approvals, i as i64),
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
                            if !crate::services::request_lifecycle::is_step_satisfied(
                                step, &simple, i as i64,
                            ) {
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

pub(crate) async fn dispatch_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::DispatchRequest, Resource::Global).await?;

    let conn = state.sqlite.lock().await;
    let id = resolve_id(&conn, &id)?;

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
        (
            ctx.created_by,
            ctx.status,
            ctx.database_name,
            ctx.environment,
            ctx.resolved_at,
        )
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
pub(crate) async fn stream_result(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::ReadResult, Resource::Global).await?;

    let (requester, database_name, environment, status): (String, String, String, String) = {
        let conn = state.sqlite.lock().await;
        let id = resolve_id(&conn, &id)?;
        conn.query_row(
            "SELECT created_by, database_name, environment, status FROM requests WHERE id = ?1",
            rusqlite::params![id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| crate::api_error::ApiError::not_found("request not found"))?
    };

    let access_roles = {
        let conn = state.sqlite.lock().await;
        let (_, access_roles) =
            crate::db::policy_repo::get_result_policy(&conn, &database_name, &environment);
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
