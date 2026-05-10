use axum::Json;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use dbward_core::request_status::{self, RequestEvent, RequestStatus};
use serde_json::json;
use std::collections::HashMap;


use tracing::error;

use crate::auth;
use crate::authz::{self, Action, Resource};
use crate::state::AppState;

type ApprovalRecord = (i64, String, String);
type ApprovalMap = HashMap<String, Vec<ApprovalRecord>>;
type RequestRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
    Option<String>,
);

const MAX_METADATA_JSON_BYTES: usize = 8 * 1024;
pub(crate) const MAX_REASON_BYTES: usize = 1024;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 255;

/// Statuses subject to approval expiry.
fn is_expirable_status(status: &str) -> bool {
    matches!(status, "approved" | "auto_approved" | "break_glass")
}

/// Compute expires_at for approved requests based on approval_ttl_secs.
fn compute_expires_at(status: &str, resolved_at: &Option<String>, ttl_secs: u64) -> Option<String> {
    if ttl_secs == 0 {
        return None;
    }
    if !is_expirable_status(status) {
        return None;
    }
    resolved_at.as_ref().and_then(|r| {
        chrono::DateTime::parse_from_rfc3339(r)
            .ok()
            .map(|t| (t + chrono::Duration::seconds(ttl_secs as i64)).to_rfc3339())
    })
}

/// Resolve a short or full request ID, returning appropriate error.
pub(crate) fn resolve_id(
    conn: &rusqlite::Connection,
    input: &str,
) -> Result<String, crate::api_error::ApiError> {
    use crate::db::request_repo::ResolveError;
    crate::db::request_repo::resolve_request_id(conn, input).map_err(|e| match e {
        ResolveError::NotFound => {
            crate::api_error::ApiError::not_found(format!("request {input} not found"))
                .with_code("request_not_found")
        }
        ResolveError::Ambiguous(ids) => crate::api_error::ApiError::conflict(format!(
            "ambiguous short ID '{input}', candidates: {}",
            ids.join(", ")
        ))
        .with_code("request_ambiguous_id"),
        ResolveError::InvalidFormat => {
            crate::api_error::ApiError::bad_request("provide an 8-character short ID or full UUID")
                .with_code("invalid_request_id")
        }
        ResolveError::Db(msg) => crate::api_error::ApiError::internal(msg),
    })
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

/// Extract a human-readable approver summary from workflow_snapshot_json.
fn extract_approver_summary(snapshot_json: Option<&str>) -> Vec<String> {
    let Some(json_str) = snapshot_json else {
        return vec![];
    };
    let steps: Vec<crate::server_config::WorkflowStep> =
        serde_json::from_str(json_str).unwrap_or_default();
    let mut summary = Vec::new();
    for step in &steps {
        for approver in &step.approvers {
            if let Some(ref role) = approver.role {
                summary.push(format!("role:{role} (min:{})", approver.min));
            }
            if let Some(ref group) = approver.group {
                summary.push(format!("group:{group} (min:{})", approver.min));
            }
        }
    }
    summary
}

fn validate_metadata(
    metadata: Option<&serde_json::Value>,
) -> Result<String, crate::api_error::ApiError> {
    let Some(metadata) = metadata else {
        return Ok("{}".into());
    };

    if !metadata.is_object() {
        return Err(
            crate::api_error::ApiError::bad_request("metadata must be a JSON object")
                .with_code("invalid_metadata"),
        );
    }

    let metadata_json = serde_json::to_string(metadata)?;
    if metadata_json.len() > MAX_METADATA_JSON_BYTES {
        return Err(crate::api_error::ApiError::bad_request(format!(
            "metadata must be at most {MAX_METADATA_JSON_BYTES} bytes"
        ))
        .with_code("metadata_too_large"));
    }

    Ok(metadata_json)
}

fn validate_text_field(
    value: Option<&str>,
    field_name: &str,
    max_bytes: usize,
) -> Result<Option<String>, crate::api_error::ApiError> {
    let Some(v) = value else { return Ok(None) };
    let trimmed = v.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.len() > max_bytes {
        return Err(crate::api_error::ApiError::bad_request(format!(
            "{field_name} must be at most {max_bytes} bytes",
        ))
        .with_code(&format!("{field_name}_too_long")));
    }
    Ok(Some(trimmed.to_string()))
}

fn validate_idempotency_key(
    raw: Option<&serde_json::Value>,
) -> Result<Option<String>, crate::api_error::ApiError> {
    let Some(value) = raw else {
        return Ok(None);
    };

    let key = value
        .as_str()
        .ok_or_else(|| {
            crate::api_error::ApiError::bad_request("idempotency_key must be a string")
                .with_code("invalid_idempotency_key")
        })?
        .trim();

    if key.is_empty() {
        return Err(
            crate::api_error::ApiError::bad_request("idempotency_key must not be empty")
                .with_code("invalid_idempotency_key"),
        );
    }
    if key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
        return Err(crate::api_error::ApiError::bad_request(format!(
            "idempotency_key must be at most {MAX_IDEMPOTENCY_KEY_BYTES} bytes"
        ))
        .with_code("idempotency_key_too_large"));
    }

    Ok(Some(key.to_string()))
}

fn is_unique_idempotency_key_violation(err: &rusqlite::Error) -> bool {
    match err {
        rusqlite::Error::SqliteFailure(inner, _)
            if inner.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            inner.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
        }
        _ => false,
    }
}

pub(crate) async fn ensure_result_slot(state: &AppState, request_id: &str) {
    state.result_channels.get_or_insert(request_id).await;
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
    authz::authorize_and_audit(&user, Action::ListRequests, Resource::Global, &state).await?;
    let (limit, offset) = parse_pagination(&params);
    let status_filter = params.get("status").filter(|s| !s.is_empty());
    let database_filter = params.get("database").filter(|s| !s.is_empty());
    let environment_filter = params.get("environment").filter(|s| !s.is_empty());
    let user_filter = params.get("user").filter(|s| !s.is_empty());
    let pending_for_me = params
        .get("pending_for_me")
        .map(|v| v == "true")
        .unwrap_or(false);

    let conn = state.db().await;

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
    if let Some(u) = user_filter {
        bind_values.push(u.clone());
        where_clauses.push(format!("created_by = ?{}", bind_values.len()));
    }

    let where_sql = if where_clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", where_clauses.join(" AND "))
    };

    let query_sql = format!(
        "SELECT id, created_by, operation, environment, database_name, detail, status, emergency, created_at, updated_at, resolved_at, reason, workflow_snapshot_json FROM requests {where_sql} ORDER BY created_at DESC",
    );
    let mut stmt = conn.prepare(&query_sql)?;

    let candidates: Vec<(serde_json::Value, String, Option<String>)> = stmt
        .query_map(rusqlite::params_from_iter(&bind_values), |row| {
            let created_by: String = row.get(1)?;
            let workflow_snapshot_json: Option<String> = row.get(12)?;
            Ok((
                json!({
                    "id": row.get::<_, String>(0)?,
                    "created_by": created_by,
                    "operation": row.get::<_, String>(2)?,
                    "environment": row.get::<_, String>(3)?,
                    "database": row.get::<_, String>(4)?,
                    "detail": row.get::<_, String>(5)?,
                    "status": row.get::<_, String>(6)?,
                    "emergency": row.get::<_, bool>(7)?,
                    "created_at": row.get::<_, String>(8)?,
                    "updated_at": row.get::<_, String>(9)?,
                    "resolved_at": row.get::<_, Option<String>>(10)?,
                    "reason": row.get::<_, Option<String>>(11)?,
                }),
                created_by,
                workflow_snapshot_json,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let all_approvals = load_pending_request_approvals(&conn)?;
    let mut filtered = Vec::new();
    for (row, created_by, workflow_snapshot_json) in &candidates {
        let resource = request_resource(
            row["created_by"].as_str().unwrap_or("").to_string(),
            row["status"].as_str().unwrap_or("").to_string(),
            row["database"].as_str().unwrap_or("").to_string(),
            row["environment"].as_str().unwrap_or("").to_string(),
        );
        if authz::authorize_sync(&user, Action::ListRequests, resource).is_ok() {
            filtered.push(row.clone());
            continue;
        }
        if row["status"].as_str() != Some("pending") {
            continue;
        }

        if request_is_approvable_by_user(
            &all_approvals,
            row,
            created_by,
            workflow_snapshot_json.as_deref(),
            &user,
        ) {
            filtered.push(row.clone());
        }
    }

    let total = filtered.len() as i64;
    let start = (offset as usize).min(filtered.len());
    let end = (start + limit as usize).min(filtered.len());
    let page = filtered[start..end].to_vec();
    let page: Vec<serde_json::Value> = page
        .into_iter()
        .map(|mut r| {
            if let Some(obj) = r.as_object_mut() {
                let status = obj.get("status").and_then(|s| s.as_str()).unwrap_or("");
                let resolved = obj
                    .get("resolved_at")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                obj.insert(
                    "expires_at".into(),
                    compute_expires_at(status, &resolved, state.retention.approval_ttl_secs)
                        .map_or(serde_json::Value::Null, Into::into),
                );
            }
            r
        })
        .collect();
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
        ?;

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
                    "database": row.get::<_, String>(4)?,
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
        })?
        .collect::<Result<Vec<_>, _>>()?;

    // Batch-load all approvals for pending requests (eliminates N+1)
    let all_approvals = load_pending_request_approvals(conn)?;

    let mut filtered: Vec<serde_json::Value> = Vec::new();
    for (row, created_by, ws_json) in &candidates {
        if request_is_approvable_by_user(&all_approvals, row, created_by, ws_json.as_deref(), user)
        {
            filtered.push(row.clone());
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

fn load_pending_request_approvals(
    conn: &rusqlite::Connection,
) -> Result<ApprovalMap, crate::api_error::ApiError> {
    let mut stmt = conn
        .prepare("SELECT request_id, step_index, actor_id, actor_role FROM approvals WHERE action = 'approve' AND request_id IN (SELECT id FROM requests WHERE status = 'pending')")
        ?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut map: ApprovalMap = HashMap::new();
    for (req_id, step, actor, role) in rows {
        map.entry(req_id).or_default().push((step, actor, role));
    }
    Ok(map)
}

fn request_is_approvable_by_user(
    all_approvals: &ApprovalMap,
    row: &serde_json::Value,
    created_by: &str,
    workflow_snapshot_json: Option<&str>,
    user: &crate::state::AuthUser,
) -> bool {
    let req_id = row["id"].as_str().unwrap_or("");
    let approvals = all_approvals.get(req_id).cloned().unwrap_or_default();

    let steps: Vec<crate::server_config::WorkflowStep> = workflow_snapshot_json
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();

    let current_step_idx = steps.iter().enumerate().find_map(|(i, step)| {
        if !crate::services::request_lifecycle::is_step_satisfied(step, &approvals, i as i64) {
            Some(i)
        } else {
            None
        }
    });

    let (allowed_roles, allowed_groups) = current_step_idx
        .and_then(|i| steps.get(i))
        .map(crate::services::request_lifecycle::step_allowed_roles_groups)
        .unwrap_or_default();

    // TODO(v0.1.1): read allow_self_approve from workflow to show self-approvable requests
    let approval_resource = authz::Resource::ApprovalStep {
        requester_id: created_by.to_string(),
        allowed_roles,
        allowed_groups,
        allow_self_approve: false,
    };

    if authz::authorize_sync(user, Action::ApproveRequest, approval_resource).is_err() {
        return false;
    }

    if let Some(idx) = current_step_idx {
        let step = match steps.get(idx) {
            Some(step) => step,
            None => return false,
        };
        if step.require_distinct_actors {
            !approvals
                .iter()
                .any(|(si, aid, _)| *si == idx as i64 && aid == &user.user)
        } else {
            true
        }
    } else {
        steps.is_empty()
    }
}

pub(crate) fn get_approvals_for_request(
    conn: &rusqlite::Connection,
    request_id: &str,
) -> Result<Vec<(i64, String, String)>, crate::api_error::ApiError> {
    Ok(crate::db::request_repo::get_approvals(conn, request_id)?)
}

pub(crate) fn current_approval_resource(
    conn: &rusqlite::Connection,
    request_id: &str,
    requester_id: String,
    workflow_snapshot_json: Option<&str>,
) -> Result<(Resource, usize, Vec<String>, usize), crate::api_error::ApiError> {
    current_approval_resource_with_workflow(
        conn,
        request_id,
        requester_id,
        workflow_snapshot_json,
        None,
    )
}

pub(crate) fn current_approval_resource_with_workflow(
    conn: &rusqlite::Connection,
    request_id: &str,
    requester_id: String,
    workflow_snapshot_json: Option<&str>,
    workflow_id: Option<&str>,
) -> Result<(Resource, usize, Vec<String>, usize), crate::api_error::ApiError> {
    let allow_self_approve = workflow_id
        .and_then(|wf_id| {
            conn.query_row(
                "SELECT allow_self_approve FROM workflows WHERE id = ?1",
                rusqlite::params![wf_id],
                |row| row.get::<_, bool>(0),
            )
            .ok()
        })
        .unwrap_or(false);

    let steps: Vec<crate::server_config::WorkflowStep> = workflow_snapshot_json
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();

    if steps.is_empty() {
        return Ok((
            Resource::ApprovalStep {
                requester_id,
                allowed_roles: Vec::new(),
                allowed_groups: vec![],
                allow_self_approve,
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

    let (allowed_roles, allowed_groups) = steps
        .get(current_step)
        .map(crate::services::request_lifecycle::step_allowed_roles_groups)
        .unwrap_or_default();
    let allowed_labels: Vec<String> = allowed_roles
        .iter()
        .map(|role| format!("role:{role}"))
        .chain(allowed_groups.iter().map(|group| format!("group:{group}")))
        .collect();

    Ok((
        Resource::ApprovalStep {
            requester_id,
            allowed_roles: allowed_roles.clone(),
            allowed_groups: allowed_groups.clone(),
            allow_self_approve,
        },
        current_step,
        allowed_labels,
        steps.len(),
    ))
}

pub(crate) async fn create_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    if state.draining.load(std::sync::atomic::Ordering::Relaxed) {
        return Err(crate::api_error::ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "server is shutting down",
        )
        .with_code("server_shutting_down"));
    }
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize_and_audit(&user, Action::CreateRequest, Resource::Global, &state).await?;

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
        ))
        .with_code("unknown_operation"));
    }

    let environment = body["environment"]
        .as_str()
        .ok_or((StatusCode::BAD_REQUEST, "environment required".into()))?;
    let detail = body["detail"].as_str().unwrap_or("");
    let database_name = body["database"].as_str().unwrap_or("default");

    // Validate database+environment against registry
    {
        let conn = state.db().await;
        if !crate::db::database_repo::database_exists(&conn, database_name, environment) {
            return Err(crate::api_error::ApiError::bad_request(format!(
                "database '{database_name}' is not registered for environment '{environment}'"
            ))
            .with_code("database_not_registered")
            .with_hint("Run `dbward databases` to see available databases"));
        }
    }

    // Validate detail size (5MB limit)
    if detail.len() > 5 * 1024 * 1024 {
        return Err(crate::api_error::ApiError::bad_request("detail exceeds 5MB limit")
            .with_code("detail_too_large"));
    }

    match operation {
        "execute_query" if detail.trim().is_empty() => {
            return Err(crate::api_error::ApiError::bad_request(
                "detail (SQL) is required for execute_query",
            )
            .with_code("detail_required"));
        }
        "migrate_up" | "migrate_down" if detail.trim().is_empty() => {
            return Err(crate::api_error::ApiError::bad_request(
                "migration detail must not be empty",
            )
            .with_code("detail_required"));
        }
        _ => {}
    }
    let emergency = body["emergency"].as_bool().unwrap_or(false);
    let reason = validate_text_field(body["reason"].as_str(), "reason", MAX_REASON_BYTES)?;
    let share_with_json: Option<String> = body["share_with"]
        .as_array()
        .map(|arr| serde_json::to_string(arr).unwrap_or_default());
    if share_with_json.is_some() {
        crate::limits::require_pro("Result sharing (share-with)", &state.license)?;
    }
    let no_store = body["no_store"].as_bool().unwrap_or(false);
    let metadata_json = validate_metadata(body.get("metadata"))?;
    let idempotency_key = validate_idempotency_key(body.get("idempotency_key"))?;

    authz::authorize_and_audit(
        &user,
        Action::CreateRequest,
        request_resource(
            user.user.clone(),
            "new".into(),
            database_name.into(),
            environment.into(),
        ),
        &state,
    )
    .await?;

    if emergency && reason.is_none() {
        return Err(crate::api_error::ApiError::bad_request(
            "reason is required for emergency requests",
        )
        .with_code("emergency_reason_required"));
    }
    // Break-glass role check (configurable via auth.break_glass_roles)
    if emergency && !state.break_glass_roles.iter().any(|r| user.has_role(r)) {
        return Err(crate::api_error::ApiError::forbidden(
            "insufficient permissions for break-glass",
        )
        .with_code("break_glass_forbidden"));
    }

    // Approver-only roles cannot create requests
    if user.effective_permission() == dbward_core::role::APPROVER {
        return Err(crate::api_error::ApiError::forbidden(
            "approver-only roles cannot create requests",
        )
        .with_code("approver_cannot_create_request"));
    }

    // Check access policy (DB-level access control)
    let mut conn = state.db().await;
    if let Err(e) = crate::db::policy_repo::check_access_policy(
        &conn,
        database_name,
        environment,
        &user,
        &state.license,
    ) {
        let meta = serde_json::json!({
            "policy_type": "access",
            "database": database_name,
            "environment": environment,
        })
        .to_string();
        let _ = crate::db::audit_event_repo::record_audit_event(
            &mut conn,
            crate::db::audit_event_repo::AuditEvent {
                event_type: "authz_denied",
                event_category: "auth",
                outcome: "denied",
                actor_id: &user.user,
                actor_type: "user",
                resource_type: Some("request"),
                resource_id: None,
                peer_ip: None,
                client_ip: None,
                client_ip_source: None,
                request_id: None,
                operation: Some(operation),
                environment: Some(environment),
                database_name: Some(database_name),
                detail_fingerprint: None,
                detail_raw: None,
                reason: None,
                metadata_json: &meta,
            },
            &headers,
            &state.audit_config,
            &state.trusted_proxies,
        );
        return Err(e);
    }

    // Evaluate workflow policy
    let decision = crate::db::policy_repo::evaluate_approval_policy(
        &conn,
        database_name,
        environment,
        operation,
    )
    .map_err(|e| {
        error!(error = %e, "workflow policy evaluation failed");
        crate::api_error::ApiError::internal(
            "workflow policy evaluation failed. Check server logs for details.",
        )
        .with_code("workflow_eval_failed")
    })?;

    if !emergency && decision.require_reason && reason.as_ref().is_none_or(|r| r.is_empty()) {
        return Err(crate::api_error::ApiError::bad_request(
            "reason is required by workflow policy",
        )
        .with_code("workflow_reason_required"));
    }

    let needs_approval = !emergency && decision.needs_approval;

    // Idempotency check
    if let Some(ref key) = idempotency_key {
        if let Ok(Some(existing)) = crate::db::request_repo::find_by_idempotency_key(&conn, key) {
            return Ok((
                StatusCode::OK,
                axum::Json(serde_json::json!({
                    "id": existing.id,
                    "status": existing.status,
                    "idempotent": true,
                })),
            ));
        }
    }

    let status = if emergency {
        "break_glass"
    } else if needs_approval {
        "pending"
    } else {
        "auto_approved"
    };

    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    conn.execute_batch("BEGIN")?;
    match crate::db::request_repo::insert_request(
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
            metadata_json: &metadata_json,
            idempotency_key: idempotency_key.as_deref(),
            workflow_id: decision.workflow_id.as_deref(),
            workflow_snapshot_json: decision.workflow_snapshot_json.as_deref(),
            share_with_json: share_with_json.as_deref(),
            no_store,
        },
        &now,
    ) {
        Ok(()) => {}
        Err(err) if is_unique_idempotency_key_violation(&err) => {
            let _ = conn.execute_batch("ROLLBACK");
            if let Some(ref key) = idempotency_key
                && let Some(existing) =
                    crate::db::request_repo::find_by_idempotency_key(&conn, key)?
            {
                return Ok((
                    StatusCode::OK,
                    axum::Json(serde_json::json!({
                        "id": existing.id,
                        "status": existing.status,
                        "idempotent": true,
                    })),
                ));
            }
            return Err(
                crate::api_error::ApiError::conflict("idempotency key already exists")
                    .with_code("duplicate_idempotency_key"),
            );
        }
        Err(err) => {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(crate::api_error::ApiError::internal(err.to_string()));
        }
    }

    if status == "auto_approved" || emergency {
        crate::db::request_repo::mark_dispatched(&conn, &id, &now)?;
    }
    conn.execute_batch("COMMIT")?;

    state
        .metrics
        .record_request_created(status, environment, database_name);

    // Audit: request_created + auto_approved/break_glass
    {
        let event_type = if emergency {
            "break_glass"
        } else if !needs_approval {
            "auto_approved"
        } else {
            "request_created"
        };
        let outcome = if needs_approval { "info" } else { "success" };
        let meta = serde_json::json!({
            "emergency": emergency,
            "workflow_id": decision.workflow_id,
        });
        if let Err(e) = crate::db::audit_event_repo::record_audit_event(
            &mut conn,
            crate::db::audit_event_repo::AuditEvent {
                event_type,
                event_category: "approval",
                outcome,
                actor_id: &user.user,
                actor_type: "user",
                resource_type: Some("request"),
                resource_id: Some(&id),
                peer_ip: None,
                client_ip: None,
                client_ip_source: None,
                request_id: Some(&id),
                operation: Some(operation),
                environment: Some(environment),
                database_name: Some(database_name),
                detail_fingerprint: None,
                detail_raw: Some(detail),
                reason: reason.as_deref(),
                metadata_json: &meta.to_string(),
            },
            &headers,
            &state.audit_config,
            &state.trusted_proxies,
        ) {
            error!(error = %e, "audit write failed");
        }
    }

    if emergency {
        state.metrics.record_break_glass();
        let token = state
            .token_signer
            .issue(&id, operation, environment, database_name, detail, user.effective_permission(), &user.user);
        let notif_hooks =
            crate::db::policy_repo::get_notification_webhooks(&conn, database_name, environment);
        drop(conn);
        state.webhooks.read().unwrap().dispatch_with_policy(
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
                cli_command: Some(format!("dbward request resume {id}")),
            },
            state.metrics.clone(),
        );
        ensure_result_slot(&state, &id).await;
        state.request_notifier.notify(&id).await;
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
        state.webhooks.read().unwrap().dispatch_with_policy(
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
                cli_command: Some(format!("dbward request approve {id}")),
            },
            state.metrics.clone(),
        );
        Ok((
            StatusCode::CREATED,
            Json(json!({
                "id": id,
                "status": "pending",
                "approvers": extract_approver_summary(decision.workflow_snapshot_json.as_deref()),
            })),
        ))
    } else {
        let token = state
            .token_signer
            .issue(&id, operation, environment, database_name, detail, user.effective_permission(), &user.user);
        let notif_hooks =
            crate::db::policy_repo::get_notification_webhooks(&conn, database_name, environment);
        drop(conn);
        state.webhooks.read().unwrap().dispatch_with_policy(
            notif_hooks,
            crate::webhook::WebhookEvent {
                event: "request_auto_approved".into(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                request_id: id.clone(),
                status: "dispatched".into(),
                requester: user.user.clone(),
                actor: user.user.clone(),
                actor_role: Some(user.effective_permission().into()),
                operation: operation.into(),
                environment: environment.into(),
                detail: detail.into(),
                database: database_name.into(),
                reason: reason.clone(),
                next_step: None,
                cli_command: Some(format!("dbward request resume {id}")),
            },
            state.metrics.clone(),
        );
        ensure_result_slot(&state, &id).await;
        state.request_notifier.notify(&id).await;
        Ok((
            StatusCode::CREATED,
            Json(json!({"id": id, "status": "dispatched", "execution_token": token})),
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
    authz::authorize_and_audit(&approver, Action::ApproveRequest, Resource::Global, &state).await?;
    let id = {
        let conn = state.db().await;
        resolve_id(&conn, &id)?
    };

    let body_val: serde_json::Value = serde_json::from_str(&body_str).unwrap_or(json!({}));

    let result = crate::services::request_lifecycle::approve_request_inner(
        &state.sqlite,
        state.token_signer.as_ref(),
        &id,
        &approver,
        &body_val,
    )
    .await?;
    state.metrics.record_approval("approve");

    // Audit: request_approved
    {
        let mut conn = state.db().await;
        let meta = serde_json::json!({
            "step_completed": result.response["step_completed"],
            "total_steps": result.response["total_steps"],
        });
        if let Err(e) = crate::db::audit_event_repo::record_audit_event(
            &mut conn,
            crate::db::audit_event_repo::AuditEvent {
                event_type: "request_approved",
                event_category: "approval",
                outcome: "success",
                actor_id: &approver.user,
                actor_type: "user",
                resource_type: Some("request"),
                resource_id: Some(&id),
                peer_ip: None,
                client_ip: None,
                client_ip_source: None,
                request_id: Some(&id),
                operation: None,
                environment: None,
                database_name: None,
                detail_fingerprint: None,
                detail_raw: None,
                reason: body_val["comment"].as_str(),
                metadata_json: &meta.to_string(),
            },
            &headers,
            &state.audit_config,
            &state.trusted_proxies,
        ) {
            error!(error = %e, "audit write failed");
        }
    }

    // Post-transaction async work
    if result.response["status"].as_str() == Some("dispatched") {
        ensure_result_slot(&state, &id).await;
    }
    if let Some(event) = result.webhook_event {
        state.webhooks.read().unwrap().dispatch_with_policy(
            result.notif_hooks,
            event,
            state.metrics.clone(),
        );
    }
    state.request_notifier.notify(&id).await;

    Ok(Json(result.response))
}

pub(crate) async fn reject_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    body_str: String,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize_and_audit(&user, Action::RejectRequest, Resource::Global, &state).await?;
    let body_val: serde_json::Value = serde_json::from_str(&body_str).unwrap_or(json!({}));
    if let Some(c) = body_val.get("comment").and_then(|v| v.as_str()) {
        if c.len() > MAX_REASON_BYTES {
            return Err(crate::api_error::ApiError::bad_request(
                "comment must be at most 1024 bytes",
            )
            .with_code("comment_too_long"));
        }
    }
    let comment = body_val
        .get("comment")
        .and_then(|v| v.as_str())
        .filter(|v| !v.is_empty());

    let id = {
        let mut conn = state.db().await;
        let id = resolve_id(&conn, &id)?;

        let ctx = crate::db::request_repo::get_request_context(&conn, &id)
            .map_err(|_| crate::api_error::ApiError::not_found("request not found"))?;
        let req_user = ctx.created_by.clone();
        let status = ctx.status.clone();
        let database_name = ctx.database_name.clone();
        let environment = ctx.environment.clone();

        let current = RequestStatus::parse(&status).ok_or_else(|| {
            crate::api_error::ApiError::internal(format!("unknown status: {status}"))
        })?;
        request_status::transition(current, &RequestEvent::Reject).map_err(|_| {
            crate::api_error::ApiError::conflict(format!("request is already {status}"))
                .with_code("request_reject_wrong_status")
        })?;

        let workflow_snapshot_json = ctx.workflow_snapshot_json.clone();
        let (approval_resource, step_idx, step_roles, total_steps) = current_approval_resource(
            &conn,
            &id,
            req_user.clone(),
            workflow_snapshot_json.as_deref(),
        )?;
        if authz::authorize_with_audit(&user, Action::RejectRequest, approval_resource, &mut conn)
            .is_err()
        {
            let roles_str = step_roles.join(", ");
            return Err(crate::api_error::ApiError::forbidden(format!(
                "you are not an approver for the current step (step {}/{}: {})",
                step_idx + 1,
                total_steps,
                roles_str
            ))
            .with_code("not_current_step_approver"));
        }

        let now = chrono::Utc::now().to_rfc3339();
        let tx = conn.transaction()?;
        crate::db::request_repo::mark_rejected(&tx, &id, &now)?;
        crate::db::request_repo::insert_approval(
            &tx,
            &id,
            "reject",
            &user.user,
            step_idx as i64,
            user.effective_permission(),
            comment,
            &now,
        )?;
        tx.commit()?;
        state.metrics.record_approval("reject");

        // Audit: request_rejected
        if let Err(e) = crate::db::audit_event_repo::record_audit_event(
            &mut conn,
            crate::db::audit_event_repo::AuditEvent {
                event_type: "request_rejected",
                event_category: "approval",
                outcome: "success",
                actor_id: &user.user,
                actor_type: "user",
                resource_type: Some("request"),
                resource_id: Some(&id),
                peer_ip: None,
                client_ip: None,
                client_ip_source: None,
                request_id: Some(&id),
                operation: None,
                environment: Some(&environment),
                database_name: Some(&database_name),
                detail_fingerprint: None,
                detail_raw: None,
                reason: comment,
                metadata_json: "{}",
            },
            &headers,
            &state.audit_config,
            &state.trusted_proxies,
        ) {
            error!(error = %e, "audit write failed");
        }

        let notif_hooks =
            crate::db::policy_repo::get_notification_webhooks(&conn, &database_name, &environment);
        state.webhooks.read().unwrap().dispatch_with_policy(
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
                environment: environment.clone(),
                database: database_name.clone(),
                detail: "".into(),
                reason: None,
                next_step: None,
                cli_command: None,
            },
            state.metrics.clone(),
        );
        id
    };

    state.request_notifier.notify(&id).await;

    Ok(Json(
        serde_json::to_value(dbward_api_types::requests::StatusResponse {
            id,
            status: RequestStatus::Rejected,
        })
        .unwrap(),
    ))
}

pub(crate) async fn cancel_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    body_str: String,
) -> Result<Json<serde_json::Value>, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize_and_audit(&user, Action::CancelRequest, Resource::Global, &state).await?;

    let body_val: serde_json::Value = serde_json::from_str(&body_str).unwrap_or(json!({}));
    let cancel_reason = validate_text_field(body_val["reason"].as_str(), "reason", MAX_REASON_BYTES)?;

    let (id, requester, operation, environment, database_name, detail, notif_hooks) = {
        let mut conn = state.db().await;
        let id = resolve_id(&conn, &id)?;
        let ctx = crate::db::request_repo::get_request_context(&conn, &id)
            .map_err(|_| crate::api_error::ApiError::not_found("request not found"))?;

        authz::authorize_with_audit(
            &user,
            Action::CancelRequest,
            request_resource(
                ctx.created_by.clone(),
                ctx.status.clone(),
                ctx.database_name.clone(),
                ctx.environment.clone(),
            ),
            &mut conn,
        )?;

        let current = RequestStatus::parse(&ctx.status).ok_or_else(|| {
            crate::api_error::ApiError::internal(format!("unknown status: {}", ctx.status))
        })?;
        request_status::transition(current, &RequestEvent::Cancel).map_err(|_| {
            crate::api_error::ApiError::conflict(format!("request is already {}", ctx.status))
        })?;

        let now = chrono::Utc::now().to_rfc3339();
        let updated = crate::db::request_repo::mark_cancelled(
            &conn,
            &id,
            &user.user,
            cancel_reason.as_deref(),
            &now,
        )?;
        if !updated {
            return Err(crate::api_error::ApiError::conflict(
                "request cannot be cancelled",
            ));
        }

        // Audit: request_cancelled
        if let Err(e) = crate::db::audit_event_repo::record_audit_event(
            &mut conn,
            crate::db::audit_event_repo::AuditEvent {
                event_type: "request_cancelled",
                event_category: "approval",
                outcome: "success",
                actor_id: &user.user,
                actor_type: "user",
                resource_type: Some("request"),
                resource_id: Some(&id),
                peer_ip: None,
                client_ip: None,
                client_ip_source: None,
                request_id: Some(&id),
                operation: Some(&ctx.operation),
                environment: Some(&ctx.environment),
                database_name: Some(&ctx.database_name),
                detail_fingerprint: None,
                detail_raw: None,
                reason: cancel_reason.as_deref(),
                metadata_json: "{}",
            },
            &headers,
            &state.audit_config,
            &state.trusted_proxies,
        ) {
            error!(error = %e, "audit write failed");
        }

        let notif_hooks = crate::db::policy_repo::get_notification_webhooks(
            &conn,
            &ctx.database_name,
            &ctx.environment,
        );
        (
            id,
            ctx.created_by,
            ctx.operation,
            ctx.environment,
            ctx.database_name,
            ctx.detail,
            notif_hooks,
        )
    };

    state.request_notifier.notify(&id).await;
    let actor_role = user.effective_permission().to_string();
    state.webhooks.read().unwrap().dispatch_with_policy(
        notif_hooks,
        crate::webhook::WebhookEvent {
            event: "request_cancelled".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            request_id: id.clone(),
            status: "cancelled".into(),
            requester,
            actor: user.user,
            actor_role: Some(actor_role),
            operation,
            environment,
            database: database_name,
            detail,
            reason: cancel_reason,
            next_step: None,
            cli_command: None,
        },
        state.metrics.clone(),
    );

    Ok(Json(
        serde_json::to_value(dbward_api_types::requests::StatusResponse {
            id,
            status: RequestStatus::Cancelled,
        })
        .unwrap(),
    ))
}

pub(crate) async fn get_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize_and_audit(&user, Action::GetRequest, Resource::Global, &state).await?;
    let id = {
        let conn = state.db().await;
        resolve_id(&conn, &id)?
    };
    let wait: u64 = params
        .get("wait")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
        .min(60);

    let build_response = |conn: &rusqlite::Connection,
                          id: &str,
                          state: &AppState|
     -> Result<serde_json::Value, crate::api_error::ApiError> {
        let (id_val, created_by, operation, environment, database_name, detail, status, created_at, updated_at, resolved_at, workflow_snapshot_json, reason, metadata_json, idempotency_key): RequestRow = conn
            .query_row(
                "SELECT id, created_by, operation, environment, database_name, detail, status, created_at, updated_at, resolved_at, workflow_snapshot_json, reason, metadata_json, idempotency_key FROM requests WHERE id = ?1",
                rusqlite::params![id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?, row.get(10)?, row.get(11)?, row.get(12)?, row.get(13)?)),
            )
            .map_err(|_| crate::api_error::ApiError::not_found("request not found"))?;

        let metadata = serde_json::from_str::<serde_json::Value>(&metadata_json)
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

        let mut resp = json!({
            "id": id_val, "created_by": created_by, "operation": operation,
            "environment": environment, "database": database_name, "detail": detail, "status": status,
            "created_at": created_at, "updated_at": updated_at, "resolved_at": resolved_at,
            "reason": reason,
            "metadata": metadata,
            "idempotency_key": idempotency_key,
            "expires_at": compute_expires_at(&status, &resolved_at, state.retention.approval_ttl_secs),
        });

        if status == "approved" || status == "auto_approved" || status == "break_glass" {
            let created_by_role = crate::db::user_repo::get_user(conn, "user", &created_by)
                .ok()
                .flatten()
                .map(|u| u.role)
                .unwrap_or_else(|| "readonly".to_string());
            let token =
                state
                    .token_signer
                    .issue(id, &operation, &environment, &database_name, &detail, &created_by_role, &created_by);
            resp["execution_token"] = serde_json::to_value(token)?;
        }

        // Include approval_progress when workflow snapshot exists
        if let Some(ref snapshot) = workflow_snapshot_json
            && let Ok(steps) =
                serde_json::from_str::<Vec<crate::server_config::WorkflowStep>>(snapshot)
            && !steps.is_empty()
        {
            let approvals: Vec<(i64, String, String, String, Option<String>, String)> = conn
                .prepare("SELECT step_index, actor_id, actor_role, created_at, comment, action FROM approvals WHERE request_id = ?1")
                ?
                .query_map(rusqlite::params![id], |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                })
                ?
                .collect::<Result<Vec<_>, _>>()
                ?;

            let step_views: Vec<serde_json::Value> = steps.iter().enumerate().map(|(i, step)| {
                        let step_apprs: Vec<serde_json::Value> = approvals.iter()
                            .filter(|(si, _, _, _, _, _)| *si == i as i64)
                            .map(|(_, user, role, at, comment, action)| json!({"user": user, "role": role, "at": at, "comment": comment, "action": action}))
                            .collect();
                        let simple_approvals: Vec<(i64, String, String)> = approvals.iter()
                            .filter(|(_, _, _, _, _, action)| action == "approve")
                            .map(|(si, uid, role, _, _, _)| (*si, uid.clone(), role.clone()))
                            .collect();
                        json!({
                            "index": i,
                            "mode": step.mode,
                            "satisfied": crate::services::request_lifecycle::is_step_satisfied(step, &simple_approvals, i as i64),
                            "approvers_required": step.approvers.iter().map(|g| json!({"role": g.role, "group": g.group, "min": g.min})).collect::<Vec<_>>(),
                            "approvals": step_apprs,
                        })
                    }).collect();

            let current = steps
                .iter()
                .enumerate()
                .find_map(|(i, step)| {
                    let simple: Vec<(i64, String, String)> = approvals
                        .iter()
                        .filter(|(_, _, _, _, _, action)| action == "approve")
                        .map(|(si, uid, role, _, _, _)| (*si, uid.clone(), role.clone()))
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

        // B5: Include error_message for failed/execution_lost requests
        if status == "failed" || status == "execution_lost" {
            let err_msg: Option<String> = conn
                .query_row(
                    "SELECT error_message FROM agent_executions WHERE request_id = ?1 ORDER BY created_at DESC LIMIT 1",
                    rusqlite::params![id],
                    |row| row.get(0),
                )
                .unwrap_or(None);
            if err_msg.is_some() {
                resp["error_message"] = json!(err_msg);
            }
        }

        // Include claimed_by (agent_id) for running requests
        if status == "running" {
            let agent_id: Option<String> = conn
                .query_row(
                    "SELECT agent_id FROM agent_executions WHERE request_id = ?1 ORDER BY created_at DESC LIMIT 1",
                    rusqlite::params![id],
                    |row| row.get(0),
                )
                .unwrap_or(None);
            if agent_id.is_some() {
                resp["claimed_by"] = json!(agent_id);
            }
        }

        // B22: Include reject reason for rejected requests
        if status == "rejected" {
            let reject_comment: Option<String> = conn
                .query_row(
                    "SELECT comment FROM approvals WHERE request_id = ?1 AND action = 'reject' ORDER BY created_at DESC LIMIT 1",
                    rusqlite::params![id],
                    |row| row.get(0),
                )
                .unwrap_or(None);
            if reject_comment.is_some() {
                resp["reject_reason"] = json!(reject_comment);
            }
        }

        Ok(resp)
    };

    // First read
    let (resp, status) = {
        let mut conn = state.db().await;
        let resp = build_response(&conn, &id, &state)?;
        let request_resource = request_resource(
            resp["created_by"].as_str().unwrap_or("").to_string(),
            resp["status"].as_str().unwrap_or("").to_string(),
            resp["database"].as_str().unwrap_or("").to_string(),
            resp["environment"].as_str().unwrap_or("").to_string(),
        );
        if authz::authorize_with_audit(&user, Action::GetRequest, request_resource, &mut conn)
            .is_err()
        {
            let ctx = crate::db::request_repo::get_request_context(&conn, &id)
                .map_err(|_| crate::api_error::ApiError::not_found("request not found"))?;
            let (approval_resource, _, _, _) = current_approval_resource(
                &conn,
                &id,
                ctx.created_by,
                ctx.workflow_snapshot_json.as_deref(),
            )?;
            authz::authorize_with_audit(&user, Action::GetRequest, approval_resource, &mut conn)?;
        }
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
        let conn = state.db().await;
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
    authz::authorize_and_audit(&user, Action::DispatchRequest, Resource::Global, &state).await?;

    let mut conn = state.db().await;
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

    authz::authorize_with_audit(
        &user,
        Action::DispatchRequest,
        request_resource(
            requester.clone(),
            status.clone(),
            database_name.clone(),
            environment.clone(),
        ),
        &mut conn,
    )?;

    // Check approval expiry
    if is_expirable_status(&status) {
        let ttl = state.retention.approval_ttl_secs;
        if ttl > 0 {
            match resolved_at {
                Some(ref resolved) => {
                    if let Ok(resolved_time) = chrono::DateTime::parse_from_rfc3339(resolved) {
                        let elapsed = chrono::Utc::now().signed_duration_since(resolved_time);
                        if elapsed.num_seconds() > 0 && elapsed.num_seconds() as u64 > ttl {
                            return Err(crate::api_error::ApiError::new(
                                StatusCode::GONE,
                                "approval has expired; please re-submit the request",
                            )
                            .with_code("approval_expired"));
                        }
                    }
                }
                None => {
                    return Err(crate::api_error::ApiError::internal(
                        "approved request has no resolved_at timestamp",
                    ));
                }
            }
        }
    }

    // For executed/failed/execution_lost: check re-execution policy
    if status == "executed" || status == "failed" || status == "execution_lost" {
        let (max_exec, window_secs, retry) =
            crate::db::policy_repo::get_execution_policy(&conn, &database_name, &environment);

        if let Some(ref resolved) = resolved_at
            && let Ok(resolved_time) = chrono::DateTime::parse_from_rfc3339(resolved)
        {
            let elapsed = chrono::Utc::now().signed_duration_since(resolved_time);
            if elapsed.num_seconds() as u64 > window_secs {
                return Err(crate::api_error::ApiError::new(
                    StatusCode::GONE,
                    "execution window expired",
                )
                .with_code("execution_window_expired"));
            }
        }

        let exec_count = crate::db::request_repo::count_executions(&conn, &id);
        if status == "failed" && !retry {
            return Err(
                crate::api_error::ApiError::conflict("retry on failure is disabled")
                    .with_code("retry_on_failure_disabled"),
            );
        }
        if exec_count >= max_exec {
            return Err(crate::api_error::ApiError::conflict(format!(
                "max executions ({max_exec}) reached"
            ))
            .with_code("max_executions_reached"));
        }
    }

    let now = chrono::Utc::now().to_rfc3339();
    let current = RequestStatus::parse(&status)
        .ok_or_else(|| crate::api_error::ApiError::internal(format!("unknown status: {status}")))?;
    request_status::transition(current, &RequestEvent::Dispatch).map_err(|_| {
        crate::api_error::ApiError::conflict("request cannot be dispatched (wrong status)")
            .with_code("request_dispatch_wrong_status")
    })?;

    if status != "dispatched" && !crate::db::request_repo::mark_dispatched(&conn, &id, &now)? {
        return Err(crate::api_error::ApiError::conflict(
            "request cannot be dispatched (wrong status)",
        )
        .with_code("request_dispatch_wrong_status"));
    }

    drop(conn);
    ensure_result_slot(&state, &id).await;
    state.request_notifier.notify(&id).await;

    {
        let mut conn = state.db().await;
        let _ = crate::db::audit_event_repo::record_audit_event(
            &mut conn,
            crate::db::audit_event_repo::AuditEvent {
                event_type: "request_dispatched",
                event_category: "approval",
                outcome: "success",
                actor_id: &user.user,
                actor_type: "user",
                resource_type: Some("request"),
                resource_id: Some(&id),
                peer_ip: None,
                client_ip: None,
                client_ip_source: None,
                request_id: Some(&id),
                operation: None,
                environment: Some(&environment),
                database_name: Some(&database_name),
                detail_fingerprint: None,
                detail_raw: None,
                reason: None,
                metadata_json: "{}",
            },
            &headers,
            &state.audit_config,
            &state.trusted_proxies,
        );
    }

    Ok(Json(
        serde_json::to_value(dbward_api_types::requests::StatusResponse {
            id,
            status: RequestStatus::Dispatched,
        })
        .unwrap(),
    ))
}

/// Client waits for execution result (long poll).
pub(crate) async fn stream_result(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize_and_audit(&user, Action::ReadResult, Resource::Global, &state).await?;

    let (id, requester, database_name, environment, status): (
        String,
        String,
        String,
        String,
        String,
    ) = {
        let conn = state.db().await;
        let id = resolve_id(&conn, &id)?;
        let row = conn
            .query_row(
                "SELECT created_by, database_name, environment, status FROM requests WHERE id = ?1",
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
            .map_err(|_| crate::api_error::ApiError::not_found("request not found"))?;
        (id, row.0, row.1, row.2, row.3)
    };

    let access_roles = {
        let conn = state.db().await;
        let (_, access_roles) =
            crate::db::policy_repo::get_result_policy(&conn, &database_name, &environment);
        access_roles
    };

    authz::authorize_and_audit(
        &user,
        Action::ReadResult,
        Resource::Result {
            requester_id: requester.clone(),
            access_roles,
        },
        &state,
    )
    .await?;

    let slot = match state.result_channels.get(&id).await {
        Some(slot) => slot,
        None => {
            match status.as_str() {
                "executed" | "failed" => {
                    // Try storage fallback
                    let no_store: bool = {
                        let conn = state.db().await;
                        conn.query_row(
                            "SELECT no_store FROM requests WHERE id = ?1",
                            [&id],
                            |row| row.get::<_, i64>(0),
                        )
                        .unwrap_or(0)
                            != 0
                    };
                    if no_store {
                        return Err(crate::api_error::ApiError::new(
                            StatusCode::GONE,
                            "result was not stored (no_store flag set)",
                        )
                        .with_code("result_not_stored"));
                    }
                    let data = state.result_store.get(&id).await.map_err(|_| {
                        crate::api_error::ApiError::conflict(
                            "result relay expired and storage read failed",
                        )
                        .with_code("result_relay_unavailable")
                    })?;
                    let payload: serde_json::Value = serde_json::from_slice(&data).unwrap_or_else(
                        |_| serde_json::json!({"success": status == "executed", "raw": true}),
                    );
                    return Ok(Json(payload));
                }
                "approved" | "auto_approved" | "break_glass" => {
                    return Err(crate::api_error::ApiError::conflict(
                        "request is approved but not dispatched",
                    )
                    .with_code("result_relay_unavailable"));
                }
                "dispatched" | "running" => {
                    return Err(crate::api_error::ApiError::conflict(
                        "result relay state is missing; retry dispatch",
                    )
                    .with_code("result_relay_unavailable"));
                }
                _ => {
                    return Err(crate::api_error::ApiError::conflict(format!(
                        "request status is {status}"
                    ))
                    .with_code("result_relay_unavailable"));
                }
            }
        }
    };

    if let Some(payload) = slot.result.lock().await.clone() {
        drop(state.result_channels.remove(&id).await);
        return Ok(Json(payload));
    }
    if state.draining.load(std::sync::atomic::Ordering::Relaxed) {
        return Err(crate::api_error::ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "server is shutting down",
        )
        .with_code("server_shutting_down")
        .with_hint(format!("dbward request resume {id}")));
    }

    // Wait up to 5 minutes for agent to deliver result
    let wait = tokio::time::timeout(
        std::time::Duration::from_secs(crate::constants::RESULT_WAIT_TIMEOUT_SECS),
        async {
            loop {
                tokio::select! {
                    _ = slot.notify.notified() => {},
                    _ = tokio::time::sleep(std::time::Duration::from_secs(3)) => {},
                }
                if state.draining.load(std::sync::atomic::Ordering::Relaxed) {
                    return Err(());
                }
                if slot.result.lock().await.is_some() {
                    return Ok(());
                }
                // Defense: re-check DB status (handles slot-overwrite race)
                let conn = state.db().await;
                let current_status: String = conn
                    .query_row("SELECT status FROM requests WHERE id = ?1", [&id], |row| {
                        row.get(0)
                    })
                    .unwrap_or_default();
                drop(conn);
                if current_status == "executed" || current_status == "failed" {
                    if let Ok(data) = state.result_store.get(&id).await {
                        if let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&data) {
                            *slot.result.lock().await = Some(payload);
                            return Ok(());
                        }
                    }
                }
            }
        },
    )
    .await;
    if matches!(wait, Ok(Err(()))) {
        return Err(crate::api_error::ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "server is shutting down",
        )
        .with_code("server_shutting_down")
        .with_hint(format!("dbward request resume {id}")));
    }
    if wait.is_err() {
        return Err(crate::api_error::ApiError::new(
            StatusCode::GATEWAY_TIMEOUT,
            "timed out waiting for result",
        )
        .with_code("result_wait_timeout"));
    }

    let result = slot.result.lock().await.clone();
    drop(state.result_channels.remove(&id).await);

    match result {
        Some(payload) => Ok(Json(payload)),
        None => {
            Err(crate::api_error::ApiError::internal("result was empty").with_code("result_empty"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- is_expirable_status ---

    #[test]
    fn expirable_statuses() {
        assert!(is_expirable_status("approved"));
        assert!(is_expirable_status("auto_approved"));
        assert!(is_expirable_status("break_glass"));
    }

    #[test]
    fn non_expirable_statuses() {
        assert!(!is_expirable_status("pending"));
        assert!(!is_expirable_status("rejected"));
        assert!(!is_expirable_status("cancelled"));
        assert!(!is_expirable_status("dispatched"));
        assert!(!is_expirable_status("completed"));
        assert!(!is_expirable_status("failed"));
    }

    // --- compute_expires_at ---

    #[test]
    fn expires_at_none_when_ttl_zero() {
        assert_eq!(
            compute_expires_at("approved", &Some("2026-01-01T00:00:00+00:00".into()), 0),
            None
        );
    }

    #[test]
    fn expires_at_none_for_non_expirable_status() {
        let ts = Some("2026-01-01T00:00:00+00:00".into());
        assert_eq!(compute_expires_at("pending", &ts, 3600), None);
        assert_eq!(compute_expires_at("rejected", &ts, 3600), None);
        assert_eq!(compute_expires_at("cancelled", &ts, 3600), None);
    }

    #[test]
    fn expires_at_computes_for_approved() {
        let result =
            compute_expires_at("approved", &Some("2026-01-01T00:00:00+00:00".into()), 3600);
        assert!(result.is_some());
        assert!(result.unwrap().contains("2026-01-01T01:00:00"));
    }

    #[test]
    fn expires_at_works_for_break_glass_and_auto_approved() {
        let ts = Some("2026-05-01T12:00:00+00:00".into());
        assert!(compute_expires_at("break_glass", &ts, 60).is_some());
        assert!(compute_expires_at("auto_approved", &ts, 60).is_some());
    }

    #[test]
    fn expires_at_none_when_resolved_at_missing() {
        assert_eq!(compute_expires_at("approved", &None, 3600), None);
    }

    #[test]
    fn expires_at_none_when_resolved_at_invalid() {
        assert_eq!(
            compute_expires_at("approved", &Some("not-a-date".into()), 3600),
            None
        );
    }

    // --- should_filter_capability ---

    #[test]
    fn filter_capability_empty_means_no_filter() {
        assert!(!should_filter_capability(&[]));
    }

    #[test]
    fn filter_capability_wildcard_means_no_filter() {
        assert!(!should_filter_capability(&["*".into()]));
        assert!(!should_filter_capability(&["app".into(), "*".into()]));
    }

    #[test]
    fn filter_capability_specific_values_means_filter() {
        assert!(should_filter_capability(&["app".into()]));
        assert!(should_filter_capability(&[
            "app".into(),
            "analytics".into()
        ]));
    }

    // --- parse_pagination ---

    #[test]
    fn pagination_defaults() {
        let params = HashMap::new();
        assert_eq!(parse_pagination(&params), (50, 0));
    }

    #[test]
    fn pagination_respects_values() {
        let mut params = HashMap::new();
        params.insert("limit".into(), "10".into());
        params.insert("offset".into(), "20".into());
        assert_eq!(parse_pagination(&params), (10, 20));
    }

    #[test]
    fn pagination_clamps_limit() {
        let mut params = HashMap::new();
        params.insert("limit".into(), "9999".into());
        assert_eq!(parse_pagination(&params), (200, 0));
    }

    #[test]
    fn pagination_handles_invalid_input() {
        let mut params = HashMap::new();
        params.insert("limit".into(), "abc".into());
        params.insert("offset".into(), "-5".into());
        let (limit, offset) = parse_pagination(&params);
        assert_eq!(limit, 50); // fallback to default
        assert_eq!(offset, 0); // clamped to 0
    }

    // --- validate_metadata ---

    #[test]
    fn metadata_none_returns_empty_object() {
        assert_eq!(validate_metadata(None).unwrap(), "{}");
    }

    #[test]
    fn metadata_valid_object() {
        let v = serde_json::json!({"key": "value"});
        assert!(validate_metadata(Some(&v)).is_ok());
    }

    #[test]
    fn metadata_rejects_non_object() {
        let v = serde_json::json!("string");
        assert!(validate_metadata(Some(&v)).is_err());
        let v = serde_json::json!([1, 2, 3]);
        assert!(validate_metadata(Some(&v)).is_err());
    }

    #[test]
    fn metadata_rejects_oversized() {
        let big = "x".repeat(MAX_METADATA_JSON_BYTES + 1);
        let v = serde_json::json!({"data": big});
        assert!(validate_metadata(Some(&v)).is_err());
    }

    // --- validate_idempotency_key ---

    #[test]
    fn idempotency_key_none_returns_none() {
        assert_eq!(validate_idempotency_key(None).unwrap(), None);
    }

    #[test]
    fn idempotency_key_valid() {
        let v = serde_json::json!("deploy-abc123");
        assert_eq!(
            validate_idempotency_key(Some(&v)).unwrap(),
            Some("deploy-abc123".into())
        );
    }

    #[test]
    fn idempotency_key_rejects_non_string() {
        let v = serde_json::json!(123);
        assert!(validate_idempotency_key(Some(&v)).is_err());
    }

    #[test]
    fn idempotency_key_rejects_empty() {
        let v = serde_json::json!("  ");
        assert!(validate_idempotency_key(Some(&v)).is_err());
    }

    #[test]
    fn idempotency_key_rejects_oversized() {
        let big = "x".repeat(MAX_IDEMPOTENCY_KEY_BYTES + 1);
        let v = serde_json::json!(big);
        assert!(validate_idempotency_key(Some(&v)).is_err());
    }

    // --- extract_approver_summary ---

    #[test]
    fn approver_summary_none_returns_empty() {
        assert_eq!(extract_approver_summary(None), Vec::<String>::new());
    }

    #[test]
    fn approver_summary_parses_roles() {
        let json = r#"[{"type":"approval","approvers":[{"role":"admin","min":1}]}]"#;
        let result = extract_approver_summary(Some(json));
        assert_eq!(result, vec!["role:admin (min:1)"]);
    }

    #[test]
    fn approver_summary_parses_groups() {
        let json = r#"[{"type":"approval","approvers":[{"group":"dba-team","min":2}]}]"#;
        let result = extract_approver_summary(Some(json));
        assert_eq!(result, vec!["group:dba-team (min:2)"]);
    }

    #[test]
    fn approver_summary_invalid_json_returns_empty() {
        assert_eq!(
            extract_approver_summary(Some("not json")),
            Vec::<String>::new()
        );
    }

    #[test]
    fn pagination_limit_zero_clamps_to_one() {
        let mut params = HashMap::new();
        params.insert("limit".into(), "0".into());
        assert_eq!(parse_pagination(&params), (1, 0));
    }

    #[test]
    fn idempotency_key_trims_whitespace() {
        let v = serde_json::json!("  hello  ");
        assert_eq!(
            validate_idempotency_key(Some(&v)).unwrap(),
            Some("hello".into())
        );
    }

    #[test]
    fn approver_summary_multiple_steps() {
        let json = r#"[
            {"type":"approval","approvers":[{"role":"developer","min":1}]},
            {"type":"approval","approvers":[{"group":"dba-team","min":2},{"role":"admin","min":1}]}
        ]"#;
        let result = extract_approver_summary(Some(json));
        assert_eq!(
            result,
            vec![
                "role:developer (min:1)",
                "group:dba-team (min:2)",
                "role:admin (min:1)",
            ]
        );
    }
}
