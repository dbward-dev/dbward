use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use serde_json::json;

use dbward_app::error::AppError;
use dbward_app::use_cases::{
    approve_request, cancel_request, create_request, dispatch_request, get_result, reject_request,
    stream_result,
};
use dbward_domain::auth::AuthUser;
use dbward_domain::values::{DatabaseName, Environment, Operation};

use crate::state::AppState;

type ApiResult =
    Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)>;

/// Check if user can approve a pending request by parsing its workflow snapshot.
fn map_error(e: AppError) -> (StatusCode, Json<serde_json::Value>) {
    let status = match &e {
        AppError::Forbidden(_) => StatusCode::FORBIDDEN,
        AppError::Auth(_) => StatusCode::UNAUTHORIZED,
        AppError::NotFound(_) => StatusCode::NOT_FOUND,
        AppError::Conflict(_) => StatusCode::CONFLICT,
        AppError::Gone(_) => StatusCode::GONE,
        AppError::Validation(_) => StatusCode::BAD_REQUEST,
        AppError::PlanLimit(_) => StatusCode::PAYMENT_REQUIRED,
        AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    let code = e.code();
    let hint: Option<String> = match &e {
        AppError::Forbidden(_) => Some("check your role permissions".into()),
        AppError::Conflict(_) => Some("request may have been modified concurrently".into()),
        AppError::Validation(msg) => Some(msg.clone()),
        _ => None,
    };
    let message = match &e {
        AppError::Internal(_) => "internal server error".to_string(),
        other => other.to_string(),
    };
    (
        status,
        Json(json!({"error": message, "code": code, "hint": hint})),
    )
}

pub async fn create(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult {
    if state.draining.load(std::sync::atomic::Ordering::SeqCst) {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "server_shutting_down", "code": "service_unavailable"})),
        ));
    }

    let database = body["database"].as_str().unwrap_or_default();
    let environment = body["environment"].as_str().unwrap_or_default();
    let detail = body["detail"].as_str().unwrap_or_default();

    let database =
        DatabaseName::new(database).map_err(|e| map_error(AppError::Validation(e.to_string())))?;
    let environment = Environment::new(environment)
        .map_err(|e| map_error(AppError::Validation(e.to_string())))?;

    let share_with = body["share_with"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let operation = body["operation"]
        .as_str()
        .and_then(|s| s.parse::<Operation>().ok())
        .unwrap_or(Operation::ExecuteSelect);

    let input = create_request::CreateRequestInput {
        database,
        environment,
        operation,
        detail: detail.to_string(),
        reason: body["reason"].as_str().map(String::from),
        emergency: body["emergency"].as_bool().unwrap_or(false),
        idempotency_key: body["idempotency_key"].as_str().map(String::from),
        share_with,
        no_store: body["no_store"].as_bool().unwrap_or(false),
        metadata_json: body
            .get("metadata")
            .map(|v| v.to_string())
            .unwrap_or_else(|| "{}".into()),
        channel: create_request::RequestChannel::Api,
    };

    let uc = create_request::CreateRequest {
        authorizer: state.authorizer.clone(),
        policy: state.policy_evaluator.clone(),
        request_repo: state.request_repo.clone(),
        db_registry: state.database_registry.clone(),
        event_dispatcher: state.event_dispatcher.clone(),
        clock: state.clock.clone(),
        id_gen: state.id_generator.clone(),
        default_approval_ttl_secs: state.default_approval_ttl_secs,
    };

    match uc.execute(input, &user) {
        Ok(out) => {
            // Extract approvers from workflow snapshot if pending
            let approvers: Vec<String> =
                if out.status == dbward_domain::entities::RequestStatus::Pending {
                    // Re-read the request to get workflow_snapshot
                    state
                        .request_repo
                        .get(&out.id)
                        .ok()
                        .flatten()
                        .and_then(|r| r.workflow_snapshot_json)
                        .and_then(|json| serde_json::from_str::<serde_json::Value>(&json).ok())
                        .and_then(|v| {
                            v.get("steps")?
                                .as_array()?
                                .first()?
                                .get("approvers")?
                                .as_array()
                                .cloned()
                        })
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|a| {
                                    a.get("selector")
                                        .and_then(|s| s.as_str())
                                        .map(String::from)
                                        .or_else(|| Some(a.get("selector")?.to_string()))
                                })
                                .collect()
                        })
                        .unwrap_or_default()
                } else {
                    vec![]
                };

            let status_code = if out.is_existing {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            };

            Ok((
                status_code,
                Json(json!({
                    "id": out.id,
                    "status": out.status.as_str(),
                    "operation": out.operation.as_str(),
                    "approvers": approvers,
                    "idempotent": out.is_existing,
                    "expires_at": out.expires_at,
                })),
            ))
        }
        Err(e) => Err(map_error(e)),
    }
}

pub async fn list(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    axum::extract::Query(params): axum::extract::Query<ListParams>,
) -> ApiResult {
    // Require request.view permission
    state
        .authorizer
        .authorize_global(&user, dbward_domain::auth::Permission::RequestView)
        .map_err(|e| (StatusCode::FORBIDDEN, Json(json!({"error": e.to_string()}))))?;

    let limit = params.limit.unwrap_or(50).min(100);
    let offset = params.offset.unwrap_or(0);
    let pending_for_me = params.pending_for_me.unwrap_or(false);

    // pending_for_me uses denormalized table (no N+1)
    if pending_for_me {
        let roles: Vec<String> = user.roles.iter().map(|r| r.name.clone()).collect();
        let (requests, total) = state
            .request_repo
            .list_pending_for_user(&user.subject_id, &user.groups, &roles, limit, offset)
            .map_err(map_error)?;
        let items: Vec<serde_json::Value> = requests
            .iter()
            .map(|r| {
                json!({
                    "id": r.id,
                    "requester": r.requester,
                    "database": r.database,
                    "environment": r.environment,
                    "operation": r.operation.as_str(),
                    "status": r.status.as_str(),
                    "created_at": r.created_at,
                })
            })
            .collect();
        return Ok((
            StatusCode::OK,
            Json(json!({"requests": items, "total": total, "limit": limit, "offset": offset})),
        ));
    }

    let (requests, total) = state
        .request_repo
        .list(limit, offset, params.status.as_deref(), params.user.as_deref())
        .map_err(map_error)?;
    // Non-admin users only see their own requests + pending requests they can approve
    let is_admin = user.roles.iter().any(|r| r.name == "admin");
    let can_approve = user.has_permission(dbward_domain::auth::Permission::RequestApprove);
    let items: Vec<serde_json::Value> = requests
        .iter()
        .filter(|r| {
            if is_admin {
                return true;
            }
            if r.requester == user.subject_id {
                return true;
            }
            if can_approve && r.status == dbward_domain::entities::RequestStatus::Pending {
                return true;
            }
            false
        })
        .map(|r| {
            json!({
                "id": r.id,
                "requester": r.requester,
                "database": r.database,
                "environment": r.environment,
                "operation": r.operation.as_str(),
                "status": r.status.as_str(),
                "created_at": r.created_at,
            })
        })
        .collect();
    let effective_total = if is_admin { total } else { items.len() as u32 };
    Ok((
        StatusCode::OK,
        Json(
            json!({"requests": items, "total": effective_total, "limit": limit, "offset": offset}),
        ),
    ))
}

#[derive(serde::Deserialize)]
pub struct ListParams {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub status: Option<String>,
    pub user: Option<String>,
    pub pending_for_me: Option<bool>,
}

#[derive(serde::Deserialize)]
pub struct GetRequestQuery {
    pub wait: Option<u64>,
}

pub async fn get(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    axum::extract::Query(query): axum::extract::Query<GetRequestQuery>,
) -> ApiResult {
    let req = match state.request_repo.get(&id) {
        Ok(Some(r)) => r,
        Ok(None) => return Err(map_error(AppError::NotFound("request not found".into()))),
        Err(e) => return Err(map_error(e)),
    };

    // M-13: Long-poll — wait for status change if non-terminal and wait specified
    let req = if let Some(wait_secs) = query.wait {
        use dbward_domain::entities::RequestStatus;
        let is_terminal = matches!(
            req.status,
            RequestStatus::Executed
                | RequestStatus::Failed
                | RequestStatus::Rejected
                | RequestStatus::Cancelled
                | RequestStatus::Expired
                | RequestStatus::ExecutionLost
        );
        if !is_terminal && wait_secs > 0 {
            let wait_secs = wait_secs.min(120);
            let original_status = req.status;
            let deadline =
                tokio::time::Instant::now() + tokio::time::Duration::from_secs(wait_secs);
            let mut current = req;
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                if tokio::time::Instant::now() >= deadline {
                    break;
                }
                match state.request_repo.get(&id) {
                    Ok(Some(r)) if r.status != original_status => {
                        current = r;
                        break;
                    }
                    Ok(Some(r)) => {
                        current = r;
                    }
                    _ => break,
                }
            }
            current
        } else {
            req
        }
    } else {
        req
    };

    use dbward_domain::auth::{Permission, ResourceContext};
    use dbward_domain::entities::RequestStatus;
    let scoped_ok = state.authorizer.authorize_scoped(
        &user,
        Permission::RequestView,
        &req.database,
        &req.environment,
        &ResourceContext::Request {
            requester_id: req.requester.clone(),
        },
    );
    let is_approver_view = if let Err(authz_err) = scoped_ok {
        // Approvers can view pending requests they need to act on (scoped to matching db/env)
        let approver = req.status == RequestStatus::Pending
            && state
                .authorizer
                .authorize_scoped(
                    &user,
                    Permission::RequestApprove,
                    &req.database,
                    &req.environment,
                    &ResourceContext::Global,
                )
                .is_ok();
        if !approver {
            return Err(map_error(AppError::Forbidden(authz_err)));
        }
        true
    } else {
        false
    };

    let detail = if is_approver_view && user.subject_id != req.requester {
        "[redacted - approve to view]".to_string()
    } else {
        req.detail.clone()
    };

    Ok((
        StatusCode::OK,
        Json(json!({
            "id": req.id,
            "requester": req.requester,
            "database": req.database,
            "environment": req.environment,
            "operation": req.operation.as_str(),
            "detail": detail,
            "status": req.status.as_str(),
            "emergency": req.emergency,
            "reason": req.reason,
            "share_with": req.share_with,
            "no_store": req.no_store,
            "created_at": req.created_at,
            "updated_at": req.updated_at,
            "expires_at": req.expires_at,
        })),
    ))
}

pub async fn approve(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult {
    let uc = approve_request::ApproveRequest {
        authorizer: state.authorizer.clone(),
        request_repo: state.request_repo.clone(),
        event_dispatcher: state.event_dispatcher.clone(),
        clock: state.clock.clone(),
        id_gen: state.id_generator.clone(),
    };

    let input = approve_request::ApproveRequestInput {
        request_id: id,
        comment: body["comment"].as_str().map(String::from),
    };

    match uc.execute(input, &user) {
        Ok(out) => Ok((
            StatusCode::OK,
            Json(json!({
                "id": out.id,
                "status": out.status.as_str(),
                "approved_by": out.approved_by,
                "step_completed": out.step_completed,
                "current_step": out.current_step,
                "total_steps": out.total_steps,
            })),
        )),
        Err(e) => Err(map_error(e)),
    }
}

pub async fn reject(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult {
    let uc = reject_request::RejectRequest {
        authorizer: state.authorizer.clone(),
        request_repo: state.request_repo.clone(),
        event_dispatcher: state.event_dispatcher.clone(),
        clock: state.clock.clone(),
        id_gen: state.id_generator.clone(),
    };

    let input = reject_request::RejectRequestInput {
        request_id: id,
        comment: body["comment"].as_str().map(String::from),
    };

    match uc.execute(input, &user) {
        Ok(out) => Ok((
            StatusCode::OK,
            Json(json!({
                "id": out.id,
                "status": out.status.as_str(),
            })),
        )),
        Err(e) => Err(map_error(e)),
    }
}

pub async fn cancel(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult {
    let uc = cancel_request::CancelRequest {
        authorizer: state.authorizer.clone(),
        request_repo: state.request_repo.clone(),
        event_dispatcher: state.event_dispatcher.clone(),
        clock: state.clock.clone(),
    };

    let input = cancel_request::CancelRequestInput {
        request_id: id,
        reason: body["reason"].as_str().map(String::from),
    };

    match uc.execute(input, &user) {
        Ok(out) => Ok((
            StatusCode::OK,
            Json(json!({
                "id": out.id,
                "status": out.status.as_str(),
            })),
        )),
        Err(e) => Err(map_error(e)),
    }
}

pub async fn dispatch(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> ApiResult {
    let uc = dispatch_request::DispatchRequest {
        authorizer: state.authorizer.clone(),
        policy: state.policy_evaluator.clone(),
        request_repo: state.request_repo.clone(),
        result_channel: state.result_channel.clone(),
        event_dispatcher: state.event_dispatcher.clone(),
        policy_repo: state.policy_repo.clone(),
        clock: state.clock.clone(),
    };

    let input = dispatch_request::DispatchRequestInput { request_id: id };

    match uc.execute(input, &user) {
        Ok(out) => Ok((
            StatusCode::OK,
            Json(json!({
                "id": out.id,
                "status": out.status.as_str(),
            })),
        )),
        Err(e) => Err(map_error(e)),
    }
}

pub async fn stream_result(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> ApiResult {
    let uc = stream_result::StreamResult {
        authorizer: state.authorizer.clone(),
        request_repo: state.request_repo.clone(),
        result_channel: state.result_channel.clone(),
    };

    let input = stream_result::StreamResultInput {
        request_id: id,
        timeout_secs: Some(300),
    };

    match uc.execute(input, &user).await {
        Ok(out) => match out.data {
            Some(summary) => Ok((
                StatusCode::OK,
                Json(json!({
                    "execution_id": summary.execution_id,
                    "success": summary.success,
                    "rows_affected": summary.rows_affected,
                    "truncated": summary.truncated,
                    "error_message": summary.error_message,
                    "result_data": summary.result_data,
                })),
            )),
            None => Ok((StatusCode::NO_CONTENT, Json(json!({})))),
        },
        Err(e) => Err(map_error(e)),
    }
}

pub async fn get_result(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> ApiResult {
    let uc = get_result::GetResult {
        authorizer: state.authorizer.clone(),
        request_repo: state.request_repo.clone(),
        agent_repo: state.agent_repo.clone(),
        result_store: state.result_store.clone(),
        policy_repo: state.policy_repo.clone(),
        clock: state.clock.clone(),
    };

    let input = get_result::GetResultInput { request_id: id };

    match uc.execute(input, &user).await {
        Ok(out) => {
            // Return stored data as JSON directly
            let json_value: serde_json::Value = serde_json::from_slice(&out.data)
                .unwrap_or_else(|_| json!({"raw": base64_encode(&out.data)}));
            Ok((StatusCode::OK, Json(json_value)))
        }
        Err(e) => Err(map_error(e)),
    }
}

fn base64_encode(data: &[u8]) -> String {
    use std::io::Write;
    let mut buf = Vec::with_capacity(data.len() * 4 / 3 + 4);
    {
        let mut encoder = Base64Encoder::new(&mut buf);
        encoder.write_all(data).unwrap();
    }
    String::from_utf8(buf).unwrap_or_default()
}

/// Minimal base64 encoder (no external dependency needed).
struct Base64Encoder<'a> {
    out: &'a mut Vec<u8>,
}

impl<'a> Base64Encoder<'a> {
    fn new(out: &'a mut Vec<u8>) -> Self {
        Self { out }
    }
}

impl<'a> std::io::Write for Base64Encoder<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for chunk in buf.chunks(3) {
            match chunk.len() {
                3 => {
                    self.out.push(TABLE[(chunk[0] >> 2) as usize]);
                    self.out
                        .push(TABLE[(((chunk[0] & 0x03) << 4) | (chunk[1] >> 4)) as usize]);
                    self.out
                        .push(TABLE[(((chunk[1] & 0x0f) << 2) | (chunk[2] >> 6)) as usize]);
                    self.out.push(TABLE[(chunk[2] & 0x3f) as usize]);
                }
                2 => {
                    self.out.push(TABLE[(chunk[0] >> 2) as usize]);
                    self.out
                        .push(TABLE[(((chunk[0] & 0x03) << 4) | (chunk[1] >> 4)) as usize]);
                    self.out.push(TABLE[((chunk[1] & 0x0f) << 2) as usize]);
                    self.out.push(b'=');
                }
                1 => {
                    self.out.push(TABLE[(chunk[0] >> 2) as usize]);
                    self.out.push(TABLE[((chunk[0] & 0x03) << 4) as usize]);
                    self.out.push(b'=');
                    self.out.push(b'=');
                }
                _ => {}
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub async fn list_results(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> ApiResult {
    let results = state
        .request_repo
        .list_results_for_user(&user.subject_id, &user.groups, &user.roles.iter().map(|r| r.name.clone()).collect::<Vec<_>>(), 50)
        .map_err(map_error)?;
    let items: Vec<serde_json::Value> = results
        .iter()
        .map(|r| {
            json!({
                "request_id": r.request_id,
                "database": r.database,
                "environment": r.environment,
                "operation": r.operation,
                "stored_at": r.stored_at,
                "content_length": r.content_length,
            })
        })
        .collect();
    Ok((StatusCode::OK, Json(json!({ "results": items }))))
}
