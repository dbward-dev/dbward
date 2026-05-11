use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    Json,
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

type ApiResult = Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)>;

fn map_error(e: AppError) -> (StatusCode, Json<serde_json::Value>) {
    let (status, code) = match &e {
        AppError::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden"),
        AppError::Auth(_) => (StatusCode::UNAUTHORIZED, "unauthorized"),
        AppError::NotFound(_) => (StatusCode::NOT_FOUND, "not_found"),
        AppError::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
        AppError::Gone(_) => (StatusCode::GONE, "gone"),
        AppError::Validation(_) => (StatusCode::BAD_REQUEST, "validation_error"),
        AppError::PlanLimit(_) => (StatusCode::PAYMENT_REQUIRED, "plan_limit_reached"),
        AppError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
    };
    let message = match &e {
        AppError::Internal(_) => "internal server error".to_string(),
        other => other.to_string(),
    };
    (status, Json(json!({"error": message, "code": code})))
}

pub async fn create(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult {
    let database = body["database"].as_str().unwrap_or_default();
    let environment = body["environment"].as_str().unwrap_or_default();
    let detail = body["detail"].as_str().unwrap_or_default();

    let database = DatabaseName::new(database)
        .map_err(|e| map_error(AppError::Validation(e.to_string())))?;
    let environment = Environment::new(environment)
        .map_err(|e| map_error(AppError::Validation(e.to_string())))?;

    let share_with = body["share_with"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
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
        metadata_json: body.get("metadata").map(|v| v.to_string()).unwrap_or_else(|| "{}".into()),
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
    };

    match uc.execute(input, &user) {
        Ok(out) => Ok((
            StatusCode::CREATED,
            Json(json!({
                "id": out.id,
                "status": out.status.as_str(),
                "operation": out.operation.as_str(),
            })),
        )),
        Err(e) => Err(map_error(e)),
    }
}

pub async fn list(
    State(state): State<AppState>,
    Extension(_user): Extension<AuthUser>,
) -> ApiResult {
    // RequestRepo doesn't have a list method yet; return empty list
    let _ = state;
    Ok((StatusCode::OK, Json(json!({"requests": []}))))
}

pub async fn get(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> ApiResult {
    let req = match state.request_repo.get(&id) {
        Ok(Some(r)) => r,
        Ok(None) => return Err(map_error(AppError::NotFound("request not found".into()))),
        Err(e) => return Err(map_error(e)),
    };

    use dbward_domain::auth::{Permission, ResourceContext};
    use dbward_domain::entities::RequestStatus;
    let scoped_ok = state.authorizer.authorize_scoped(
        &user,
        Permission::RequestView,
        &req.database,
        &req.environment,
        &ResourceContext::Request { requester_id: req.requester.clone() },
    );
    if scoped_ok.is_err() {
        // Approvers can view pending requests they need to act on (scoped to matching db/env)
        let is_approver_view = req.status == RequestStatus::Pending
            && state.authorizer.authorize_scoped(
                &user,
                Permission::RequestApprove,
                &req.database,
                &req.environment,
                &ResourceContext::Global,
            ).is_ok();
        if !is_approver_view {
            return Err(map_error(AppError::Forbidden(scoped_ok.unwrap_err())));
        }
    }

    Ok((StatusCode::OK, Json(json!({
        "id": req.id,
        "requester": req.requester,
        "database": req.database,
        "environment": req.environment,
        "operation": req.operation.as_str(),
        "detail": req.detail,
        "status": req.status.as_str(),
        "emergency": req.emergency,
        "reason": req.reason,
        "share_with": req.share_with,
        "no_store": req.no_store,
        "created_at": req.created_at,
        "updated_at": req.updated_at,
    }))))
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
        Ok(out) => Ok((StatusCode::OK, Json(json!({
            "id": out.id,
            "status": out.status.as_str(),
            "approved_by": out.approved_by,
            "step_completed": out.step_completed,
            "current_step": out.current_step,
            "total_steps": out.total_steps,
        })))),
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
        Ok(out) => Ok((StatusCode::OK, Json(json!({
            "id": out.id,
            "status": out.status.as_str(),
        })))),
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
        Ok(out) => Ok((StatusCode::OK, Json(json!({
            "id": out.id,
            "status": out.status.as_str(),
        })))),
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
        event_dispatcher: state.event_dispatcher.clone(),
        clock: state.clock.clone(),
    };

    let input = dispatch_request::DispatchRequestInput { request_id: id };

    match uc.execute(input, &user) {
        Ok(out) => Ok((StatusCode::OK, Json(json!({
            "id": out.id,
            "status": out.status.as_str(),
        })))),
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
            Some(summary) => Ok((StatusCode::OK, Json(json!({
                "execution_id": summary.execution_id,
                "success": summary.success,
                "rows_affected": summary.rows_affected,
                "truncated": summary.truncated,
                "error_message": summary.error_message,
            })))),
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
        clock: state.clock.clone(),
    };

    let input = get_result::GetResultInput { request_id: id };

    match uc.execute(input, &user).await {
        Ok(out) => Ok((StatusCode::OK, Json(json!({
            "data": base64_encode(&out.data),
        })))),
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
        const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for chunk in buf.chunks(3) {
            match chunk.len() {
                3 => {
                    self.out.push(TABLE[(chunk[0] >> 2) as usize]);
                    self.out.push(TABLE[(((chunk[0] & 0x03) << 4) | (chunk[1] >> 4)) as usize]);
                    self.out.push(TABLE[(((chunk[1] & 0x0f) << 2) | (chunk[2] >> 6)) as usize]);
                    self.out.push(TABLE[(chunk[2] & 0x3f) as usize]);
                }
                2 => {
                    self.out.push(TABLE[(chunk[0] >> 2) as usize]);
                    self.out.push(TABLE[(((chunk[0] & 0x03) << 4) | (chunk[1] >> 4)) as usize]);
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
