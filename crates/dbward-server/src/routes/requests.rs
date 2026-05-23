use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use serde_json::json;

use dbward_app::error::AppError;
use dbward_app::use_cases::{
    approve_request, cancel_request, create_request, dispatch_request, get_request, get_result,
    list_requests, reject_request, stream_result,
};
use dbward_domain::auth::AuthUser;
use dbward_domain::values::{DatabaseName, Environment, Operation};

use crate::middleware::trusted_proxies::ClientIp;
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
        AppError::PayloadTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
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
    client_ip: Option<Extension<ClientIp>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult {
    if state.draining.load(std::sync::atomic::Ordering::SeqCst) {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "server_shutting_down", "code": "service_unavailable"})),
        ));
    }

    let audit_ctx = super::extract_audit_context(
        client_ip.as_ref().map(|e| &e.0),
        connect_info.as_ref().map(|e| &e.0),
    );

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

    let operation = match body["operation"].as_str() {
        None | Some("") => Operation::ExecuteSelect, // unspecified → classify from SQL
        Some(s) => s
            .parse::<Operation>()
            .map_err(|e| map_error(AppError::Validation(e)))?,
    };

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
        request_reader: state.request_reader.clone(),
        request_writer: state.request_writer.clone(),
        db_registry: state.database_registry.clone(),
        schema_repo: state.schema_repo.clone(),
        dry_run_repo: state.dry_run_repo.clone(),
        context_repo: state.context_repo.clone(),
        event_dispatcher: state.event_dispatcher.clone(),
        audit_logger: state.audit_logger.clone(),
        clock: state.clock.clone(),
        id_gen: state.id_generator.clone(),
        default_approval_ttl_secs: state.default_approval_ttl_secs,
        review_rules: state.sql_review_rules.clone(),
        auto_approve_entries: state.auto_approve_entries.clone(),
    };

    match uc.execute(input, &user, &audit_ctx) {
        Ok(out) => {
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
                    "approvers": out.approvers,
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
    let uc = list_requests::ListRequests {
        request_reader: state.request_reader.clone(),
        authorizer: state.authorizer.clone(),
    };
    let output = uc
        .execute(
            list_requests::ListRequestsInput {
                limit: params.limit,
                offset: params.offset,
                status: params.status,
                user: params.user,
                pending_for_me: params.pending_for_me,
            },
            &user,
        )
        .map_err(map_error)?;

    let items: Vec<serde_json::Value> = output
        .requests
        .iter()
        .map(|r| {
            let mut obj = json!({
                "id": r.id,
                "requester": r.requester,
                "database": r.database,
                "environment": r.environment,
                "operation": r.operation,
                "detail": r.detail,
                "status": r.status,
                "created_at": r.created_at,
            });
            if let Some(cs) = r.current_step {
                obj["current_step"] = json!(cs);
            }
            if let Some(ts) = r.total_steps {
                obj["total_steps"] = json!(ts);
            }
            if !r.next_approvers.is_empty() {
                obj["next_approvers"] = json!(r.next_approvers);
            }
            obj
        })
        .collect();
    Ok((
        StatusCode::OK,
        Json(
            json!({"requests": items, "total": output.total, "limit": output.limit, "offset": output.offset}),
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
    let uc = get_request::GetRequest {
        request_reader: state.request_reader.clone(),
        approval_repo: state.approval_repo.clone(),
        authorizer: state.authorizer.clone(),
        context_repo: state.context_repo.clone(),
    };

    // Authorize BEFORE any waiting
    let output = uc.execute(&id, &user).map_err(map_error)?;

    // M-13: Long-poll — wait for status change if non-terminal and wait specified
    let output = if let Some(wait_secs) = query.wait {
        use dbward_domain::entities::RequestStatus;
        let is_terminal = matches!(
            output.request.status,
            RequestStatus::Executed
                | RequestStatus::Failed
                | RequestStatus::Rejected
                | RequestStatus::Cancelled
                | RequestStatus::Expired
                | RequestStatus::ExecutionLost
        );
        if !is_terminal && wait_secs > 0 {
            let wait_secs = wait_secs.min(120);
            let original_status = output.request.status;
            let deadline =
                tokio::time::Instant::now() + tokio::time::Duration::from_secs(wait_secs);
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                if tokio::time::Instant::now() >= deadline {
                    break;
                }
                match state.request_reader.get(&id) {
                    Ok(Some(r)) if r.status != original_status => {
                        break;
                    }
                    Ok(Some(_)) => {}
                    _ => break,
                }
            }
            // Re-fetch with authorization
            uc.execute(&id, &user).map_err(map_error)?
        } else {
            output
        }
    } else {
        output
    };

    Ok((
        StatusCode::OK,
        Json(json!({
            "id": output.request.id,
            "requester": output.request.requester,
            "database": output.request.database,
            "environment": output.request.environment,
            "operation": output.request.operation.as_str(),
            "detail": output.detail,
            "status": output.request.status.as_str(),
            "queue_hint": compute_queue_hint(&output.request, &state),
            "emergency": output.request.emergency,
            "reason": output.request.reason,
            "share_with": output.request.share_with,
            "no_store": output.request.no_store,
            "created_at": output.request.created_at,
            "updated_at": output.request.updated_at,
            "expires_at": output.request.expires_at,
            "approval_progress": output.approval_progress,
            "context": output.context.as_ref().map(|c| {
                let explain_enabled = c.status != "ready" || c.explain_json.is_some();
                serde_json::json!({
                    "status": c.status,
                    "explain_enabled": explain_enabled,
                    "tables": c.tables_json.as_deref().and_then(|j| serde_json::from_str::<serde_json::Value>(j).ok()),
                    "sql_review": c.sql_review_json.as_deref().and_then(|j| serde_json::from_str::<serde_json::Value>(j).ok()),
                    "risk": c.risk_json.as_deref().and_then(|j| serde_json::from_str::<serde_json::Value>(j).ok()),
                    "explain": c.explain_json.as_deref().and_then(|j| serde_json::from_str::<serde_json::Value>(j).ok()),
                })
            }),
        })),
    ))
}

pub async fn approve(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    client_ip: Option<Extension<ClientIp>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult {
    let audit_ctx = super::extract_audit_context(
        client_ip.as_ref().map(|e| &e.0),
        connect_info.as_ref().map(|e| &e.0),
    );
    let uc = approve_request::ApproveRequest {
        authorizer: state.authorizer.clone(),
        request_reader: state.request_reader.clone(),
        approval_repo: state.approval_repo.clone(),
        event_dispatcher: state.event_dispatcher.clone(),
        clock: state.clock.clone(),
        id_gen: state.id_generator.clone(),
    };

    let input = approve_request::ApproveRequestInput {
        request_id: id,
        comment: body["comment"].as_str().map(String::from),
    };

    match uc.execute(input, &user, &audit_ctx) {
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
    client_ip: Option<Extension<ClientIp>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult {
    let audit_ctx = super::extract_audit_context(
        client_ip.as_ref().map(|e| &e.0),
        connect_info.as_ref().map(|e| &e.0),
    );
    let uc = reject_request::RejectRequest {
        authorizer: state.authorizer.clone(),
        request_reader: state.request_reader.clone(),
        approval_repo: state.approval_repo.clone(),
        event_dispatcher: state.event_dispatcher.clone(),
        clock: state.clock.clone(),
        id_gen: state.id_generator.clone(),
    };

    let input = reject_request::RejectRequestInput {
        request_id: id,
        comment: body["comment"].as_str().map(String::from),
    };

    match uc.execute(input, &user, &audit_ctx) {
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
    client_ip: Option<Extension<ClientIp>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> ApiResult {
    let audit_ctx = super::extract_audit_context(
        client_ip.as_ref().map(|e| &e.0),
        connect_info.as_ref().map(|e| &e.0),
    );
    let uc = cancel_request::CancelRequest {
        authorizer: state.authorizer.clone(),
        request_reader: state.request_reader.clone(),
        request_writer: state.request_writer.clone(),
        event_dispatcher: state.event_dispatcher.clone(),
        clock: state.clock.clone(),
    };

    let input = cancel_request::CancelRequestInput {
        request_id: id,
        reason: body["reason"].as_str().map(String::from),
    };

    match uc.execute(input, &user, &audit_ctx) {
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
    client_ip: Option<Extension<ClientIp>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    Path(id): Path<String>,
) -> ApiResult {
    let audit_ctx = super::extract_audit_context(
        client_ip.as_ref().map(|e| &e.0),
        connect_info.as_ref().map(|e| &e.0),
    );
    let uc = dispatch_request::DispatchRequest {
        authorizer: state.authorizer.clone(),
        policy: state.policy_evaluator.clone(),
        request_reader: state.request_reader.clone(),
        request_writer: state.request_writer.clone(),
        result_channel: state.result_channel.clone(),
        event_dispatcher: state.event_dispatcher.clone(),
        policy_repo: state.policy_repo.clone(),
        clock: state.clock.clone(),
    };

    let input = dispatch_request::DispatchRequestInput { request_id: id };

    match uc.execute(input, &user, &audit_ctx) {
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
        request_reader: state.request_reader.clone(),
        result_channel: state.result_channel.clone(),
        policy_repo: state.policy_repo.clone(),
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
) -> Result<axum::http::Response<axum::body::Body>, (StatusCode, Json<serde_json::Value>)> {
    let uc = get_result::GetResult {
        authorizer: state.authorizer.clone(),
        request_reader: state.request_reader.clone(),
        agent_repo: state.agent_repo.clone(),
        result_store: state.result_store.clone(),
        policy_repo: state.policy_repo.clone(),
        clock: state.clock.clone(),
    };

    let input = get_result::GetResultInput { request_id: id };

    match uc.execute(input, &user).await {
        Ok(out) => {
            let mut builder =
                axum::http::Response::builder().header("content-type", "application/octet-stream");
            if let Some(len) = out.stream.content_length {
                builder = builder.header("content-length", len);
            }
            Ok(builder
                .body(axum::body::Body::from_stream(out.stream.stream))
                .unwrap())
        }
        Err(e) => Err(map_error(e)),
    }
}

pub async fn list_results(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> ApiResult {
    let results = state
        .request_reader
        .list_results_for_user(
            &user.subject_id,
            &user.groups,
            &user
                .roles
                .iter()
                .map(|r| r.name.clone())
                .collect::<Vec<_>>(),
            50,
        )
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

/// Compute queue_hint for a dispatched request by checking eligible agents.
fn compute_queue_hint(
    request: &dbward_domain::entities::Request,
    state: &AppState,
) -> Option<&'static str> {
    use dbward_domain::entities::{AgentDerivedStatus, AgentStatus, RequestStatus};

    if request.status != RequestStatus::Dispatched {
        return None;
    }

    let agents = match state.agent_repo.list() {
        Ok(a) => a,
        Err(_) => return None,
    };

    let now = state.clock.now();

    // Filter to agents whose capabilities include this request's db/env
    let eligible: Vec<_> = agents
        .iter()
        .filter(|a| {
            a.databases.iter().any(|cap| {
                cap.database == request.database && cap.environment == request.environment
            })
        })
        .collect();

    if eligible.is_empty() {
        return Some("no_agents");
    }

    // Offline takes priority — agent is truly gone
    let all_offline = eligible
        .iter()
        .all(|a| a.derived_status(now) == AgentDerivedStatus::Offline);
    if all_offline {
        return Some("no_agents");
    }

    // Draining — agent is alive but refusing new work
    let all_draining = eligible.iter().all(|a| a.status == AgentStatus::Draining);
    if all_draining {
        return Some("agents_draining");
    }

    let all_saturated = eligible
        .iter()
        .all(|a| a.derived_status(now) == AgentDerivedStatus::Saturated);
    if all_saturated {
        return Some("agents_saturated");
    }

    None
}
