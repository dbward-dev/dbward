use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use serde_json::json;

use dbward_app::error::AppError;
use dbward_app::use_cases::{create_request, list_requests, stream_result};
use dbward_domain::auth::AuthUser;
use dbward_domain::values::{DatabaseName, Environment, Operation};

use crate::middleware::trusted_proxies::ClientIp;
use crate::state::AppState;

use super::map_error;

type ApiResult =
    Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)>;

pub async fn create(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    client_ip: Option<Extension<ClientIp>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    Json(body): Json<dbward_api_types::requests::CreateRequestBody>,
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

    let database = DatabaseName::new(&body.database)
        .map_err(|e| map_error(AppError::Validation(e.to_string())))?;
    let environment = Environment::new(&body.environment)
        .map_err(|e| map_error(AppError::Validation(e.to_string())))?;

    let operation = match body.operation.as_str() {
        "" => Operation::ExecuteSelect,
        s => s
            .parse::<Operation>()
            .map_err(|e| map_error(AppError::Validation(e)))?,
    };

    let input = create_request::CreateRequestInput {
        database,
        environment,
        operation,
        detail: body.detail,
        reason: body.reason,
        emergency: body.emergency,
        allow_ddl: body.allow_ddl,
        idempotency_key: body.idempotency_key,
        share_with: body.share_with,
        no_store: body.no_store,
        metadata_json: body
            .metadata
            .as_ref()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "{}".into()),
        channel: create_request::RequestChannel::Api,
    };

    let uc = state.requests().create();

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
    let uc = state.requests().list();
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

#[derive(Debug, serde::Deserialize)]
pub struct GetResultQuery {
    pub execution_id: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct ListExecutionsQuery {
    pub limit: Option<u32>,
}

#[derive(Debug, serde::Deserialize)]
pub struct ListResultsQuery {
    pub limit: Option<u32>,
}

pub async fn get(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    axum::extract::Query(query): axum::extract::Query<GetRequestQuery>,
) -> ApiResult {
    let uc = state.requests().get();

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
                match state.request_reader().get(&id) {
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
            "decision_trace": output.request.decision_trace_json.as_deref()
                .and_then(|j| serde_json::from_str::<serde_json::Value>(j)
                    .map_err(|e| { tracing::warn!(%e, "failed to parse decision_trace_json"); e })
                    .ok()),
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
    let uc = state.requests().approve();

    let input = dbward_app::use_cases::approve_request::ApproveRequestInput {
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
    let uc = state.requests().reject();

    let input = dbward_app::use_cases::reject_request::RejectRequestInput {
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
    let uc = state.requests().cancel();

    let input = dbward_app::use_cases::cancel_request::CancelRequestInput {
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

pub async fn resume(
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
    let uc = state.requests().resume();

    let input = dbward_app::use_cases::resume_request::ResumeRequestInput { request_id: id };

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
    let uc = state.requests().stream_result();

    let input = stream_result::StreamResultInput {
        request_id: id.clone(),
        timeout_secs: Some(300),
    };

    match uc.execute(input, &user).await {
        Ok(out) => match out.data {
            stream_result::StreamResultData::Result(summary) => Ok((
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
            stream_result::StreamResultData::TerminalPlaceholder { success: _ } => {
                let get_uc = state.requests().get_result();
                let get_input = dbward_app::use_cases::get_result::GetResultInput {
                    request_id: id.clone(),
                    execution_id: None,
                };
                match get_uc.execute(get_input, &user).await {
                    Ok(stored_out) => {
                        let bytes = stored_out.stream.collect().await.map_err(map_error)?;
                        Ok((
                            StatusCode::OK,
                            Json(build_result_envelope(
                                &stored_out.execution_id,
                                stored_out.success,
                                &bytes,
                            )),
                        ))
                    }
                    Err(AppError::Gone(msg)) => Err(map_error(AppError::Gone(msg))),
                    Err(e) => Err(map_error(e)),
                }
            }
            stream_result::StreamResultData::Timeout => {
                Ok((StatusCode::NO_CONTENT, Json(json!({}))))
            }
        },
        Err(e) => Err(map_error(e)),
    }
}

pub async fn get_result(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    axum::extract::Query(query): axum::extract::Query<GetResultQuery>,
) -> ApiResult {
    let uc = state.requests().get_result();

    let input = dbward_app::use_cases::get_result::GetResultInput {
        request_id: id,
        execution_id: query.execution_id,
    };

    let out = uc.execute(input, &user).await.map_err(map_error)?;

    let bytes = out.stream.collect().await.map_err(map_error)?;
    let envelope = build_result_envelope(&out.execution_id, out.success, &bytes);
    Ok((StatusCode::OK, Json(envelope)))
}

fn build_result_envelope(execution_id: &str, success: bool, raw_bytes: &[u8]) -> serde_json::Value {
    let raw_text = String::from_utf8_lossy(raw_bytes);

    if !success {
        let stored: serde_json::Value = serde_json::from_slice(raw_bytes).unwrap_or(json!(null));
        return json!({
            "_dbward_result": true,
            "execution_id": execution_id,
            "success": false,
            "result_data": null,
            "rows_affected": null,
            "truncated": false,
            "error_message": stored.get("error").or_else(|| stored.get("error_message")),
        });
    }

    let stored: serde_json::Value = serde_json::from_slice(raw_bytes).unwrap_or(json!(null));

    json!({
        "_dbward_result": true,
        "execution_id": execution_id,
        "success": true,
        "result_data": raw_text.as_ref(),
        "rows_affected": stored.get("rows_affected"),
        "truncated": stored.get("truncated").and_then(|v| v.as_bool()).unwrap_or(false),
        "error_message": null,
    })
}

pub async fn list_executions(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    axum::extract::Query(query): axum::extract::Query<ListExecutionsQuery>,
) -> ApiResult {
    // Authorize via get request UC
    let uc = state.requests().get();
    uc.execute(&id, &user).map_err(map_error)?;

    let executions = state
        .agent()
        .agent_repo()
        .find_executions_for_request(&id)
        .map_err(map_error)?;

    let limit = query.limit.unwrap_or(20).min(100) as usize;

    let mut sorted = executions;
    sorted.sort_by_key(|e| std::cmp::Reverse(e.created_at));

    let stored_ids: std::collections::HashSet<String> = state
        .request_reader()
        .find_stored_execution_ids(&id)
        .map_err(map_error)?
        .into_iter()
        .collect();

    let items: Vec<serde_json::Value> = sorted
        .into_iter()
        .take(limit)
        .map(|e| {
            let has_stored = stored_ids.contains(&e.id);
            json!({
                "id": e.id,
                "status": format!("{:?}", e.status).to_lowercase(),
                "agent_id": e.agent_id,
                "created_at": e.created_at.to_rfc3339(),
                "started_at": e.started_at.map(|t| t.to_rfc3339()),
                "finished_at": e.finished_at.map(|t| t.to_rfc3339()),
                "error_message": e.error_message,
                "has_stored_result": has_stored,
            })
        })
        .collect();

    Ok((StatusCode::OK, Json(json!({ "executions": items }))))
}

pub async fn list_results(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    axum::extract::Query(query): axum::extract::Query<ListResultsQuery>,
) -> ApiResult {
    let limit = query.limit.unwrap_or(50).min(100);
    let results = state
        .list_results_for_user(&user, limit)
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

    let agents = match state.agent().agent_repo().list() {
        Ok(a) => a,
        Err(_) => return None,
    };

    let now = state.clock().now();

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

    let all_offline = eligible
        .iter()
        .all(|a| a.derived_status(now) == AgentDerivedStatus::Offline);
    if all_offline {
        return Some("no_agents");
    }

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
