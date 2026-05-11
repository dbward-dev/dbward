use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    Json,
};
use dbward_app::use_cases::{
    agent_claim::{AgentClaim, AgentClaimInput},
    agent_heartbeat::{AgentHeartbeat, AgentHeartbeatInput},
    agent_poll::{AgentPoll, AgentPollInput},
    agent_submit_result::{AgentSubmitResult, AgentSubmitResultInput},
};
use dbward_domain::auth::{AuthUser, SubjectType};
use serde::Deserialize;

use crate::state::AppState;

use super::map_error;

fn require_agent(user: &AuthUser) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if user.subject_type != SubjectType::Agent {
        return Err((StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "agent token required", "code": "forbidden"}))));
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct PollBody {
    pub capabilities: Vec<dbward_domain::entities::DatabaseCapability>,
    #[serde(default)]
    pub operations: Vec<dbward_domain::values::Operation>,
    pub limit: Option<u32>,
    #[serde(default)]
    pub in_flight: u32,
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: u32,
}

fn default_max_concurrent() -> u32 {
    4
}

pub async fn poll(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Json(body): Json<PollBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    require_agent(&user)?;
    let uc = AgentPoll {
        authorizer: state.authorizer.clone(),
        agent_repo: state.agent_repo.clone(),
        clock: state.clock.clone(),
    };
    let output = uc.execute(
        AgentPollInput {
            capabilities: body.capabilities,
            operations: body.operations,
            limit: body.limit,
            in_flight: body.in_flight,
            max_concurrent: body.max_concurrent,
        },
        &user,
    ).map_err(map_error)?;

    Ok((StatusCode::OK, Json(serde_json::json!({ "jobs": output.jobs.iter().map(|j| serde_json::json!({
        "id": j.id,
        "created_by": j.created_by,
        "operation": j.operation,
        "environment": j.environment,
        "database": j.database,
        "detail": j.detail,
    })).collect::<Vec<_>>() }))))
}

pub async fn claim(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    require_agent(&user)?;

    // Fetch agent's registered capabilities
    let agent = state.agent_repo.get(&user.subject_id)
        .map_err(map_error)?
        .ok_or_else(|| map_error(dbward_app::error::AppError::NotFound("agent not registered".into())))?;

    let uc = AgentClaim {
        authorizer: state.authorizer.clone(),
        request_repo: state.request_repo.clone(),
        agent_repo: state.agent_repo.clone(),
        policy: state.policy_evaluator.clone(),
        token_signer: state.token_signer.clone(),
        event_dispatcher: state.event_dispatcher.clone(),
        clock: state.clock.clone(),
        id_gen: state.id_generator.clone(),
    };
    let output = uc.execute(
        AgentClaimInput {
            request_id: id,
            agent_id: user.subject_id.clone(),
            agent_databases: agent.databases,
            agent_operations: vec![],
        },
        &user,
    ).map_err(map_error)?;

    Ok((StatusCode::OK, Json(serde_json::json!({
        "execution_id": output.execution_id,
        "request_id": output.request_id,
        "execution_token": output.execution_token,
        "operation": output.operation,
        "database": output.database,
        "environment": output.environment,
        "detail": output.detail,
        "statement_timeout_secs": output.statement_timeout_secs,
    }))))
}

pub async fn heartbeat(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    require_agent(&user)?;
    let uc = AgentHeartbeat {
        authorizer: state.authorizer.clone(),
        agent_repo: state.agent_repo.clone(),
        request_repo: state.request_repo.clone(),
        event_dispatcher: state.event_dispatcher.clone(),
        clock: state.clock.clone(),
    };
    let output = uc.execute(AgentHeartbeatInput { execution_id: id }, &user)
        .map_err(map_error)?;

    Ok((StatusCode::OK, Json(serde_json::json!({ "cancelled": output.cancelled }))))
}

#[derive(Deserialize)]
pub struct SubmitResultBody {
    pub success: bool,
    pub result_data: Option<String>,
    pub error_message: Option<String>,
}

pub async fn submit_result(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    Json(body): Json<SubmitResultBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    require_agent(&user)?;
    let uc = AgentSubmitResult {
        authorizer: state.authorizer.clone(),
        agent_repo: state.agent_repo.clone(),
        request_repo: state.request_repo.clone(),
        result_store: state.result_store.clone(),
        event_dispatcher: state.event_dispatcher.clone(),
        clock: state.clock.clone(),
    };
    let result_data = body.result_data.map(|s| s.into_bytes());
    let output = uc.execute(
        AgentSubmitResultInput {
            execution_id: id,
            success: body.success,
            result_data,
            error_message: body.error_message,
        },
        &user,
    ).await.map_err(map_error)?;

    Ok((StatusCode::OK, Json(serde_json::json!({
        "request_id": output.request_id,
        "status": output.status,
    }))))
}

pub async fn list_agents(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    use dbward_domain::auth::Permission;

    state.authorizer.authorize_global(&user, Permission::MetricsView)
        .map_err(|e| map_error(dbward_app::error::AppError::Forbidden(e)))?;

    let agents = state.agent_repo.list()
        .map_err(map_error)?;

    Ok((StatusCode::OK, Json(serde_json::json!({ "agents": agents }))))
}
