use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
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
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "agent token required", "code": "forbidden"})),
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct PollBody {
    pub capabilities: PollBodyCapabilities,
    pub limit: Option<u32>,
    #[serde(default)]
    pub status: Option<PollBodyStatus>,
}

#[derive(Deserialize)]
pub struct PollBodyCapabilities {
    pub databases: Vec<String>,
    #[serde(default)]
    pub environments: Vec<String>,
    #[serde(default)]
    pub operations: Vec<dbward_domain::values::Operation>,
}

#[derive(Deserialize)]
pub struct PollBodyStatus {
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
    if state.draining.load(std::sync::atomic::Ordering::SeqCst) {
        return Ok((StatusCode::OK, Json(serde_json::json!({"jobs": []}))));
    }

    require_agent(&user)?;

    // Convert PollBodyCapabilities to Vec<DatabaseCapability>
    use dbward_domain::entities::DatabaseCapability;
    use dbward_domain::values::{DatabaseName, Environment};
    let envs = if body.capabilities.environments.is_empty() {
        vec![Environment::wildcard()]
    } else {
        body.capabilities
            .environments
            .iter()
            .map(|e| {
                Environment::new(e).map_err(|_| {
                    map_error(dbward_app::error::AppError::Validation(format!(
                        "invalid environment: {e}"
                    )))
                })
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    let databases: Vec<DatabaseName> = body
        .capabilities
        .databases
        .iter()
        .map(|d| {
            DatabaseName::new(d).map_err(|_| {
                map_error(dbward_app::error::AppError::Validation(format!(
                    "invalid database: {d}"
                )))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let capabilities: Vec<DatabaseCapability> = databases
        .iter()
        .flat_map(|db| {
            envs.iter().map(move |env| DatabaseCapability {
                database: db.clone(),
                environment: env.clone(),
            })
        })
        .collect();

    let (in_flight, max_concurrent) = match body.status {
        Some(ref s) => (s.in_flight, s.max_concurrent),
        None => (0, 4),
    };

    let uc = AgentPoll {
        authorizer: state.authorizer.clone(),
        agent_repo: state.agent_repo.clone(),
        audit_logger: state.audit_logger.clone(),
        license_checker: state.license_checker.clone(),
        clock: state.clock.clone(),
    };
    let output = uc
        .execute(
            AgentPollInput {
                capabilities,
                operations: body.capabilities.operations,
                limit: body.limit,
                in_flight,
                max_concurrent,
            },
            &user,
        )
        .map_err(map_error)?;

    Ok((
        StatusCode::OK,
        Json(
            serde_json::json!({ "jobs": output.jobs.iter().map(|j| serde_json::json!({
        "id": j.id,
        "created_by": j.created_by,
        "operation": j.operation,
        "environment": j.environment,
        "database": j.database,
        "detail": j.detail,
    })).collect::<Vec<_>>() }),
        ),
    ))
}

pub async fn claim(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    require_agent(&user)?;

    if state.draining.load(std::sync::atomic::Ordering::SeqCst) {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "server_shutting_down"})),
        ));
    }

    // Fetch agent's registered capabilities
    let agent = state
        .agent_repo
        .get(&user.subject_id)
        .map_err(map_error)?
        .ok_or_else(|| {
            map_error(dbward_app::error::AppError::NotFound(
                "agent not registered".into(),
            ))
        })?;

    let uc = AgentClaim {
        authorizer: state.authorizer.clone(),
        request_repo: state.request_repo.clone(),
        agent_repo: state.agent_repo.clone(),
        policy: state.policy_evaluator.clone(),
        token_signer: state.token_signer.clone(),
        event_dispatcher: state.event_dispatcher.clone(),
        clock: state.clock.clone(),
        id_gen: state.id_generator.clone(),
        user_repo: state.user_repo.clone(),
        role_resolver: state.role_resolver.clone(),
    };
    let output = uc
        .execute(
            AgentClaimInput {
                request_id: id,
                agent_id: user.subject_id.clone(),
                agent_databases: agent.databases,
            },
            &user,
        )
        .map_err(map_error)?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "execution_id": output.execution_id,
            "request_id": output.request_id,
            "execution_token": output.execution_token,
            "operation": output.operation,
            "database": output.database,
            "environment": output.environment,
            "detail": output.detail,
            "statement_timeout_secs": output.statement_timeout_secs,
            "lease_expires_at": output.lease_expires_at.to_rfc3339(),
        })),
    ))
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
        policy: state.policy_evaluator.clone(),
        event_dispatcher: state.event_dispatcher.clone(),
        clock: state.clock.clone(),
    };
    let output = uc
        .execute(AgentHeartbeatInput { execution_id: id }, &user)
        .map_err(map_error)?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({ "cancelled": output.cancelled })),
    ))
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
        result_channel: state.result_channel.clone(),
        event_dispatcher: state.event_dispatcher.clone(),
        clock: state.clock.clone(),
        max_persist_bytes: state.max_persist_bytes,
        policy_repo: state.policy_repo.clone(),
    };
    let result_data = body.result_data.map(|s| s.into_bytes());
    let output = uc
        .execute(
            AgentSubmitResultInput {
                execution_id: id,
                success: body.success,
                result_data,
                error_message: body.error_message,
            },
            &user,
        )
        .await
        .map_err(map_error)?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "request_id": output.request_id,
            "status": output.status,
        })),
    ))
}

pub async fn list_agents(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    use dbward_domain::auth::Permission;

    state
        .authorizer
        .authorize_global(&user, Permission::MetricsView)
        .map_err(|e| map_error(dbward_app::error::AppError::Forbidden(e)))?;

    let agents = state.agent_repo.list().map_err(map_error)?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({ "agents": agents })),
    ))
}
