use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use dbward_app::use_cases::{
    agent_claim::AgentClaimInput, agent_heartbeat::AgentHeartbeatInput, agent_poll::AgentPollInput,
    agent_submit_result::AgentSubmitResultInput,
};
use dbward_domain::auth::{AuthUser, SubjectType};
use serde::Deserialize;

use crate::middleware::trusted_proxies::ClientIp;
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
    pub status: Option<dbward_api_types::agent::AgentStatusReport>,
    #[serde(default)]
    pub agent_version: Option<String>,
}

#[derive(Deserialize)]
pub struct PollBodyCapabilities {
    pub scopes: Vec<PollScopeBody>,
    #[serde(default)]
    pub operations: Vec<dbward_domain::values::Operation>,
}

#[derive(Deserialize)]
pub struct PollScopeBody {
    pub database: String,
    pub environment: String,
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

    use dbward_domain::entities::DatabaseCapability;
    use dbward_domain::values::{DatabaseName, Environment};

    // Validate: reject wildcards
    for s in &body.capabilities.scopes {
        if s.database == "*" || s.environment == "*" {
            return Err(map_error(dbward_app::error::AppError::Validation(
                "wildcard '*' is not allowed in scopes".into(),
            )));
        }
    }

    // Dedup at string level
    let unique_scopes: Vec<&PollScopeBody> = {
        let mut seen = std::collections::HashSet::new();
        body.capabilities
            .scopes
            .iter()
            .filter(|s| seen.insert((&s.database, &s.environment)))
            .collect()
    };

    let capabilities: Vec<DatabaseCapability> = unique_scopes
        .iter()
        .map(|s| {
            let db = DatabaseName::new(&s.database).map_err(|_| {
                map_error(dbward_app::error::AppError::Validation(format!(
                    "invalid database in scope: {}",
                    s.database
                )))
            })?;
            let env = Environment::new(&s.environment).map_err(|_| {
                map_error(dbward_app::error::AppError::Validation(format!(
                    "invalid environment in scope: {}",
                    s.environment
                )))
            })?;
            Ok(DatabaseCapability {
                database: db,
                environment: env,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let (in_flight, max_concurrent, uptime_secs, draining, active_jobs) = match body.status {
        Some(ref s) => {
            let jobs = s
                .active_jobs
                .iter()
                .map(|j| dbward_domain::entities::ActiveJobEntry {
                    request_id: j.request_id.clone(),
                    operation: j.operation.clone(),
                    elapsed_secs: j.elapsed_secs,
                })
                .collect();
            (
                s.in_flight,
                s.max_concurrent,
                s.uptime_secs,
                s.draining,
                jobs,
            )
        }
        None => (0, 4, 0, false, vec![]),
    };

    let uc = state.agent().poll();
    let output = uc
        .execute(
            AgentPollInput {
                capabilities,
                operations: body.capabilities.operations,
                limit: body.limit,
                in_flight,
                max_concurrent,
                draining,
                uptime_secs,
                active_jobs,
            },
            &user,
        )
        .map_err(map_error)?;

    let min_agent_version = env!("CARGO_PKG_VERSION");
    let upgrade_required = body
        .agent_version
        .as_deref()
        .is_some_and(|av| !av.is_empty() && version_lt(av, min_agent_version));

    let jobs: Vec<serde_json::Value> = if upgrade_required {
        vec![]
    } else {
        output
            .jobs
            .iter()
            .map(|j| {
                serde_json::json!({
                    "id": j.id,
                    "created_by": j.created_by,
                    "operation": j.operation,
                    "environment": j.environment,
                    "database": j.database,
                    "detail": j.detail,
                })
            })
            .collect()
    };

    // Fetch pending dry-run jobs
    let db_pairs: Vec<(String, String)> = unique_scopes
        .iter()
        .map(|s| (s.database.clone(), s.environment.clone()))
        .collect();
    let dry_run_jobs: Vec<serde_json::Value> = if upgrade_required || db_pairs.is_empty() {
        vec![]
    } else {
        match state
            .agent()
            .dry_run_repo()
            .find_pending_for_agent(&db_pairs)
        {
            Ok(jobs) => jobs
                .iter()
                .map(|j| {
                    serde_json::json!({
                        "id": j.id,
                        "request_id": j.request_id,
                        "database": j.database_name,
                        "environment": j.environment,
                        "sql": j.sql_text,
                    })
                })
                .collect(),
            Err(e) => {
                tracing::warn!(%e, "failed to fetch dry-run jobs");
                vec![]
            }
        }
    };

    // Preflight jobs: atomically claim pending jobs for this agent's scopes
    let preflight_jobs: Vec<serde_json::Value> = if upgrade_required || db_pairs.is_empty() {
        vec![]
    } else {
        // Shared budget: normal jobs already allocated, use remainder for preflight
        let normal_count = jobs.len() as u32;
        let status_in_flight = body.status.as_ref().map(|s| s.in_flight).unwrap_or(0);
        let max_concurrent = body.status.as_ref().map(|s| s.max_concurrent).unwrap_or(1);
        let in_flight_preflight = body.status.as_ref().map(|s| s.in_flight_preflight).unwrap_or(0);
        let total_available = max_concurrent.saturating_sub(status_in_flight).saturating_sub(in_flight_preflight);
        let remaining = total_available.saturating_sub(normal_count) as usize;

        if remaining == 0 {
            vec![]
        } else {
            match state
                .agent()
                .preflight_job_repo()
                .claim_for_agent(&user.subject_id, &db_pairs, remaining)
            {
                Ok(claimed) => claimed
                    .iter()
                    .map(|j| {
                        serde_json::json!({
                            "id": j.id,
                            "database": j.database_name,
                            "environment": j.environment,
                            "sql": j.sql_text,
                            "claim_token": j.claim_token,
                        })
                    })
                    .collect(),
                Err(e) => {
                    tracing::warn!(%e, "failed to claim preflight jobs");
                    vec![]
                }
            }
        }
    };

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "jobs": jobs,
            "dry_run_jobs": dry_run_jobs,
            "preflight_jobs": preflight_jobs,
            "server_version": env!("CARGO_PKG_VERSION"),
            "min_agent_version": min_agent_version,
            "upgrade_required": upgrade_required,
        })),
    ))
}

pub async fn claim(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    client_ip: Option<Extension<ClientIp>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    require_agent(&user)?;

    if state.draining.load(std::sync::atomic::Ordering::SeqCst) {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "server_shutting_down"})),
        ));
    }

    let audit_ctx = super::extract_audit_context(
        client_ip.as_ref().map(|e| &e.0),
        connect_info.as_ref().map(|e| &e.0),
    );

    let agent = state
        .agent()
        .agent_repo()
        .get(&user.subject_id)
        .map_err(map_error)?
        .ok_or_else(|| {
            map_error(dbward_app::error::AppError::NotFound(
                "agent not registered".into(),
            ))
        })?;

    let uc = state.agent().claim();
    let output = uc
        .execute(
            AgentClaimInput {
                request_id: id,
                agent_id: user.subject_id.clone(),
                agent_databases: agent.databases,
            },
            &user,
            &audit_ctx,
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
            "max_rows": output.max_rows,
            "lease_expires_at": output.lease_expires_at.to_rfc3339(),
            "execution_plan": output.execution_plan,
            "execution_plan_json": output.execution_plan_json,
        })),
    ))
}

pub async fn heartbeat(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    require_agent(&user)?;
    let uc = state.agent().heartbeat();
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
    #[serde(default)]
    pub rows_affected: Option<u64>,
    #[serde(default)]
    pub duration_ms: Option<u64>,
}

pub async fn submit_result(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    client_ip: Option<Extension<ClientIp>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    Path(id): Path<String>,
    Json(body): Json<SubmitResultBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    require_agent(&user)?;
    let audit_ctx = super::extract_audit_context(
        client_ip.as_ref().map(|e| &e.0),
        connect_info.as_ref().map(|e| &e.0),
    );
    let uc = state.agent().submit_result();
    let result_data = body.result_data.map(|s| s.into_bytes());
    let output = uc
        .execute(
            AgentSubmitResultInput {
                execution_id: id,
                success: body.success,
                result_data,
                error_message: body.error_message,
                rows_affected: body.rows_affected,
                duration_ms: body.duration_ms,
            },
            &user,
            &audit_ctx,
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

    let agents = state.agent().agent_repo().list().map_err(map_error)?;
    let now = chrono::Utc::now();

    let enriched: Vec<serde_json::Value> = agents
        .iter()
        .map(|a| {
            let derived = a.derived_status(now);
            let is_draining = a.status == dbward_domain::entities::AgentStatus::Draining;
            let display_status = if derived == dbward_domain::entities::AgentDerivedStatus::Offline
            {
                "offline"
            } else if is_draining {
                "draining"
            } else if derived == dbward_domain::entities::AgentDerivedStatus::Saturated {
                "saturated"
            } else {
                "healthy"
            };
            let last_poll_ago_secs = a
                .last_seen
                .map(|ls| now.signed_duration_since(ls).num_seconds().max(0))
                .unwrap_or(9999);
            let active_jobs = if display_status == "offline" {
                &[][..]
            } else {
                &a.active_jobs[..]
            };
            let uptime = if display_status == "offline" {
                0
            } else {
                a.uptime_secs
            };
            serde_json::json!({
                "id": a.id,
                "status": display_status,
                "last_poll_ago_secs": last_poll_ago_secs,
                "in_flight": a.in_flight,
                "max_concurrent": a.max_concurrent,
                "uptime_secs": uptime,
                "active_jobs": active_jobs,
                "capabilities": { "scopes": a.databases },
            })
        })
        .collect();

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({ "agents": enriched })),
    ))
}

fn version_lt(a: &str, b: &str) -> bool {
    let parse = |s: &str| -> Vec<u32> { s.split('.').filter_map(|p| p.parse().ok()).collect() };
    parse(a) < parse(b)
}

#[derive(Deserialize)]
pub struct SchemaSyncBody {
    pub database: String,
    pub environment: String,
    pub dialect: String,
    pub status: String,
    pub snapshot: Option<serde_json::Value>,
    pub error_message: Option<String>,
}

pub async fn schema_sync(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Json(body): Json<SchemaSyncBody>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    require_agent(&user)?;

    let uc = state.agent().schema_sync();
    uc.execute(dbward_app::use_cases::schema_sync::SchemaSyncInput {
        agent_id: user.subject_id.clone(),
        database: body.database,
        environment: body.environment,
        dialect: body.dialect,
        status: body.status,
        snapshot: body.snapshot,
        error_message: body.error_message,
    })
    .map_err(map_error)?;

    Ok(StatusCode::OK)
}

pub async fn dry_run_claim(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    require_agent(&user)?;

    let uc = state.agent().dry_run_claim();
    let claim_token = uc.execute(&id, &user.subject_id).map_err(map_error)?;
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({"claim_token": claim_token})),
    ))
}

#[derive(Deserialize)]
pub struct DryRunResultBody {
    pub claim_token: String,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
}

pub async fn dry_run_result(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    Json(body): Json<DryRunResultBody>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    require_agent(&user)?;

    let uc = state.agent().dry_run_submit();
    let result_str = body.result.as_ref().map(|v| v.to_string());
    uc.execute(dbward_app::use_cases::dry_run::DryRunResultInput {
        job_id: &id,
        agent_id: &user.subject_id,
        claim_token: &body.claim_token,
        result_json: result_str.as_deref(),
        error: body.error.as_deref(),
    })
    .map_err(map_error)?;

    Ok(StatusCode::OK)
}

// --- Preflight Result ---

#[derive(serde::Deserialize)]
pub struct PreflightResultBody {
    pub job_id: String,
    pub claim_token: String,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
}

pub async fn preflight_result(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Json(body): Json<PreflightResultBody>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    require_agent(&user)?;

    // Size validation
    if let Some(ref r) = body.result {
        if r.to_string().len() > 256 * 1024 {
            return Err(map_error(dbward_app::error::AppError::PayloadTooLarge(
                "result exceeds 256KB".into(),
            )));
        }
    }
    if let Some(ref e) = body.error {
        if e.len() > 4096 {
            return Err(map_error(dbward_app::error::AppError::PayloadTooLarge(
                "error exceeds 4KB".into(),
            )));
        }
    }

    let now = chrono::Utc::now().to_rfc3339();
    let repo = state.agent().preflight_job_repo().clone();
    let notifier = state.agent().preflight_notifier().clone();

    let job_id = body.job_id.clone();
    let agent_id = user.subject_id.clone();
    let claim_token = body.claim_token.clone();

    let updated = if let Some(ref error) = body.error {
        let error = error.clone();
        tokio::task::spawn_blocking(move || {
            repo.fail(&job_id, &agent_id, &claim_token, &error, &now)
        })
        .await
        .map_err(|_| map_error(dbward_app::error::AppError::Internal("task join".into())))?
        .map_err(map_error)?
    } else {
        let result_json = body
            .result
            .as_ref()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "{}".into());
        tokio::task::spawn_blocking(move || {
            repo.complete(&job_id, &agent_id, &claim_token, &result_json, &now)
        })
        .await
        .map_err(|_| map_error(dbward_app::error::AppError::Internal("task join".into())))?
        .map_err(map_error)?
    };

    if updated {
        notifier.notify(&body.job_id);
        Ok(StatusCode::OK)
    } else {
        // Job was already expired, completed, or claim mismatch
        Err(map_error(dbward_app::error::AppError::Gone(
            "preflight job already completed or expired".into(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::version_lt;

    #[test]
    fn version_comparison() {
        assert!(version_lt("0.1.2", "0.1.3"));
        assert!(version_lt("0.1.9", "0.1.10"));
        assert!(!version_lt("0.1.10", "0.1.9"));
        assert!(!version_lt("0.1.2", "0.1.2"));
        assert!(version_lt("0.1.0", "0.2.0"));
        assert!(!version_lt("0.2.0", "0.1.99"));
    }
}
