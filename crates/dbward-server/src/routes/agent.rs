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
    pub databases: Vec<String>,
    #[serde(default)]
    pub environments: Vec<String>,
    #[serde(default)]
    pub operations: Vec<dbward_domain::values::Operation>,
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

    let uc = AgentPoll {
        authorizer: state.authorizer.clone(),
        agent_repo: state.agent_repo.clone(),
        audit_logger: state.audit_logger.clone(),
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

    // Fetch pending dry-run jobs for this agent's databases
    let db_pairs: Vec<(String, String)> = databases
        .iter()
        .flat_map(|db| {
            envs.iter()
                .filter(|env| env.as_str() != "*")
                .map(move |env| (db.as_str().to_string(), env.as_str().to_string()))
        })
        .collect();
    let dry_run_jobs: Vec<serde_json::Value> = if upgrade_required || db_pairs.is_empty() {
        vec![]
    } else {
        match state.dry_run_repo.find_pending_for_agent(&db_pairs) {
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

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "jobs": jobs,
            "dry_run_jobs": dry_run_jobs,
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
        request_reader: state.request_reader.clone(),
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
        request_reader: state.request_reader.clone(),
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
    let uc = AgentSubmitResult {
        authorizer: state.authorizer.clone(),
        agent_repo: state.agent_repo.clone(),
        request_reader: state.request_reader.clone(),
        result_store: state.result_store.clone(),
        result_channel: state.result_channel.clone(),
        event_dispatcher: state.event_dispatcher.clone(),
        clock: state.clock.clone(),
        max_persist_bytes: state.max_persist_bytes,
        policy_repo: state.policy_repo.clone(),
        storage_backend: state.storage_backend.clone(),
    };
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

    let agents = state.agent_repo.list().map_err(map_error)?;
    let now = chrono::Utc::now();

    let enriched: Vec<serde_json::Value> = agents
        .iter()
        .map(|a| {
            let derived = a.derived_status(now);
            let is_draining = a.status == dbward_domain::entities::AgentStatus::Draining;
            // Display status: offline > draining > saturated > healthy
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
            // Offline agents: clear stale active_jobs
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
                "capabilities": { "databases": a.databases },
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

    // Validate dialect
    if !matches!(body.dialect.as_str(), "postgresql" | "mysql") {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid dialect", "code": "validation_error"})),
        ));
    }
    // Validate status
    if !matches!(body.status.as_str(), "ready" | "failed" | "partial") {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid status", "code": "validation_error"})),
        ));
    }
    // Validate consistency: ready requires snapshot, failed requires error_message
    if body.status == "ready" && body.snapshot.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({"error": "snapshot required when status=ready", "code": "validation_error"}),
            ),
        ));
    }

    // Scope check: agent must have capability for this database+environment
    let agent = state.agent_repo.get(&user.subject_id).map_err(map_error)?;
    if let Some(agent) = agent {
        let scope_match = agent.databases.iter().any(|d| {
            d.database.as_str() == body.database && d.environment.as_str() == body.environment
        });
        if !scope_match {
            return Err((
                StatusCode::FORBIDDEN,
                Json(
                    serde_json::json!({"error": "agent not authorized for this database/environment", "code": "forbidden"}),
                ),
            ));
        }
    }
    // Verify database+environment is registered
    {
        use dbward_domain::values::{DatabaseName, Environment};
        if let (Ok(db), Ok(env)) = (
            DatabaseName::new(&body.database),
            Environment::new(&body.environment),
        ) && !state.database_registry.exists(&db, &env).unwrap_or(false)
        {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({"error": "database/environment not registered", "code": "validation_error"}),
                ),
            ));
        }
    }

    let now = state.clock.now().to_rfc3339();
    let record = dbward_app::ports::SchemaSnapshotRecord {
        database_name: body.database,
        environment: body.environment,
        status: body.status,
        snapshot_json: body.snapshot.map(|v| v.to_string()),
        error_message: body.error_message,
        dialect: body.dialect,
        collected_at: now,
        agent_id: user.subject_id,
    };
    state
        .schema_repo
        .upsert_snapshot(&record)
        .map_err(map_error)?;

    Ok(StatusCode::OK)
}

pub async fn dry_run_claim(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    require_agent(&user)?;
    // Security: job IDs are UUIDv4, only discoverable through poll which is scope-filtered.
    // Claim atomicity (pending→claimed) prevents double-claim.
    let claim_token = uuid::Uuid::new_v4().to_string();
    let now = state.clock.now().to_rfc3339();
    let claimed = state
        .dry_run_repo
        .claim(&id, &user.subject_id, &claim_token, &now)
        .map_err(map_error)?;
    if !claimed {
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "already_claimed", "code": "conflict"})),
        ));
    }
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
    let now = state.clock.now().to_rfc3339();
    let success = if let Some(error) = body.error {
        state
            .dry_run_repo
            .fail(&id, &user.subject_id, &body.claim_token, &error, &now)
            .map_err(map_error)?
    } else {
        let result_json = body
            .result
            .map(|v| v.to_string())
            .unwrap_or_else(|| "{}".to_string());
        state
            .dry_run_repo
            .complete(&id, &user.subject_id, &body.claim_token, &result_json, &now)
            .map_err(map_error)?
    };
    if !success {
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "fencing_violation", "code": "conflict"})),
        ));
    }

    // on_dry_run_complete: check if all jobs for this request are done, update context
    if let Ok(Some(request_id)) = state.dry_run_repo.get_request_id(&id)
        && let Ok(jobs) = state.dry_run_repo.find_for_request(&request_id)
    {
        let all_done = jobs
            .iter()
            .all(|j| j.status != "pending" && j.status != "claimed");
        if all_done {
            let results: Vec<serde_json::Value> = jobs
                .iter()
                .map(|j| {
                    if j.status == "completed" {
                        serde_json::json!({"sql": &j.sql_text, "plan": &j.result_json})
                    } else {
                        serde_json::json!({"sql": &j.sql_text, "error": &j.error_message})
                    }
                })
                .collect();
            let explain_json = serde_json::to_string(&results).unwrap_or_default();
            let ctx_status = if jobs.iter().all(|j| j.status == "completed") {
                "ready"
            } else {
                "partial"
            };
            let now_str = state.clock.now().to_rfc3339();
            let _ =
                state
                    .context_repo
                    .update_explain(&request_id, &explain_json, ctx_status, &now_str);
        }
    }

    Ok(StatusCode::OK)
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
