use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use serde_json::json;
use sha2::Digest;
use tracing::error;

use crate::auth;
use crate::authz::{self, Action, Resource};
use crate::state::AppState;

/// List all known agents (admin only).
pub(crate) async fn list_agents(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize_and_audit(&user, Action::ReadMetrics, Resource::Global, &state).await?;

    let conn = state.db().await;
    let agents = crate::db::agent_repo::list_agents(&conn)
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

    let now = chrono::Utc::now();
    let items: Vec<serde_json::Value> = agents
        .into_iter()
        .map(|a| {
            let caps: serde_json::Value =
                serde_json::from_str(&a.capabilities_json).unwrap_or(json!({}));
            let active_jobs: serde_json::Value =
                serde_json::from_str(&a.active_jobs_json).unwrap_or(json!([]));
            let last_poll_ago_secs = chrono::DateTime::parse_from_rfc3339(&a.last_seen_at)
                .map(|t| now.signed_duration_since(t).num_seconds().max(0))
                .unwrap_or(9999);
            let status = if a.draining {
                "draining"
            } else if last_poll_ago_secs > 60 {
                "offline"
            } else if a.in_flight >= a.max_concurrent {
                "saturated"
            } else {
                "healthy"
            };
            json!({
                "id": a.id,
                "status": status,
                "capabilities": caps,
                "last_seen_at": a.last_seen_at,
                "last_poll_ago_secs": last_poll_ago_secs,
                "in_flight": a.in_flight,
                "max_concurrent": a.max_concurrent,
                "available": (a.max_concurrent - a.in_flight).max(0),
                "draining": a.draining,
                "uptime_secs": a.uptime_secs,
                "active_jobs": active_jobs,
                "created_at": a.created_at,
            })
        })
        .collect();

    Ok(Json(json!({ "agents": items })))
}

// ---------------------------------------------------------------------------
// Agent endpoints
// ---------------------------------------------------------------------------

/// Agent polls for dispatchable jobs (approved / auto_approved / break_glass).
pub(crate) async fn agent_poll(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize_and_audit(&user, Action::AgentPoll, Resource::Global, &state).await?;

    let databases: Vec<String> = body["databases"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let environments: Vec<String> = body["environments"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let operations: Vec<String> = body["operations"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let conn = state.db().await;

    // Free tier: check agent limit for new agents only
    let is_existing: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM agents WHERE id = ?1)",
            rusqlite::params![user.user],
            |row| row.get(0),
        )
        .unwrap_or(false);
    if !is_existing {
        crate::limits::check_can_create(&conn, crate::limits::Resource::Agent, &state.license)?;
    }

    // Record agent capabilities for claim-time verification
    let caps_json = serde_json::to_string(&json!({
        "databases": databases,
        "environments": environments,
        "operations": operations,
    }))
    .unwrap_or_else(|_| "{}".into());
    // Parse agent status (optional, for observability)
    let agent_status = body["status"].as_object().map(|s| {
        let active_jobs_json = s.get("active_jobs")
            .map(|v| {
                let json = serde_json::to_string(v).unwrap_or_else(|_| "[]".into());
                if json.len() > 4096 { "[]".into() } else { json }
            })
            .unwrap_or_else(|| "[]".into());
        crate::db::agent_repo::AgentStatusReport {
            in_flight: s.get("in_flight").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
            max_concurrent: s.get("max_concurrent").and_then(|v| v.as_u64()).unwrap_or(1) as u32,
            draining: s.get("draining").and_then(|v| v.as_bool()).unwrap_or(false),
            uptime_secs: s.get("uptime_secs").and_then(|v| v.as_u64()).unwrap_or(0),
            active_jobs_json,
        }
    });

    crate::db::agent_repo::upsert_agent(&conn, &user.user, &user.token_id, &caps_json, agent_status.as_ref()).map_err(
        |e| crate::api_error::ApiError::internal(format!("agent registration failed: {e}")),
    )?;
    drop(conn);

    if !is_existing {
        let mut conn = state.db().await;
        let _ = crate::db::audit_event_repo::record_audit_event(
            &mut conn,
            crate::db::audit_event_repo::AuditEvent {
                event_type: "agent_registered",
                event_category: "agent",
                outcome: "success",
                actor_id: &user.user,
                actor_type: "agent",
                resource_type: Some("agent"),
                resource_id: Some(&user.user),
                peer_ip: None,
                client_ip: None,
                client_ip_source: None,
                request_id: None,
                operation: None,
                environment: None,
                database_name: None,
                detail_fingerprint: None,
                detail_raw: None,
                reason: None,
                metadata_json: &caps_json,
            },
            &headers,
            &state.audit_config,
            &state.trusted_proxies,
        );
    }

    let conn = state.db().await;

    // Free tier: check total unique database connections across all agents
    if !databases.is_empty() {
        crate::limits::check_database_limit(&conn, &state.license)?;
    }

    // Build dynamic WHERE clause for capability filtering
    let mut where_clauses = vec!["status = 'dispatched'".to_string()];
    let mut bind_values: Vec<String> = Vec::new();

    if super::requests::should_filter_capability(&databases) {
        let placeholders: Vec<String> = databases
            .iter()
            .enumerate()
            .map(|(i, _)| format!("?{}", bind_values.len() + i + 1))
            .collect();
        where_clauses.push(format!("database_name IN ({})", placeholders.join(",")));
        bind_values.extend(databases.clone());
    }
    if super::requests::should_filter_capability(&environments) {
        let placeholders: Vec<String> = environments
            .iter()
            .enumerate()
            .map(|(i, _)| format!("?{}", bind_values.len() + i + 1))
            .collect();
        where_clauses.push(format!("environment IN ({})", placeholders.join(",")));
        bind_values.extend(environments.clone());
    }
    if super::requests::should_filter_capability(&operations) {
        let placeholders: Vec<String> = operations
            .iter()
            .enumerate()
            .map(|(i, _)| format!("?{}", bind_values.len() + i + 1))
            .collect();
        where_clauses.push(format!("operation IN ({})", placeholders.join(",")));
        bind_values.extend(operations.clone());
    }

    let where_sql = where_clauses.join(" AND ");
    let limit = body["limit"].as_u64().unwrap_or(10).min(20) as usize;
    let query_sql = format!(
        "SELECT id, created_by, operation, environment, database_name, detail
         FROM requests WHERE {where_sql} ORDER BY created_at ASC LIMIT {limit}"
    );

    let mut stmt = conn
        .prepare(&query_sql)
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

    let rows: Vec<serde_json::Value> = stmt
        .query_map(rusqlite::params_from_iter(&bind_values), |row| {
            Ok(json!({
                "id": row.get::<_, String>(0)?,
                "created_by": row.get::<_, String>(1)?,
                "operation": row.get::<_, String>(2)?,
                "environment": row.get::<_, String>(3)?,
                "database_name": row.get::<_, String>(4)?,
                "detail": row.get::<_, String>(5)?,
            }))
        })
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

    Ok(Json(json!({"jobs": rows})))
}

/// Agent claims a job for execution.
pub(crate) async fn agent_claim(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(_body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize_and_audit(&user, Action::AgentClaim, Resource::Global, &state).await?;
    let agent_id = user.user.clone();

    let mut conn = state.db().await;

    let ctx = crate::db::request_repo::get_request_context(&conn, &id)
        .map_err(|_| crate::api_error::ApiError::not_found("request not found"))?;
    let (operation, environment, database, detail, status) = (
        ctx.operation,
        ctx.environment,
        ctx.database_name,
        ctx.detail,
        ctx.status,
    );

    if status != "dispatched" {
        return Err(crate::api_error::ApiError::conflict(format!(
            "request status is {status}, cannot claim"
        )));
    }

    authz::authorize_with_audit(
        &user,
        Action::AgentClaim,
        Resource::AgentExecution {
            agent_id: agent_id.clone(),
        },
        &mut conn,
    )?;

    // Verify agent has capability for this job
    if let Some(caps_json) = crate::db::agent_repo::get_agent_capabilities(&conn, &agent_id)
        && let Ok(caps) = serde_json::from_str::<serde_json::Value>(&caps_json)
    {
        let matches = |arr: &serde_json::Value, val: &str| -> bool {
            arr.as_array().is_none_or(|a| {
                a.is_empty()
                    || a.iter()
                        .any(|v| v.as_str() == Some(val) || v.as_str() == Some("*"))
            })
        };
        if !matches(&caps["databases"], &database)
            || !matches(&caps["environments"], &environment)
            || !matches(&caps["operations"], &operation)
        {
            return Err(crate::api_error::ApiError::forbidden(
                "agent lacks capability for this job",
            ));
        }
    }

    let token = state
        .token_signer
        .issue(&id, &operation, &environment, &database, &detail);
    let token_json = serde_json::to_string(&token)
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

    let Some(exec_id) = crate::db::agent_repo::create_execution_and_mark_running(
        &mut conn,
        &id,
        &agent_id,
        &token_json,
    )
    .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?
    else {
        return Err(crate::api_error::ApiError::conflict(
            "request status is no longer dispatched, cannot claim",
        ));
    };

    // Audit: execution_started
    if let Err(e) = crate::db::audit_event_repo::record_audit_event(&mut conn,
    crate::db::audit_event_repo::AuditEvent {
        event_type: "execution_started",
        event_category: "execution",
        outcome: "success",
        actor_id: &agent_id,
        actor_type: "agent",
        resource_type: Some("request"),
        resource_id: Some(&id),
        peer_ip: None,
        client_ip: None,
        client_ip_source: None,
        request_id: Some(&id),
        operation: Some(&operation),
        environment: Some(&environment),
        database_name: Some(&database),
        detail_fingerprint: None,
        detail_raw: None,
        reason: None,
        metadata_json: &serde_json::json!({
            "execution_id": exec_id,
        })
        .to_string(),
    }, &headers, &state.audit_config, &state.trusted_proxies) {
                error!(error = %e, "audit write failed");
            }

    Ok(Json(json!({
        "execution_id": exec_id,
        "request_id": id,
        "operation": operation,
        "environment": environment,
        "database": database,
        "detail": detail,
        "execution_token": token,
    })))
}

/// Agent heartbeat: extend lease while executing.
pub(crate) async fn agent_heartbeat(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize_and_audit(&user, Action::AgentPoll, Resource::Global, &state).await?;

    let conn = state.db().await;
    let new_expires = chrono::Utc::now() + chrono::Duration::seconds(300);
    let updated = conn
        .execute(
            "UPDATE agent_executions SET lease_expires_at = ?1
         WHERE id = ?2 AND status = 'claimed'",
            rusqlite::params![new_expires.to_rfc3339(), id],
        )
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

    if updated == 0 {
        return Err(crate::api_error::ApiError::new(
            StatusCode::NOT_FOUND,
            "execution not found or not claimed",
        ));
    }

    let cancelled: bool = conn.query_row(
        "SELECT r.status FROM requests r JOIN agent_executions e ON e.request_id = r.id WHERE e.id = ?1",
        rusqlite::params![id],
        |row| {
            let status: String = row.get(0)?;
            Ok(status == "cancelled")
        },
    ).unwrap_or(false);

    Ok(Json(serde_json::json!({"cancelled": cancelled})))
}

/// Agent sends execution result. Server relays to waiting CLI via channel.
pub(crate) async fn agent_result(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize_and_audit(&user, Action::AgentSubmitResult, Resource::Global, &state).await?;

    let success = body["success"].as_bool().unwrap_or(false);
    let result = body["result"].clone();
    let error_msg = body["error"].as_str().map(|s| s.to_string());

    let (request_id, req_status, wh_operation, wh_environment, wh_database, wh_detail, wh_requester, wh_agent_id, webhook_ctx) = {
        let mut conn = state.db().await;

        let exec_ctx = crate::db::agent_repo::get_execution_context(&conn, &id)
            .map_err(|_| crate::api_error::ApiError::not_found("execution not found"))?;

        if exec_ctx.status != "claimed" {
            return Err(crate::api_error::ApiError::conflict(format!(
                "execution status is {}",
                exec_ctx.status
            )));
        }

        authz::authorize_with_audit(
            &user,
            Action::AgentSubmitResult,
            Resource::AgentExecution {
                agent_id: exec_ctx.agent_id.clone(),
            },
            &mut conn,
        )?;

        let req_ctx = crate::db::request_repo::get_request_context(&conn, &exec_ctx.request_id)
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

        let req_status = crate::db::agent_repo::finish_execution(
            &mut conn,
            &id,
            &exec_ctx.request_id,
            success,
            error_msg.as_deref(),
            &req_ctx.operation,
            &req_ctx.environment,
            &req_ctx.database_name,
            &req_ctx.detail,
            &req_ctx.created_by,
        )
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        state
            .metrics
            .record_agent_execution(if success { "succeeded" } else { "failed" });

        // Audit: execution_completed or execution_failed
        if let Err(e) = crate::db::audit_event_repo::record_audit_event(&mut conn,
        crate::db::audit_event_repo::AuditEvent {
            event_type: if success {
                "execution_completed"
            } else {
                "execution_failed"
            },
            event_category: "execution",
            outcome: if success { "success" } else { "failure" },
            actor_id: &exec_ctx.agent_id,
            actor_type: "agent",
            resource_type: Some("request"),
            resource_id: Some(&exec_ctx.request_id),
            peer_ip: None,
            client_ip: None,
            client_ip_source: None,
            request_id: Some(&exec_ctx.request_id),
            operation: Some(&req_ctx.operation),
            environment: Some(&req_ctx.environment),
            database_name: Some(&req_ctx.database_name),
            detail_fingerprint: None,
            detail_raw: Some(&req_ctx.detail),
            reason: None,
            metadata_json: &serde_json::json!({
                "execution_id": id,
                "error": error_msg,
            })
            .to_string(),
        }, &headers, &state.audit_config, &state.trusted_proxies) {
                    error!(error = %e, "audit write failed");
                }

        let notif_hooks = crate::db::policy_repo::get_notification_webhooks(
            &conn,
            &req_ctx.database_name,
            &req_ctx.environment,
        );

        (
            exec_ctx.request_id,
            req_status,
            req_ctx.operation,
            req_ctx.environment,
            req_ctx.database_name,
            req_ctx.detail,
            req_ctx.created_by,
            exec_ctx.agent_id,
            notif_hooks,
        )
    };

    // Save to result storage (skip if no_store flag is set)
    if success {
        let no_store: bool = {
            let conn = state.db().await;
            conn.query_row(
                "SELECT no_store FROM requests WHERE id = ?1",
                [&request_id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or(0)
                != 0
        };

        if !no_store {
            let share_with: Vec<String> = {
                let conn = state.db().await;
                conn.query_row(
                    "SELECT share_with_json FROM requests WHERE id = ?1",
                    [&request_id],
                    |row| row.get::<_, Option<String>>(0),
                )
                .ok()
                .flatten()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default()
            };

            let data = serde_json::to_vec(&result).unwrap_or_default();
            let content_length = data.len() as i64;
            let checksum = format!("{:x}", sha2::Sha256::digest(&data));
            let storage_key = state.result_store.storage_key(&request_id);
            let backend = state.result_store.backend();

            match state.result_store.put(&request_id, &data).await {
                Ok(()) => {
                    let now = chrono::Utc::now().to_rfc3339();
                    let retention_days = state.retention.result_ttl_days as i64;
                    let expires_at =
                        (chrono::Utc::now() + chrono::Duration::days(retention_days)).to_rfc3339();
                    let db_write_result = {
                        let mut conn = state.db().await;
                        let tx = conn.transaction();
                        tx.and_then(|tx| {
                                tx.execute(
                                    "INSERT OR REPLACE INTO request_results (request_id, storage_backend, storage_key, content_length, checksum_sha256, retention_days, status, stored_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'stored', ?7, ?8)",
                                    rusqlite::params![request_id, backend, storage_key, content_length, checksum, retention_days, now, expires_at],
                                )?;
                                tx.execute(
                                    "DELETE FROM result_access WHERE request_id = ?1",
                                    rusqlite::params![request_id],
                                )?;

                                // Default access: requester + admin. share_with adds extra.
                                let mut all_selectors =
                                    vec!["requester".to_string(), "role:admin".to_string()];
                                all_selectors.extend(share_with.iter().cloned());
                                for sel in &all_selectors {
                                    let (sel_type, sel_value) = if sel == "requester" {
                                        ("requester", "")
                                    } else if let Some(v) = sel.strip_prefix("role:") {
                                        ("role", v)
                                    } else if let Some(v) = sel.strip_prefix("group:") {
                                        ("group", v)
                                    } else if let Some(v) = sel.strip_prefix("user:") {
                                        ("user", v)
                                    } else {
                                        ("role", sel.as_str())
                                    };
                                    tx.execute(
                                        "INSERT INTO result_access (request_id, selector_type, selector_value) VALUES (?1, ?2, ?3)",
                                        rusqlite::params![request_id, sel_type, sel_value],
                                    )?;
                                }
                                tx.commit()
                            })
                    };

                    if db_write_result.is_err() {
                        if let Err(err) = state.result_store.delete(&request_id).await {
                            error!(
                                request_id = %request_id,
                                error = %err,
                                "failed to delete partially stored result"
                            );
                        }
                        let conn = state.db().await;
                        if let Err(err) = conn.execute(
                            "INSERT OR REPLACE INTO request_results (request_id, storage_backend, storage_key, content_length, checksum_sha256, retention_days, status, stored_at, expires_at) VALUES (?1, ?2, ?3, 0, '', ?4, 'storage_failed', ?5, ?5)",
                            rusqlite::params![request_id, backend, storage_key, retention_days, now],
                        ) {
                            error!(
                                request_id = %request_id,
                                error = %err,
                                "failed to mark result storage failure"
                            );
                        }
                    }
                }
                Err(_) => {
                    let conn = state.db().await;
                    let now = chrono::Utc::now().to_rfc3339();
                    if let Err(err) = conn.execute(
                        "INSERT OR REPLACE INTO request_results (request_id, storage_backend, storage_key, content_length, checksum_sha256, retention_days, status, stored_at, expires_at) VALUES (?1, 'unknown', '', 0, '', ?3, 'storage_failed', ?2, ?2)",
                        rusqlite::params![
                            request_id,
                            now,
                            crate::constants::RESULT_STORAGE_FAILURE_RETENTION_DAYS,
                        ],
                    ) {
                        error!(request_id = %request_id, error = %err, "failed to persist storage failure");
                    }
                }
            }
        }
    }

    // Relay result to waiting CLI
    let payload = json!({
        "success": success,
        "result": result,
        "error": error_msg,
        "request_id": request_id,
    });

    let slot = match state.result_channels.get(&request_id).await {
        Some(slot) => slot,
        None => {
            crate::routes::requests::ensure_result_slot(&state, &request_id).await;
            state
                .result_channels
                .get(&request_id)
                .await
                .ok_or_else(|| {
                    crate::api_error::ApiError::internal("failed to create result relay slot")
                })?
        }
    };
    let mut r = slot.result.lock().await;
    *r = Some(payload);
    slot.notify.notify_waiters();

    state.request_notifier.notify(&request_id).await;

    // B17: Fire webhook on completion/failure (skip if request was already cancelled)
    if req_status != "cancelled" {
        let event_name = if success {
            "request_completed"
        } else {
            "request_failed"
        };
        state.webhooks.read().unwrap().dispatch_with_policy(
            webhook_ctx,
            crate::webhook::WebhookEvent {
                event: event_name.into(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                request_id: request_id.clone(),
                status: req_status.clone(),
                requester: wh_requester,
                actor: wh_agent_id,
                actor_role: Some("agent".into()),
                operation: wh_operation,
                environment: wh_environment,
                detail: wh_detail,
                database: wh_database,
                reason: error_msg.clone(),
                next_step: None,
                cli_command: None,
            },
            state.metrics.clone(),
        );
    }

    Ok(Json(
        json!({"status": req_status, "request_id": request_id}),
    ))
}
