use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use serde_json::json;
use sha2::Digest;

use crate::auth;
use crate::authz::{self, Action, Resource};
use crate::state::AppState;

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
    authz::authorize(&user, Action::AgentPoll, Resource::Global).await?;

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

    let conn = state.sqlite.lock().await;

    // Record agent capabilities for claim-time verification
    let caps_json = serde_json::to_string(&json!({
        "databases": databases,
        "environments": environments,
        "operations": operations,
    }))
    .unwrap_or_else(|_| "{}".into());
    crate::db::agent_repo::upsert_agent(&conn, &user.user, &user.token_id, &caps_json).map_err(
        |e| crate::api_error::ApiError::internal(format!("agent registration failed: {e}")),
    )?;

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
    let query_sql = format!(
        "SELECT id, created_by, operation, environment, database_name, detail
         FROM requests WHERE {where_sql} ORDER BY created_at ASC LIMIT 10"
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
    authz::authorize(&user, Action::AgentClaim, Resource::Global).await?;
    let agent_id = user.user.clone();

    let mut conn = state.sqlite.lock().await;

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

    authz::authorize_sync(
        &user,
        Action::AgentClaim,
        Resource::AgentExecution {
            agent_id: agent_id.clone(),
        },
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
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::AgentPoll, Resource::Global).await?;

    let conn = state.sqlite.lock().await;
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
    Ok(StatusCode::OK)
}

/// Agent sends execution result. Server relays to waiting CLI via channel.
pub(crate) async fn agent_result(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::AgentSubmitResult, Resource::Global).await?;

    let success = body["success"].as_bool().unwrap_or(false);
    let result = body["result"].clone();
    let error_msg = body["error"].as_str().map(|s| s.to_string());

    let (request_id, req_status) = {
        let mut conn = state.sqlite.lock().await;

        let exec_ctx = crate::db::agent_repo::get_execution_context(&conn, &id)
            .map_err(|_| crate::api_error::ApiError::not_found("execution not found"))?;

        if exec_ctx.status != "claimed" {
            return Err(crate::api_error::ApiError::conflict(format!(
                "execution status is {}",
                exec_ctx.status
            )));
        }

        authz::authorize_sync(
            &user,
            Action::AgentSubmitResult,
            Resource::AgentExecution {
                agent_id: exec_ctx.agent_id.clone(),
            },
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

        (exec_ctx.request_id, req_status)
    };

    // Save to storage if share_with was specified
    if success {
        let share_with: Option<Vec<String>> = {
            let conn = state.sqlite.lock().await;
            conn.query_row(
                "SELECT share_with_json FROM requests WHERE id = ?1",
                [&request_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .ok()
            .flatten()
            .and_then(|s| serde_json::from_str(&s).ok())
        };

        if let Some(ref selectors) = share_with
            && let Some(ref store) = state.result_store
        {
            let data = serde_json::to_vec(&result).unwrap_or_default();
            let content_length = data.len() as i64;
            let checksum = format!("{:x}", sha2::Sha256::digest(&data));
            let storage_key = store.storage_key(&request_id);
            let backend = store.backend();

            match store.put(&request_id, &data).await {
                Ok(()) => {
                    let now = chrono::Utc::now().to_rfc3339();
                    let retention_days = 30i64; // TODO: from result_policy
                    let expires_at =
                        (chrono::Utc::now() + chrono::Duration::days(retention_days)).to_rfc3339();
                    let db_write_result = {
                        let mut conn = state.sqlite.lock().await;
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

                                // Expand selectors into result_access.
                                let mut all_selectors =
                                    vec!["requester".to_string(), "role:admin".to_string()];
                                all_selectors.extend(selectors.iter().cloned());
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
                        if let Err(err) = store.delete(&request_id).await {
                            eprintln!(
                                "failed to delete partially stored result {request_id}: {err}"
                            );
                        }
                        let conn = state.sqlite.lock().await;
                        if let Err(err) = conn.execute(
                            "INSERT OR REPLACE INTO request_results (request_id, storage_backend, storage_key, content_length, checksum_sha256, retention_days, status, stored_at, expires_at) VALUES (?1, ?2, ?3, 0, '', ?4, 'storage_failed', ?5, ?5)",
                            rusqlite::params![request_id, backend, storage_key, retention_days, now],
                        ) {
                            eprintln!(
                                "failed to mark result storage failure for {request_id}: {err}"
                            );
                        }
                    }
                }
                Err(_) => {
                    // Storage failed — record but don't fail the request
                    let conn = state.sqlite.lock().await;
                    let now = chrono::Utc::now().to_rfc3339();
                    if let Err(err) = conn.execute(
                        "INSERT OR REPLACE INTO request_results (request_id, storage_backend, storage_key, content_length, checksum_sha256, retention_days, status, stored_at, expires_at) VALUES (?1, 'unknown', '', 0, '', ?3, 'storage_failed', ?2, ?2)",
                        rusqlite::params![
                            request_id,
                            now,
                            crate::constants::RESULT_STORAGE_FAILURE_RETENTION_DAYS,
                        ],
                    ) {
                        eprintln!("failed to persist storage failure for {request_id}: {err}");
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

    if let Some(slot) = state.result_channels.get(&request_id).await {
        let mut r = slot.result.lock().await;
        *r = Some(payload);
        slot.notify.notify_waiters();
    }

    state.request_notifier.notify(&request_id).await;

    Ok(Json(
        json!({"status": req_status, "request_id": request_id}),
    ))
}
