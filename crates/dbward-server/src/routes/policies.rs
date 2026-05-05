use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use serde_json::json;

use crate::auth;
use crate::authz::{self, Action, Resource};
use crate::state::AppState;

pub(crate) async fn list_workflows(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::ListPolicy, Resource::PolicyObject).await?;

    let conn = state.sqlite.lock().await;
    let mut stmt = conn
        .prepare("SELECT id, database_name, environment, operations_json, steps_json, require_reason, allow_same_approver_across_steps, source, created_at, updated_at FROM workflows ORDER BY database_name, environment")
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

    let rows: Vec<serde_json::Value> = stmt
        .query_map([], |row| {
            let ops: serde_json::Value =
                serde_json::from_str(row.get::<_, String>(3)?.as_str()).unwrap_or_default();
            let steps: serde_json::Value =
                serde_json::from_str(row.get::<_, String>(4)?.as_str()).unwrap_or_default();
            Ok(json!({
                "id": row.get::<_, String>(0)?,
                "database": row.get::<_, String>(1)?,
                "environment": row.get::<_, String>(2)?,
                "operations": ops,
                "steps": steps,
                "require_reason": row.get::<_, bool>(5)?,
                "allow_same_approver_across_steps": row.get::<_, bool>(6)?,
                "source": row.get::<_, String>(7)?,
                "created_at": row.get::<_, String>(8)?,
                "updated_at": row.get::<_, String>(9)?,
            }))
        })
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

    Ok(Json(json!({"workflows": rows})))
}

pub(crate) async fn get_workflow(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::GetPolicy, Resource::PolicyObject).await?;

    let conn = state.sqlite.lock().await;
    let row = conn
        .query_row(
            "SELECT id, database_name, environment, operations_json, steps_json, require_reason, allow_same_approver_across_steps, source, created_at, updated_at FROM workflows WHERE id = ?1",
            rusqlite::params![id],
            |row| {
                let ops: serde_json::Value = serde_json::from_str(row.get::<_, String>(3)?.as_str()).unwrap_or_default();
                let steps: serde_json::Value = serde_json::from_str(row.get::<_, String>(4)?.as_str()).unwrap_or_default();
                Ok(json!({
                    "id": row.get::<_, String>(0)?,
                    "database": row.get::<_, String>(1)?,
                    "environment": row.get::<_, String>(2)?,
                    "operations": ops,
                    "steps": steps,
                    "require_reason": row.get::<_, bool>(5)?,
                    "allow_same_approver_across_steps": row.get::<_, bool>(6)?,
                    "source": row.get::<_, String>(7)?,
                    "created_at": row.get::<_, String>(8)?,
                    "updated_at": row.get::<_, String>(9)?,
                }))
            },
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "workflow not found".into()))?;

    Ok(Json(row))
}

pub(crate) async fn create_workflow(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::CreatePolicy, Resource::PolicyObject).await?;

    let database = body["database"]
        .as_str()
        .ok_or((StatusCode::BAD_REQUEST, "database required".into()))?;
    let environment = body["environment"]
        .as_str()
        .ok_or((StatusCode::BAD_REQUEST, "environment required".into()))?;
    let operations = body.get("operations").cloned().unwrap_or(json!([]));
    let steps = body.get("steps").cloned().unwrap_or(json!([]));
    let require_reason = body["require_reason"].as_bool().unwrap_or(false);
    let allow_same_approver_across_steps = body["allow_same_approver_across_steps"]
        .as_bool()
        .unwrap_or(false);

    let id = format!("{database}:{environment}");
    let ops_json = operations.to_string();
    let steps_json = steps.to_string();
    let now = chrono::Utc::now().to_rfc3339();

    let mut conn = state.sqlite.lock().await;
    {
        let tx = conn
            .transaction()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.execute(
            "INSERT INTO workflows (id, database_name, environment, operations_json, steps_json, require_reason, allow_same_approver_across_steps, source, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'api', ?8, ?8)",
            rusqlite::params![
                id,
                database,
                environment,
                ops_json,
                steps_json,
                require_reason,
                allow_same_approver_across_steps,
                now
            ],
        )
        .map_err(|e| {
            if e.to_string().contains("UNIQUE") {
                (StatusCode::CONFLICT, format!("workflow for {database}:{environment} already exists"))
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            }
        })?;

        crate::db::audit_repo::insert_policy_change(
            &tx,
            &user.user,
            "policy_create",
            "workflow",
            &id,
        )
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.commit()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
    }

    Ok((
        StatusCode::CREATED,
        Json(json!({"id": id, "database": database, "environment": environment})),
    ))
}

pub(crate) async fn update_workflow(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::UpdatePolicy, Resource::PolicyObject).await?;

    let mut conn = state.sqlite.lock().await;
    let now = chrono::Utc::now().to_rfc3339();

    // Check exists
    conn.query_row(
        "SELECT id FROM workflows WHERE id = ?1",
        rusqlite::params![id],
        |_| Ok(()),
    )
    .map_err(|_| (StatusCode::NOT_FOUND, "workflow not found".into()))?;

    // Block changes if pending requests reference this workflow
    let pending_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM requests WHERE workflow_id = ?1 AND status = 'pending'",
            rusqlite::params![id],
            |row| row.get(0),
        )
        .unwrap_or(0);
    if pending_count > 0 {
        return Err(crate::api_error::ApiError::conflict(format!(
            "{pending_count} pending request(s) reference this workflow"
        )));
    }

    {
        let tx = conn
            .transaction()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        if let Some(steps) = body.get("steps") {
            tx.execute(
                "UPDATE workflows SET steps_json = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
                rusqlite::params![steps.to_string(), now, id],
            )
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        }
        if let Some(ops) = body.get("operations") {
            tx.execute(
                "UPDATE workflows SET operations_json = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
                rusqlite::params![ops.to_string(), now, id],
            )
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        }
        if let Some(v) = body.get("require_reason").and_then(|v| v.as_bool()) {
            tx.execute(
                "UPDATE workflows SET require_reason = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
                rusqlite::params![v, now, id],
            )
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        }
        if let Some(v) = body
            .get("allow_same_approver_across_steps")
            .and_then(|v| v.as_bool())
        {
            tx.execute(
                "UPDATE workflows SET allow_same_approver_across_steps = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
                rusqlite::params![v, now, id],
            )
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        }

        crate::db::audit_repo::insert_policy_change(
            &tx,
            &user.user,
            "policy_update",
            "workflow",
            &id,
        )
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.commit()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
    }

    Ok(Json(json!({"id": id, "updated": true})))
}

pub(crate) async fn delete_workflow(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::DeletePolicy, Resource::PolicyObject).await?;

    let mut conn = state.sqlite.lock().await;

    // Block deletion if pending requests reference this workflow
    let pending_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM requests WHERE workflow_id = ?1 AND status = 'pending'",
            rusqlite::params![id],
            |row| row.get(0),
        )
        .unwrap_or(0);
    if pending_count > 0 {
        return Err(crate::api_error::ApiError::conflict(format!(
            "{pending_count} pending request(s) reference this workflow"
        )));
    }

    {
        let tx = conn
            .transaction()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        let changes = tx
            .execute("DELETE FROM workflows WHERE id = ?1", rusqlite::params![id])
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

        if changes == 0 {
            return Err(crate::api_error::ApiError::not_found("workflow not found"));
        }

        crate::db::audit_repo::insert_policy_change(
            &tx,
            &user.user,
            "policy_delete",
            "workflow",
            &id,
        )
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.commit()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
    }

    Ok(Json(json!({"id": id, "deleted": true})))
}

// ---------------------------------------------------------------------------
// Execution Policy CRUD (admin only for mutations)
// ---------------------------------------------------------------------------

pub(crate) async fn list_execution_policies(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::ListPolicy, Resource::PolicyObject).await?;

    let conn = state.sqlite.lock().await;
    let mut stmt = conn
        .prepare("SELECT id, database_name, environment, max_executions, execution_window_secs, retry_on_failure, source, created_at, updated_at FROM execution_policies ORDER BY database_name, environment")
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

    let rows: Vec<serde_json::Value> = stmt
        .query_map([], |row| {
            Ok(json!({
                "id": row.get::<_, String>(0)?,
                "database": row.get::<_, String>(1)?,
                "environment": row.get::<_, String>(2)?,
                "max_executions": row.get::<_, i64>(3)?,
                "execution_window_secs": row.get::<_, i64>(4)?,
                "retry_on_failure": row.get::<_, bool>(5)?,
                "source": row.get::<_, String>(6)?,
                "created_at": row.get::<_, String>(7)?,
                "updated_at": row.get::<_, String>(8)?,
            }))
        })
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

    Ok(Json(json!({"execution_policies": rows})))
}

pub(crate) async fn get_execution_policy_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::GetPolicy, Resource::PolicyObject).await?;

    let conn = state.sqlite.lock().await;
    let row = conn
        .query_row(
            "SELECT id, database_name, environment, max_executions, execution_window_secs, retry_on_failure, source, created_at, updated_at FROM execution_policies WHERE id = ?1",
            rusqlite::params![id],
            |row| {
                Ok(json!({
                    "id": row.get::<_, String>(0)?,
                    "database": row.get::<_, String>(1)?,
                    "environment": row.get::<_, String>(2)?,
                    "max_executions": row.get::<_, i64>(3)?,
                    "execution_window_secs": row.get::<_, i64>(4)?,
                    "retry_on_failure": row.get::<_, bool>(5)?,
                    "source": row.get::<_, String>(6)?,
                    "created_at": row.get::<_, String>(7)?,
                    "updated_at": row.get::<_, String>(8)?,
                }))
            },
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "execution policy not found".into()))?;

    Ok(Json(row))
}

pub(crate) async fn create_execution_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::CreatePolicy, Resource::PolicyObject).await?;

    let database = body["database"]
        .as_str()
        .ok_or((StatusCode::BAD_REQUEST, "database required".into()))?;
    let environment = body["environment"]
        .as_str()
        .ok_or((StatusCode::BAD_REQUEST, "environment required".into()))?;
    let max_executions = body["max_executions"].as_i64().unwrap_or(1);
    let execution_window_secs = body["execution_window_secs"].as_i64().unwrap_or(3600);
    let retry_on_failure = body["retry_on_failure"].as_bool().unwrap_or(false);

    let id = format!("{database}:{environment}");
    let now = chrono::Utc::now().to_rfc3339();

    let mut conn = state.sqlite.lock().await;
    {
        let tx = conn
            .transaction()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.execute(
            "INSERT INTO execution_policies (id, database_name, environment, max_executions, execution_window_secs, retry_on_failure, source, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'api', ?7, ?7)",
            rusqlite::params![id, database, environment, max_executions, execution_window_secs, retry_on_failure, now],
        )
        .map_err(|e| {
            if e.to_string().contains("UNIQUE") {
                (StatusCode::CONFLICT, format!("execution policy for {database}:{environment} already exists"))
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            }
        })?;

        crate::db::audit_repo::insert_policy_change(
            &tx,
            &user.user,
            "policy_create",
            "execution_policy",
            &id,
        )
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.commit()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
    }

    Ok((
        StatusCode::CREATED,
        Json(json!({"id": id, "database": database, "environment": environment})),
    ))
}

pub(crate) async fn update_execution_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::UpdatePolicy, Resource::PolicyObject).await?;

    let mut conn = state.sqlite.lock().await;
    let now = chrono::Utc::now().to_rfc3339();

    conn.query_row(
        "SELECT id FROM execution_policies WHERE id = ?1",
        rusqlite::params![id],
        |_| Ok(()),
    )
    .map_err(|_| (StatusCode::NOT_FOUND, "execution policy not found".into()))?;

    {
        let tx = conn
            .transaction()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        if let Some(v) = body.get("max_executions").and_then(|v| v.as_i64()) {
            tx.execute(
                "UPDATE execution_policies SET max_executions = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
                rusqlite::params![v, now, id],
            ).map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        }
        if let Some(v) = body.get("execution_window_secs").and_then(|v| v.as_i64()) {
            tx.execute(
                "UPDATE execution_policies SET execution_window_secs = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
                rusqlite::params![v, now, id],
            ).map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        }
        if let Some(v) = body.get("retry_on_failure").and_then(|v| v.as_bool()) {
            tx.execute(
                "UPDATE execution_policies SET retry_on_failure = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
                rusqlite::params![v, now, id],
            ).map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        }

        crate::db::audit_repo::insert_policy_change(
            &tx,
            &user.user,
            "policy_update",
            "execution_policy",
            &id,
        )
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.commit()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
    }

    Ok(Json(json!({"id": id, "updated": true})))
}

pub(crate) async fn delete_execution_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::DeletePolicy, Resource::PolicyObject).await?;

    let mut conn = state.sqlite.lock().await;
    {
        let tx = conn
            .transaction()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        let changes = tx
            .execute(
                "DELETE FROM execution_policies WHERE id = ?1",
                rusqlite::params![id],
            )
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

        if changes == 0 {
            return Err(crate::api_error::ApiError::not_found(
                "execution policy not found",
            ));
        }

        crate::db::audit_repo::insert_policy_change(
            &tx,
            &user.user,
            "policy_delete",
            "execution_policy",
            &id,
        )
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.commit()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
    }

    Ok(Json(json!({"id": id, "deleted": true})))
}

// ---------------------------------------------------------------------------
// Result Policy CRUD (admin only for mutations)
// ---------------------------------------------------------------------------

pub(crate) async fn list_result_policies(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::ListPolicy, Resource::PolicyObject).await?;

    let conn = state.sqlite.lock().await;
    let mut stmt = conn
        .prepare("SELECT id, database_name, environment, delivery_mode, storage_config_json, access_json, source, created_at, updated_at FROM result_policies ORDER BY database_name, environment")
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

    let rows: Vec<serde_json::Value> = stmt
        .query_map([], |row| {
            let storage: serde_json::Value =
                serde_json::from_str(row.get::<_, String>(4)?.as_str()).unwrap_or_default();
            let access: serde_json::Value =
                serde_json::from_str(row.get::<_, String>(5)?.as_str()).unwrap_or_default();
            Ok(json!({
                "id": row.get::<_, String>(0)?,
                "database": row.get::<_, String>(1)?,
                "environment": row.get::<_, String>(2)?,
                "delivery_mode": row.get::<_, String>(3)?,
                "storage_config": storage,
                "access": access,
                "source": row.get::<_, String>(6)?,
                "created_at": row.get::<_, String>(7)?,
                "updated_at": row.get::<_, String>(8)?,
            }))
        })
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

    Ok(Json(json!({"result_policies": rows})))
}

pub(crate) async fn get_result_policy_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::GetPolicy, Resource::PolicyObject).await?;

    let conn = state.sqlite.lock().await;
    let row = conn
        .query_row(
            "SELECT id, database_name, environment, delivery_mode, storage_config_json, access_json, source, created_at, updated_at FROM result_policies WHERE id = ?1",
            rusqlite::params![id],
            |row| {
                let storage: serde_json::Value = serde_json::from_str(row.get::<_, String>(4)?.as_str()).unwrap_or_default();
                let access: serde_json::Value = serde_json::from_str(row.get::<_, String>(5)?.as_str()).unwrap_or_default();
                Ok(json!({
                    "id": row.get::<_, String>(0)?,
                    "database": row.get::<_, String>(1)?,
                    "environment": row.get::<_, String>(2)?,
                    "delivery_mode": row.get::<_, String>(3)?,
                    "storage_config": storage,
                    "access": access,
                    "source": row.get::<_, String>(6)?,
                    "created_at": row.get::<_, String>(7)?,
                    "updated_at": row.get::<_, String>(8)?,
                }))
            },
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "result policy not found".into()))?;

    Ok(Json(row))
}

pub(crate) async fn create_result_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::CreatePolicy, Resource::PolicyObject).await?;

    let database = body["database"]
        .as_str()
        .ok_or((StatusCode::BAD_REQUEST, "database required".into()))?;
    let environment = body["environment"]
        .as_str()
        .ok_or((StatusCode::BAD_REQUEST, "environment required".into()))?;
    let delivery_mode = body["delivery_mode"].as_str().unwrap_or("stream");
    let storage_config = body.get("storage_config").cloned().unwrap_or(json!({}));
    let access = body.get("access").cloned().unwrap_or(json!({}));

    let id = format!("{database}:{environment}");
    let storage_json = storage_config.to_string();
    let access_json = access.to_string();
    let now = chrono::Utc::now().to_rfc3339();

    let mut conn = state.sqlite.lock().await;
    {
        let tx = conn
            .transaction()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.execute(
            "INSERT INTO result_policies (id, database_name, environment, delivery_mode, storage_config_json, access_json, source, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'api', ?7, ?7)",
            rusqlite::params![id, database, environment, delivery_mode, storage_json, access_json, now],
        )
        .map_err(|e| {
            if e.to_string().contains("UNIQUE") {
                (StatusCode::CONFLICT, format!("result policy for {database}:{environment} already exists"))
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            }
        })?;

        crate::db::audit_repo::insert_policy_change(
            &tx,
            &user.user,
            "policy_create",
            "result_policy",
            &id,
        )
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.commit()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
    }

    Ok((
        StatusCode::CREATED,
        Json(json!({"id": id, "database": database, "environment": environment})),
    ))
}

pub(crate) async fn update_result_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::UpdatePolicy, Resource::PolicyObject).await?;

    let mut conn = state.sqlite.lock().await;
    let now = chrono::Utc::now().to_rfc3339();

    conn.query_row(
        "SELECT id FROM result_policies WHERE id = ?1",
        rusqlite::params![id],
        |_| Ok(()),
    )
    .map_err(|_| (StatusCode::NOT_FOUND, "result policy not found".into()))?;

    {
        let tx = conn
            .transaction()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        if let Some(v) = body.get("delivery_mode").and_then(|v| v.as_str()) {
            tx.execute(
                "UPDATE result_policies SET delivery_mode = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
                rusqlite::params![v, now, id],
            ).map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        }
        if let Some(v) = body.get("storage_config") {
            tx.execute(
                "UPDATE result_policies SET storage_config_json = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
                rusqlite::params![v.to_string(), now, id],
            ).map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        }
        if let Some(v) = body.get("access") {
            tx.execute(
                "UPDATE result_policies SET access_json = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
                rusqlite::params![v.to_string(), now, id],
            ).map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        }

        crate::db::audit_repo::insert_policy_change(
            &tx,
            &user.user,
            "policy_update",
            "result_policy",
            &id,
        )
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.commit()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
    }

    Ok(Json(json!({"id": id, "updated": true})))
}

pub(crate) async fn delete_result_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::DeletePolicy, Resource::PolicyObject).await?;

    let mut conn = state.sqlite.lock().await;
    {
        let tx = conn
            .transaction()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        let changes = tx
            .execute(
                "DELETE FROM result_policies WHERE id = ?1",
                rusqlite::params![id],
            )
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

        if changes == 0 {
            return Err(crate::api_error::ApiError::not_found(
                "result policy not found",
            ));
        }

        crate::db::audit_repo::insert_policy_change(
            &tx,
            &user.user,
            "policy_delete",
            "result_policy",
            &id,
        )
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.commit()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
    }

    Ok(Json(json!({"id": id, "deleted": true})))
}

// ---------------------------------------------------------------------------
// Notification Policy CRUD (admin only for mutations)
// ---------------------------------------------------------------------------

pub(crate) async fn list_notification_policies(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::ListPolicy, Resource::PolicyObject).await?;

    let conn = state.sqlite.lock().await;
    let mut stmt = conn
        .prepare("SELECT id, database_name, environment, webhooks_json, source, created_at, updated_at FROM notification_policies ORDER BY database_name, environment")
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

    let rows: Vec<serde_json::Value> = stmt
        .query_map([], |row| {
            let webhooks: serde_json::Value =
                serde_json::from_str(row.get::<_, String>(3)?.as_str()).unwrap_or_default();
            Ok(json!({
                "id": row.get::<_, String>(0)?,
                "database": row.get::<_, String>(1)?,
                "environment": row.get::<_, String>(2)?,
                "webhooks": webhooks,
                "source": row.get::<_, String>(4)?,
                "created_at": row.get::<_, String>(5)?,
                "updated_at": row.get::<_, String>(6)?,
            }))
        })
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

    Ok(Json(json!({"notification_policies": rows})))
}

pub(crate) async fn get_notification_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::GetPolicy, Resource::PolicyObject).await?;

    let conn = state.sqlite.lock().await;
    let row = conn
        .query_row(
            "SELECT id, database_name, environment, webhooks_json, source, created_at, updated_at FROM notification_policies WHERE id = ?1",
            rusqlite::params![id],
            |row| {
                let webhooks: serde_json::Value = serde_json::from_str(row.get::<_, String>(3)?.as_str()).unwrap_or_default();
                Ok(json!({
                    "id": row.get::<_, String>(0)?,
                    "database": row.get::<_, String>(1)?,
                    "environment": row.get::<_, String>(2)?,
                    "webhooks": webhooks,
                    "source": row.get::<_, String>(4)?,
                    "created_at": row.get::<_, String>(5)?,
                    "updated_at": row.get::<_, String>(6)?,
                }))
            },
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "notification policy not found".into()))?;

    Ok(Json(row))
}

pub(crate) async fn create_notification_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::CreatePolicy, Resource::PolicyObject).await?;

    let database = body["database"]
        .as_str()
        .ok_or((StatusCode::BAD_REQUEST, "database required".into()))?;
    let environment = body["environment"]
        .as_str()
        .ok_or((StatusCode::BAD_REQUEST, "environment required".into()))?;
    let webhooks = body.get("webhooks").cloned().unwrap_or(json!([]));

    let id = format!("{database}:{environment}");
    let webhooks_json = webhooks.to_string();
    let now = chrono::Utc::now().to_rfc3339();

    let mut conn = state.sqlite.lock().await;
    {
        let tx = conn
            .transaction()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.execute(
            "INSERT INTO notification_policies (id, database_name, environment, webhooks_json, source, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, 'api', ?5, ?5)",
            rusqlite::params![id, database, environment, webhooks_json, now],
        )
        .map_err(|e| {
            if e.to_string().contains("UNIQUE") {
                (StatusCode::CONFLICT, format!("notification policy for {database}:{environment} already exists"))
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            }
        })?;

        crate::db::audit_repo::insert_policy_change(
            &tx,
            &user.user,
            "policy_create",
            "notification_policy",
            &id,
        )
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.commit()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
    }

    Ok((
        StatusCode::CREATED,
        Json(json!({"id": id, "database": database, "environment": environment})),
    ))
}

pub(crate) async fn update_notification_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::UpdatePolicy, Resource::PolicyObject).await?;

    let mut conn = state.sqlite.lock().await;
    let now = chrono::Utc::now().to_rfc3339();

    conn.query_row(
        "SELECT id FROM notification_policies WHERE id = ?1",
        rusqlite::params![id],
        |_| Ok(()),
    )
    .map_err(|_| {
        (
            StatusCode::NOT_FOUND,
            "notification policy not found".into(),
        )
    })?;

    {
        let tx = conn
            .transaction()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        if let Some(v) = body.get("webhooks") {
            tx.execute(
                "UPDATE notification_policies SET webhooks_json = ?1, source = 'api', updated_at = ?2 WHERE id = ?3",
                rusqlite::params![v.to_string(), now, id],
            ).map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        }

        crate::db::audit_repo::insert_policy_change(
            &tx,
            &user.user,
            "policy_update",
            "notification_policy",
            &id,
        )
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.commit()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
    }

    Ok(Json(json!({"id": id, "updated": true})))
}

pub(crate) async fn delete_notification_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::DeletePolicy, Resource::PolicyObject).await?;

    let mut conn = state.sqlite.lock().await;
    {
        let tx = conn
            .transaction()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        let changes = tx
            .execute(
                "DELETE FROM notification_policies WHERE id = ?1",
                rusqlite::params![id],
            )
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

        if changes == 0 {
            return Err(crate::api_error::ApiError::not_found(
                "notification policy not found",
            ));
        }

        crate::db::audit_repo::insert_policy_change(
            &tx,
            &user.user,
            "policy_delete",
            "notification_policy",
            &id,
        )
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.commit()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
    }

    Ok(Json(json!({"id": id, "deleted": true})))
}
