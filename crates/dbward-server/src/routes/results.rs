use crate::auth::authenticate;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde_json::json;

use crate::api_error::ApiError;
use crate::state::AppState;

/// GET /api/requests/{id}/result/content — retrieve stored result (access controlled)
pub async fn get_result_content(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let user = authenticate(&headers, &state).await?;
    let conn = state.sqlite.lock().await;

    let request_id = super::requests::resolve_id(&conn, &id)?;

    // Get request info for authz
    let created_by: String = conn
        .query_row(
            "SELECT created_by FROM requests WHERE id = ?1",
            [&request_id],
            |row| row.get(0),
        )
        .map_err(|_| ApiError::not_found("request not found"))?;

    // Check request_results exists
    let status: String = conn
        .query_row(
            "SELECT status FROM request_results WHERE request_id = ?1",
            [&request_id],
            |row| row.get(0),
        )
        .map_err(|_| {
            // Check if this was a --no-store request
            let is_no_store: bool = conn
                .query_row(
                    "SELECT no_store FROM requests WHERE id = ?1",
                    [&request_id],
                    |row| row.get::<_, i64>(0).map(|v| v != 0),
                )
                .unwrap_or(false);
            if is_no_store {
                ApiError::new(StatusCode::GONE, "this request was created with --no-store; result was not persisted")
                    .with_code("result_not_stored")
            } else {
                ApiError::not_found("result not stored for this request")
            }
        })?;

    if status == "storage_failed" {
        return Err(
            ApiError::conflict("result storage failed; not available for sharing")
                .with_code("result_storage_failed"),
        );
    }

    // Check expires_at
    let expires_at: String = conn
        .query_row(
            "SELECT expires_at FROM request_results WHERE request_id = ?1",
            [&request_id],
            |row| row.get(0),
        )
        .unwrap_or_default();
    if !expires_at.is_empty() && expires_at < chrono::Utc::now().to_rfc3339() {
        return Err(
            ApiError::new(StatusCode::GONE, "result has expired").with_code("result_expired")
        );
    }

    // Access control via result_access table
    let selectors: Vec<(String, String)> = {
        let mut stmt = conn
            .prepare(
                "SELECT selector_type, selector_value FROM result_access WHERE request_id = ?1",
            )
            .map_err(|e| ApiError::internal(e.to_string()))?;
        stmt.query_map([&request_id], |row| Ok((row.get(0)?, row.get(1)?)))
            .map_err(|e| ApiError::internal(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| ApiError::internal(e.to_string()))?
    };

    let allowed = selectors
        .iter()
        .any(|(sel_type, sel_value)| match sel_type.as_str() {
            "requester" => user.user == created_by,
            "role" => {
                user.roles.iter().any(|r| r == sel_value)
                    || user.effective_permission() == sel_value
            }
            "group" => user.groups.iter().any(|g| g == sel_value),
            "user" => user.user == *sel_value,
            _ => false,
        });

    if !allowed {
        return Err(ApiError::forbidden("you do not have access to this result")
            .with_code("result_access_denied"));
    }

    drop(conn);

    // Read from storage
    let data = state.result_store.get(&request_id).await.map_err(|e| {
        ApiError::new(StatusCode::GONE, "result data is no longer available (storage lost)")
            .with_code("result_data_lost")
            .with_hint(format!("storage error: {e}"))
    })?;

    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        data,
    ))
}

/// GET /api/results — list results accessible to current user
pub async fn list_results(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = authenticate(&headers, &state).await?;
    let conn = state.sqlite.lock().await;

    // Build WHERE clause for result_access
    let mut conditions = vec![];
    let mut params: Vec<String> = vec![];

    // requester match
    conditions.push(format!(
        "(ra.selector_type = 'requester' AND r.created_by = ?{})",
        params.len() + 1
    ));
    params.push(user.user.clone());

    // user match
    conditions.push(format!(
        "(ra.selector_type = 'user' AND ra.selector_value = ?{})",
        params.len() + 1
    ));
    params.push(user.user.clone());

    // role matches
    for role in &user.roles {
        conditions.push(format!(
            "(ra.selector_type = 'role' AND ra.selector_value = ?{})",
            params.len() + 1
        ));
        params.push(role.clone());
    }
    // effective permission as role
    let perm = user.effective_permission().to_string();
    if !user.roles.iter().any(|r| r == &perm) {
        conditions.push(format!(
            "(ra.selector_type = 'role' AND ra.selector_value = ?{})",
            params.len() + 1
        ));
        params.push(perm);
    }

    // group matches
    for group in &user.groups {
        conditions.push(format!(
            "(ra.selector_type = 'group' AND ra.selector_value = ?{})",
            params.len() + 1
        ));
        params.push(group.clone());
    }

    let where_clause = conditions.join(" OR ");
    let sql = format!(
        "SELECT DISTINCT r.id, r.created_by, r.operation, r.database_name, r.environment, r.detail, rr.content_length, rr.stored_at, rr.expires_at \
         FROM result_access ra \
         JOIN requests r ON r.id = ra.request_id \
         JOIN request_results rr ON rr.request_id = ra.request_id \
         WHERE rr.status = 'stored' AND rr.expires_at > ?{} AND ({}) \
         ORDER BY rr.stored_at DESC LIMIT 100",
        params.len() + 1,
        where_clause
    );
    params.push(chrono::Utc::now().to_rfc3339());

    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let param_refs: Vec<&dyn rusqlite::types::ToSql> = params
        .iter()
        .map(|p| p as &dyn rusqlite::types::ToSql)
        .collect();

    let results: Vec<serde_json::Value> = stmt
        .query_map(param_refs.as_slice(), |row| {
            Ok(json!({
                "request_id": row.get::<_, String>(0)?,
                "created_by": row.get::<_, String>(1)?,
                "operation": row.get::<_, String>(2)?,
                "database": row.get::<_, String>(3)?,
                "environment": row.get::<_, String>(4)?,
                "detail": row.get::<_, String>(5)?,
                "content_length": row.get::<_, i64>(6)?,
                "stored_at": row.get::<_, String>(7)?,
                "expires_at": row.get::<_, String>(8)?,
            }))
        })
        .map_err(|e| ApiError::internal(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ApiError::internal(e.to_string()))?;

    Ok(Json(json!({ "results": results })))
}

/// GET /api/storage-config — get current result storage configuration (admin only)
pub async fn get_storage_config(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = authenticate(&headers, &state).await?;
    if user.effective_permission() != "admin" {
        return Err(ApiError::forbidden("admin only").with_code("admin_required"));
    }
    let config = json!({"configured": true, "backend": state.result_store.backend()});
    Ok(Json(config))
}
