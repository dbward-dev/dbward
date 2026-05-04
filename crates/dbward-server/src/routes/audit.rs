use axum::Json;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use serde_json::json;
use std::collections::HashMap;

use super::requests::parse_pagination;
use crate::auth;
use crate::authz::{self, Action, Resource};
use crate::state::AppState;

pub(crate) async fn list_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(
        &user,
        Action::ListAudit,
        Resource::AuditQuery {
            requested_user: params.get("user").filter(|s| !s.is_empty()).cloned(),
        },
    )
    .await?;

    let (limit, offset) = parse_pagination(&params);
    // Developer: force filter to own user
    let user_filter = match user.effective_permission() {
        "admin" => params.get("user").filter(|s| !s.is_empty()).cloned(),
        _ => Some(user.user.clone()),
    };
    let user_filter = user_filter.as_deref();
    let operation_filter = params.get("operation").filter(|s| !s.is_empty());
    let status_filter = params.get("status").filter(|s| !s.is_empty());
    let database_filter = params.get("database").filter(|s| !s.is_empty());

    let conn = state.sqlite.lock().await;

    let mut where_clauses: Vec<String> = Vec::new();
    let mut bind_values: Vec<String> = Vec::new();

    if let Some(u) = user_filter {
        bind_values.push(u.to_string());
        where_clauses.push(format!("actor_id = ?{}", bind_values.len()));
    }
    if let Some(o) = operation_filter {
        bind_values.push(o.to_string());
        where_clauses.push(format!("operation = ?{}", bind_values.len()));
    }
    if let Some(s) = status_filter {
        bind_values.push(s.to_string());
        where_clauses.push(format!("status = ?{}", bind_values.len()));
    }
    if let Some(d) = database_filter {
        bind_values.push(d.to_string());
        where_clauses.push(format!("database_name = ?{}", bind_values.len()));
    }

    let where_sql = if where_clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", where_clauses.join(" AND "))
    };

    let count_sql = format!("SELECT COUNT(*) FROM audit_log {where_sql}");
    let mut count_stmt = conn
        .prepare(&count_sql)
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
    let total: i64 = count_stmt
        .query_row(rusqlite::params_from_iter(&bind_values), |row| row.get(0))
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

    let query_sql = format!(
        "SELECT id, request_id, execution_id, actor_id, operation, environment, database_name, detail, status, result_summary, error_message, created_at FROM audit_log {where_sql} ORDER BY created_at DESC LIMIT ?{} OFFSET ?{}",
        bind_values.len() + 1,
        bind_values.len() + 2,
    );
    let mut stmt = conn
        .prepare(&query_sql)
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

    let mut all_params: Vec<Box<dyn rusqlite::types::ToSql>> = bind_values
        .iter()
        .map(|v| Box::new(v.clone()) as Box<dyn rusqlite::types::ToSql>)
        .collect();
    all_params.push(Box::new(limit));
    all_params.push(Box::new(offset));
    let param_refs: Vec<&dyn rusqlite::types::ToSql> =
        all_params.iter().map(|p| p.as_ref()).collect();

    let rows: Vec<serde_json::Value> = stmt
        .query_map(param_refs.as_slice(), |row| {
            Ok(json!({
                "id": row.get::<_, String>(0)?,
                "request_id": row.get::<_, Option<String>>(1)?,
                "execution_id": row.get::<_, Option<String>>(2)?,
                "actor_id": row.get::<_, String>(3)?,
                "operation": row.get::<_, String>(4)?,
                "environment": row.get::<_, String>(5)?,
                "database_name": row.get::<_, String>(6)?,
                "detail": row.get::<_, String>(7)?,
                "status": row.get::<_, String>(8)?,
                "result_summary": row.get::<_, Option<String>>(9)?,
                "error_message": row.get::<_, Option<String>>(10)?,
                "created_at": row.get::<_, String>(11)?,
            }))
        })
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

    Ok(Json(
        json!({"audit_log": rows, "total": total, "limit": limit, "offset": offset}),
    ))
}
