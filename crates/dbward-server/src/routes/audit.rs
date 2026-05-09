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
    state: State<AppState>,
    headers: HeaderMap,
    query: Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    // Legacy endpoint — delegates to audit_events
    list_audit_events(state, headers, query).await
}

/// List audit events from the new audit_events table with extended filters.
pub(crate) async fn list_audit_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(
        &user,
        Action::ListAudit,
        Resource::AuditQuery {
            requested_user: params
                .get("actor_id")
                .or_else(|| params.get("user"))
                .filter(|s| !s.is_empty())
                .cloned(),
        },
    )
    .await?;

    let (limit, offset) = parse_pagination(&params);

    let conn = state.db().await;

    let mut where_clauses: Vec<String> = Vec::new();
    let mut bind_values: Vec<String> = Vec::new();

    // Developer: force filter to own user
    if user.effective_permission() != "admin" {
        bind_values.push(user.user.clone());
        where_clauses.push(format!("actor_id = ?{}", bind_values.len()));
    } else if let Some(u) = params.get("actor_id").filter(|s| !s.is_empty()) {
        bind_values.push(u.to_string());
        where_clauses.push(format!("actor_id = ?{}", bind_values.len()));
    }

    if let Some(v) = params.get("event_type").filter(|s| !s.is_empty()) {
        bind_values.push(v.to_string());
        where_clauses.push(format!("event_type = ?{}", bind_values.len()));
    }
    if let Some(v) = params.get("event_category").filter(|s| !s.is_empty()) {
        bind_values.push(v.to_string());
        where_clauses.push(format!("event_category = ?{}", bind_values.len()));
    }
    if let Some(v) = params.get("outcome").filter(|s| !s.is_empty()) {
        bind_values.push(v.to_string());
        where_clauses.push(format!("outcome = ?{}", bind_values.len()));
    }
    if let Some(v) = params.get("environment").filter(|s| !s.is_empty()) {
        bind_values.push(v.to_string());
        where_clauses.push(format!("environment = ?{}", bind_values.len()));
    }
    if let Some(v) = params.get("database").filter(|s| !s.is_empty()) {
        bind_values.push(v.to_string());
        where_clauses.push(format!("database_name = ?{}", bind_values.len()));
    }
    if let Some(v) = params.get("since").filter(|s| !s.is_empty()) {
        bind_values.push(v.to_string());
        where_clauses.push(format!("created_at >= ?{}", bind_values.len()));
    }
    if let Some(v) = params.get("until").filter(|s| !s.is_empty()) {
        bind_values.push(v.to_string());
        where_clauses.push(format!("created_at <= ?{}", bind_values.len()));
    }

    let where_sql = if where_clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", where_clauses.join(" AND "))
    };

    let count_sql = format!("SELECT COUNT(*) FROM audit_events {where_sql}");
    let total: i64 = conn
        .prepare(&count_sql)
        .and_then(|mut s| s.query_row(rusqlite::params_from_iter(&bind_values), |r| r.get(0)))
        .unwrap_or(0);

    let query_sql = format!(
        "SELECT id, event_type, event_category, outcome, actor_id, actor_type, resource_type, resource_id, peer_ip, client_ip, client_ip_source, request_id, operation, environment, database_name, detail_fingerprint, reason, metadata_json, event_hash, created_at FROM audit_events {where_sql} ORDER BY created_at DESC LIMIT ?{} OFFSET ?{}",
        bind_values.len() + 1,
        bind_values.len() + 2,
    );
    bind_values.push(limit.to_string());
    bind_values.push(offset.to_string());

    let mut stmt = conn.prepare(&query_sql)?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(&bind_values), |row| {
            Ok(json!({
                "id": row.get::<_, String>(0)?,
                "event_type": row.get::<_, String>(1)?,
                "event_category": row.get::<_, String>(2)?,
                "outcome": row.get::<_, String>(3)?,
                "actor_id": row.get::<_, String>(4)?,
                "actor_type": row.get::<_, String>(5)?,
                "resource_type": row.get::<_, Option<String>>(6)?,
                "resource_id": row.get::<_, Option<String>>(7)?,
                "peer_ip": row.get::<_, Option<String>>(8)?,
                "client_ip": row.get::<_, Option<String>>(9)?,
                "client_ip_source": row.get::<_, Option<String>>(10)?,
                "request_id": row.get::<_, Option<String>>(11)?,
                "operation": row.get::<_, Option<String>>(12)?,
                "environment": row.get::<_, Option<String>>(13)?,
                "database_name": row.get::<_, Option<String>>(14)?,
                "detail_fingerprint": row.get::<_, Option<String>>(15)?,
                "reason": row.get::<_, Option<String>>(16)?,
                "metadata": row.get::<_, String>(17).ok().and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok()).unwrap_or(json!({})),
                "event_hash": row.get::<_, String>(18)?,
                "created_at": row.get::<_, String>(19)?,
            }))
        })
        ?;

    let entries: Vec<serde_json::Value> = rows.filter_map(|r| r.ok()).collect();

    Ok(Json(json!({
        "audit_events": entries,
        "total": total,
        "limit": limit,
        "offset": offset,
    })))
}

/// Verify hash chain integrity.
pub(crate) async fn verify_audit_chain(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, crate::api_error::ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(
        &user,
        Action::ListAudit,
        Resource::AuditQuery {
            requested_user: None,
        },
    )
    .await?;

    let conn = state.db().await;
    let (count, broken) = crate::db::audit_event_repo::verify_hash_chain(&conn)?;

    Ok(Json(json!({
        "verified_events": count,
        "chain_intact": broken.is_none(),
        "first_broken_id": broken,
    })))
}
