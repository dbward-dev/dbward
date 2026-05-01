use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;

use crate::auth;
use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/requests", get(list_requests).post(create_request))
        .route("/api/requests/{id}", get(get_request))
        .route(
            "/api/requests/{id}/approve",
            axum::routing::post(approve_request),
        )
        .route(
            "/api/requests/{id}/reject",
            axum::routing::post(reject_request),
        )
        .route(
            "/api/requests/{id}/complete",
            axum::routing::post(complete_request),
        )
        .route("/api/audit", get(list_audit))
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    Json(json!({"status": "ok"}))
}

async fn list_requests(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let _user = auth::authenticate(&headers, &state)?;

    let conn = state.sqlite.lock().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let mut stmt = conn
        .prepare("SELECT id, user, operation, environment, detail, status, approved_by, created_at, resolved_at FROM requests ORDER BY created_at DESC")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let rows: Vec<serde_json::Value> = stmt
        .query_map([], |row| {
            Ok(json!({
                "id": row.get::<_, String>(0)?,
                "user": row.get::<_, String>(1)?,
                "operation": row.get::<_, String>(2)?,
                "environment": row.get::<_, String>(3)?,
                "detail": row.get::<_, String>(4)?,
                "status": row.get::<_, String>(5)?,
                "approved_by": row.get::<_, Option<String>>(6)?,
                "created_at": row.get::<_, String>(7)?,
                "resolved_at": row.get::<_, Option<String>>(8)?,
            }))
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .filter_map(|r| r.ok())
        .collect();

    Ok(Json(json!({"requests": rows})))
}

async fn create_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state)?;

    let operation = body["operation"]
        .as_str()
        .ok_or((StatusCode::BAD_REQUEST, "operation required".into()))?;
    let environment = body["environment"]
        .as_str()
        .ok_or((StatusCode::BAD_REQUEST, "environment required".into()))?;
    let detail = body["detail"].as_str().unwrap_or("");

    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    let conn = state.sqlite.lock().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    conn.execute(
        "INSERT INTO requests (id, user, operation, environment, detail, status, created_at) VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6)",
        rusqlite::params![id, user.user, operation, environment, detail, now],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok((
        StatusCode::CREATED,
        Json(json!({"id": id, "status": "pending"})),
    ))
}

async fn approve_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let approver = auth::authenticate(&headers, &state)?;

    let conn = state.sqlite.lock().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Fetch request
    let (req_user, status): (String, String) = conn
        .query_row(
            "SELECT user, status FROM requests WHERE id = ?1",
            rusqlite::params![id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "request not found".into()))?;

    if status != "pending" {
        return Err((StatusCode::CONFLICT, format!("request is already {status}")));
    }

    // Requester ≠ approver
    if req_user == approver.user {
        return Err((
            StatusCode::FORBIDDEN,
            "requester cannot approve their own request".into(),
        ));
    }

    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "UPDATE requests SET status = 'approved', approved_by = ?1, resolved_at = ?2 WHERE id = ?3",
        rusqlite::params![approver.user, now, id],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(json!({"id": id, "status": "approved", "approved_by": approver.user})))
}

async fn reject_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state)?;

    let conn = state.sqlite.lock().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let (req_user, status): (String, String) = conn
        .query_row(
            "SELECT user, status FROM requests WHERE id = ?1",
            rusqlite::params![id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "request not found".into()))?;

    if status != "pending" {
        return Err((StatusCode::CONFLICT, format!("request is already {status}")));
    }

    // Only admin or the requester can reject
    if user.role != dbward_core::Role::Admin && user.user != req_user {
        return Err((StatusCode::FORBIDDEN, "only admin or the requester can reject".into()));
    }

    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "UPDATE requests SET status = 'rejected', resolved_at = ?1 WHERE id = ?2",
        rusqlite::params![now, id],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(json!({"id": id, "status": "rejected"})))
}

async fn get_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let _user = auth::authenticate(&headers, &state)?;

    let conn = state.sqlite.lock().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let row: serde_json::Value = conn
        .query_row(
            "SELECT id, user, operation, environment, detail, status, approved_by, created_at, resolved_at FROM requests WHERE id = ?1",
            rusqlite::params![id],
            |row| {
                Ok(json!({
                    "id": row.get::<_, String>(0)?,
                    "user": row.get::<_, String>(1)?,
                    "operation": row.get::<_, String>(2)?,
                    "environment": row.get::<_, String>(3)?,
                    "detail": row.get::<_, String>(4)?,
                    "status": row.get::<_, String>(5)?,
                    "approved_by": row.get::<_, Option<String>>(6)?,
                    "created_at": row.get::<_, String>(7)?,
                    "resolved_at": row.get::<_, Option<String>>(8)?,
                }))
            },
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "request not found".into()))?;

    Ok(Json(row))
}

async fn complete_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user = auth::authenticate(&headers, &state)?;

    let conn = state.sqlite.lock().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let (req_user, status): (String, String) = conn
        .query_row(
            "SELECT user, status FROM requests WHERE id = ?1",
            rusqlite::params![id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| (StatusCode::NOT_FOUND, "request not found".into()))?;

    // Only the requester (or admin) can report completion
    if req_user != user.user && user.role != dbward_core::Role::Admin {
        return Err((StatusCode::FORBIDDEN, "only the requester can report completion".into()));
    }

    if status != "approved" && status != "auto_approved" {
        return Err((StatusCode::CONFLICT, format!("request status is {status}, expected approved")));
    }

    let success = body["success"].as_bool().unwrap_or(false);
    let new_status = if success { "executed" } else { "failed" };
    let now = chrono::Utc::now().to_rfc3339();

    conn.execute(
        "UPDATE requests SET status = ?1, resolved_at = ?2 WHERE id = ?3",
        rusqlite::params![new_status, now, id],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Write audit log
    let audit_id = uuid::Uuid::new_v4().to_string();
    let detail = body["result"].as_str().unwrap_or("");
    let error_msg = body["error_message"].as_str();
    let operation = conn
        .query_row("SELECT operation FROM requests WHERE id = ?1", rusqlite::params![id], |row| row.get::<_, String>(0))
        .unwrap_or_default();

    conn.execute(
        "INSERT INTO audit_log (id, timestamp, user, role, operation, environment, detail, success, error_message, request_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        rusqlite::params![
            audit_id, now, req_user, user.role.to_string(), operation,
            "", detail, success, error_msg, id
        ],
    )
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(json!({"id": id, "status": new_status})))
}

async fn list_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let _user = auth::authenticate(&headers, &state)?;

    let conn = state.sqlite.lock().map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let mut stmt = conn
        .prepare("SELECT id, timestamp, user, role, operation, environment, detail, success, error_message, request_id FROM audit_log ORDER BY timestamp DESC LIMIT 100")
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let rows: Vec<serde_json::Value> = stmt
        .query_map([], |row| {
            Ok(json!({
                "id": row.get::<_, String>(0)?,
                "timestamp": row.get::<_, String>(1)?,
                "user": row.get::<_, String>(2)?,
                "role": row.get::<_, String>(3)?,
                "operation": row.get::<_, String>(4)?,
                "environment": row.get::<_, String>(5)?,
                "detail": row.get::<_, String>(6)?,
                "success": row.get::<_, bool>(7)?,
                "error_message": row.get::<_, Option<String>>(8)?,
                "request_id": row.get::<_, Option<String>>(9)?,
            }))
        })
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .filter_map(|r| r.ok())
        .collect();

    Ok(Json(json!({"audit_log": rows})))
}
