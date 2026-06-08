use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use dbward_domain::auth::{AuthUser, Permission};

use crate::state::AppState;

use super::map_error;

pub async fn list(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    state
        .authorizer
        .authorize_global(&user, Permission::WorkflowRead)
        .map_err(|e| map_error(dbward_app::error::AppError::Forbidden(e)))?;
    let webhooks = state.webhook_repo().list().map_err(map_error)?;
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({ "webhooks": webhooks })),
    ))
}

pub async fn get(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    state
        .authorizer
        .authorize_global(&user, Permission::WorkflowRead)
        .map_err(|e| map_error(dbward_app::error::AppError::Forbidden(e)))?;
    let webhook = state
        .webhook_repo()
        .get(&id)
        .map_err(map_error)?
        .ok_or_else(|| {
            map_error(dbward_app::error::AppError::NotFound(format!(
                "webhook '{id}' not found"
            )))
        })?;
    Ok((StatusCode::OK, Json(serde_json::json!(webhook))))
}

#[derive(serde::Deserialize)]
pub(super) struct DeliveryListParams {
    pub status: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

pub(super) async fn list_deliveries(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    axum::extract::Query(params): axum::extract::Query<DeliveryListParams>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    state
        .authorizer
        .authorize_global(&user, Permission::MetricsView)
        .map_err(|e| map_error(dbward_app::error::AppError::Forbidden(e)))?;

    let limit = params.limit.unwrap_or(50).min(100);
    let offset = params.offset.unwrap_or(0);

    if let Some(repo) = state.admin().webhook_delivery_repo() {
        let (deliveries, total) = repo
            .list_by_status(params.status.as_deref(), limit, offset)
            .map_err(map_error)?;
        let items: Vec<serde_json::Value> = deliveries
            .iter()
            .map(|d| {
                serde_json::json!({
                    "id": d.id,
                    "webhook_id": d.webhook_id,
                    "event_type": d.event_type,
                    "status": match d.status {
                        dbward_domain::entities::DeliveryStatus::Pending => "pending",
                        dbward_domain::entities::DeliveryStatus::InProgress => "in_progress",
                        dbward_domain::entities::DeliveryStatus::Delivered => "delivered",
                        dbward_domain::entities::DeliveryStatus::Dead => "dead",
                    },
                    "attempts": d.attempts,
                    "max_attempts": d.max_attempts,
                    "last_error": d.last_error,
                    "created_at": d.created_at.to_rfc3339(),
                    "next_retry_at": d.next_retry_at.map(|t| t.to_rfc3339()),
                })
            })
            .collect();
        Ok((
            StatusCode::OK,
            Json(serde_json::json!({ "deliveries": items, "total": total })),
        ))
    } else {
        Ok((
            StatusCode::OK,
            Json(serde_json::json!({ "deliveries": [], "total": 0 })),
        ))
    }
}
