use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use dbward_app::use_cases::webhook_manage::{
    WebhookCreateInput, WebhookDeleteInput, WebhookManage, WebhookUpdateInput,
};
use dbward_domain::auth::AuthUser;
use serde::Deserialize;

use crate::state::AppState;

use super::map_error;

#[derive(Deserialize)]
pub struct CreateBody {
    pub url: String,
    #[serde(default)]
    pub events: Vec<String>,
    #[serde(default = "default_format")]
    pub format: String,
    pub secret: Option<String>,
}

fn default_format() -> String {
    "generic".into()
}

#[derive(Deserialize)]
pub struct UpdateBody {
    pub url: Option<String>,
    pub events: Option<Vec<String>>,
    pub format: Option<String>,
    pub secret: Option<Option<String>>,
}

fn make_uc(state: &AppState) -> WebhookManage {
    WebhookManage {
        authorizer: state.authorizer.clone(),
        webhook_repo: state.webhook_repo.clone(),
        ssrf_validator: state.ssrf_validator.clone(),
        license: state.license_checker.clone(),
        audit: state.audit_logger.clone(),
        notifier: state.notifier.clone(),
        clock: state.clock.clone(),
        id_gen: state.id_generator.clone(),
    }
}

pub async fn create(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Json(body): Json<CreateBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let uc = make_uc(&state);
    let webhook = uc
        .create(
            WebhookCreateInput {
                url: body.url,
                events: body.events,
                format: body.format,
                secret: body.secret,
            },
            &user,
        )
        .map_err(map_error)?;

    Ok((StatusCode::CREATED, Json(serde_json::json!(webhook))))
}

pub async fn list(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let uc = make_uc(&state);
    let webhooks = uc.list(&user).map_err(map_error)?;
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
    let uc = make_uc(&state);
    let webhook = uc.get(&id, &user).map_err(map_error)?;
    Ok((StatusCode::OK, Json(serde_json::json!(webhook))))
}

pub async fn update(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    Json(body): Json<UpdateBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let uc = make_uc(&state);
    let webhook = uc
        .update(
            WebhookUpdateInput {
                id,
                url: body.url,
                events: body.events,
                format: body.format,
                secret: body.secret,
            },
            &user,
        )
        .map_err(map_error)?;

    Ok((StatusCode::OK, Json(serde_json::json!(webhook))))
}

pub async fn delete(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let uc = make_uc(&state);
    uc.delete(WebhookDeleteInput { id }, &user)
        .map_err(map_error)?;
    Ok((StatusCode::NO_CONTENT, Json(serde_json::json!(null))))
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
        .authorize_global(&user, dbward_domain::auth::Permission::MetricsView)
        .map_err(|e| map_error(dbward_app::error::AppError::Forbidden(e)))?;

    let limit = params.limit.unwrap_or(50).min(100);
    let offset = params.offset.unwrap_or(0);

    if let Some(ref repo) = state.webhook_delivery_repo {
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
