use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    Json,
};
use dbward_app::use_cases::webhook_manage::{WebhookCreateInput, WebhookDeleteInput, WebhookManage, WebhookUpdateInput};
use dbward_domain::auth::AuthUser;
use serde::Deserialize;

use crate::state::AppState;

use super::map_error;

#[derive(Deserialize)]
pub struct CreateBody {
    pub url: String,
    #[serde(default)]
    pub events: Vec<String>,
    pub format: String,
    pub secret: Option<String>,
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
    let webhook = uc.create(
        WebhookCreateInput {
            url: body.url,
            events: body.events,
            format: body.format,
            secret: body.secret,
        },
        &user,
    ).map_err(map_error)?;

    Ok((StatusCode::CREATED, Json(serde_json::json!(webhook))))
}

pub async fn list(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let uc = make_uc(&state);
    let webhooks = uc.list(&user).map_err(map_error)?;
    Ok((StatusCode::OK, Json(serde_json::json!({ "webhooks": webhooks }))))
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
    let webhook = uc.update(
        WebhookUpdateInput {
            id,
            url: body.url,
            events: body.events,
            format: body.format,
            secret: body.secret,
        },
        &user,
    ).map_err(map_error)?;

    Ok((StatusCode::OK, Json(serde_json::json!(webhook))))
}

pub async fn delete(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let uc = make_uc(&state);
    uc.delete(WebhookDeleteInput { id }, &user).map_err(map_error)?;
    Ok((StatusCode::NO_CONTENT, Json(serde_json::json!(null))))
}
