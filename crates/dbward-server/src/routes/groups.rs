use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use dbward_domain::auth::AuthUser;

use crate::state::AppState;

use super::map_error;

pub async fn list(
    State(state): State<AppState>,
    Extension(_user): Extension<AuthUser>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let groups = state.group_repo().list_names().map_err(map_error)?;
    Ok((StatusCode::OK, Json(serde_json::json!({ "groups": groups }))))
}

pub async fn show(
    State(state): State<AppState>,
    Extension(_user): Extension<AuthUser>,
    Path(name): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    if !state.group_repo().exists(&name).map_err(map_error)? {
        return Err(map_error(dbward_app::error::AppError::NotFound(
            "group not found".into(),
        )));
    }
    let members = state.group_repo().list_members(&name).map_err(map_error)?;
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "name": name,
            "members": members,
        })),
    ))
}
