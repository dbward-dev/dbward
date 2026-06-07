use axum::{
    Json,
    extract::{Extension, State},
    http::StatusCode,
};
use dbward_domain::auth::AuthUser;

use crate::state::AppState;

use super::map_error;

pub async fn list(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let databases = state.list_databases(&user).map_err(map_error)?;
    let items: Vec<_> = databases
        .iter()
        .map(|(db, env)| serde_json::json!({ "database": db, "environment": env }))
        .collect();
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({ "databases": items })),
    ))
}
