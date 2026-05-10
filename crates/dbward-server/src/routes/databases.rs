use axum::{extract::State, Json};
use serde_json::json;

use crate::state::AppState;

pub(crate) async fn list_databases(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, crate::api_error::ApiError> {
    let conn = state.db().await;
    let databases = crate::db::database_repo::list_databases(&conn)
        .map_err(|e| crate::api_error::ApiError::internal(format!("list databases: {e}")))?;

    let result: Vec<serde_json::Value> = databases
        .into_iter()
        .map(|(name, envs)| json!({"name": name, "environments": envs}))
        .collect();

    Ok(Json(json!({ "databases": result })))
}
