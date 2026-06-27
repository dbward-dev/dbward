use axum::Extension;
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};

use dbward_app::use_cases::get_schema::GetSchemaInput;
use dbward_domain::auth::AuthUser;

use crate::state::AppState;

#[derive(Deserialize)]
pub struct SchemaQuery {
    pub table: Option<String>,
    pub summary: Option<bool>,
    pub environment: Option<String>,
}

pub async fn get_schema(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(db): Path<String>,
    Query(query): Query<SchemaQuery>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let input = GetSchemaInput {
        database: db,
        environment: query.environment,
        table: query.table,
        summary: query.summary.unwrap_or(true),
    };

    let output = state.schemas().get().execute(input, &user).map_err(|e| {
        use dbward_app::error::AppError;
        match e {
            AppError::NotFound(msg) => (
                StatusCode::NOT_FOUND,
                Json(json!({"error": msg, "code": "not_found"})),
            ),
            AppError::Forbidden(_) => (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "forbidden", "code": "forbidden"})),
            ),
            _ => {
                tracing::error!(error = %e, "schema endpoint internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "internal error", "code": "internal"})),
                )
            }
        }
    })?;

    let resp = serde_json::to_value(&output).unwrap_or_else(|_| json!({"error": "serialization"}));
    Ok((StatusCode::OK, Json(resp)))
}
