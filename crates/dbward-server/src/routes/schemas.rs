use axum::Extension;
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};

use dbward_domain::auth::{AuthUser, Permission, ResourceContext};
use dbward_domain::values::{DatabaseName, Environment};

use crate::state::AppState;

#[derive(Deserialize)]
pub struct SchemaQuery {
    pub table: Option<String>,
    pub summary: Option<bool>,
    pub environment: Option<String>,
}

const ENV_PRIORITY: &[&str] = &["production", "staging", "development"];

// TODO(v0.2): Extract to use case layer
pub async fn get_schema(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(db): Path<String>,
    Query(query): Query<SchemaQuery>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    // 1. Check DB is registered
    let all_pairs = state.database_registry().list().map_err(map_error)?;
    let envs_for_db: Vec<&str> = all_pairs
        .iter()
        .filter(|(d, _)| d.as_str() == db)
        .map(|(_, e)| e.as_str())
        .collect();
    if envs_for_db.is_empty() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({"error": "database not registered", "code": "not_found"})),
        ));
    }

    // 2. Resolve env: ready + authorized, sorted by priority
    let mut candidates: Vec<&str> = Vec::new();
    if let Some(ref env_override) = query.environment {
        if envs_for_db.contains(&env_override.as_str()) {
            candidates.push(env_override);
        } else {
            return Err((
                StatusCode::NOT_FOUND,
                Json(
                    json!({"error": format!("environment '{}' not registered for database '{}'", env_override, db), "code": "not_found"}),
                ),
            ));
        }
    } else {
        for &p in ENV_PRIORITY {
            if envs_for_db.contains(&p) {
                candidates.push(p);
            }
        }
        let mut remaining: Vec<&str> = envs_for_db
            .iter()
            .copied()
            .filter(|e| !candidates.contains(e))
            .collect();
        remaining.sort_unstable();
        candidates.extend(remaining);
    }

    let mut any_ready = false;
    let mut resolved = None;
    for env in &candidates {
        let snapshot = state
            .schema_repo()
            .get_snapshot(&db, env)
            .map_err(map_error)?;
        if let Some(ref s) = snapshot.filter(|s| s.status == "ready") {
            any_ready = true;
            let db_name = DatabaseName::new(&db).map_err(map_internal)?;
            let env_val = Environment::new(*env).map_err(map_internal)?;
            if state
                .authorizer
                .authorize_scoped(
                    &user,
                    Permission::RequestView,
                    &db_name,
                    &env_val,
                    &ResourceContext::Global,
                )
                .is_ok()
            {
                resolved = Some((env.to_string(), s.clone()));
                break;
            }
        }
    }

    let (resolved_env, record) = match resolved {
        Some(r) => r,
        None => {
            if any_ready {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(json!({"error": "forbidden", "code": "forbidden"})),
                ));
            }
            return Err((
                StatusCode::NOT_FOUND,
                Json(
                    json!({"error": "schema not yet collected. Start an agent for this database.", "code": "not_found"}),
                ),
            ));
        }
    };

    // 3. Parse snapshot
    let snapshot_json = record.snapshot_json.as_deref().unwrap_or("{}");
    let snapshot: Value =
        serde_json::from_str(snapshot_json).map_err(|_| map_internal("internal error"))?;
    let tables = snapshot["tables"]
        .as_array()
        .ok_or_else(|| map_internal("internal error"))?
        .clone();

    // 4. Build response
    let base = json!({
        "database": db,
        "environment": resolved_env,
        "dialect": record.dialect,
        "status": record.status,
        "collected_at": record.collected_at,
    });

    if let Some(table_filter) = &query.table {
        let (schema_filter, name_filter) = if let Some((s, t)) = table_filter.split_once('.') {
            (Some(s), t)
        } else {
            (None, table_filter.as_str())
        };

        let matches: Vec<&Value> = tables
            .iter()
            .filter(|t| {
                let name = t["name"].as_str().unwrap_or("");
                let schema = t["schema_name"].as_str().unwrap_or("");
                if let Some(sf) = schema_filter {
                    name == name_filter && schema == sf
                } else {
                    name == name_filter
                }
            })
            .collect();

        match matches.len() {
            0 => Err((
                StatusCode::NOT_FOUND,
                Json(
                    json!({"error": format!("table '{}' not found in snapshot", table_filter), "code": "not_found"}),
                ),
            )),
            1 => {
                let mut resp = base;
                resp["table"] = matches[0].clone();
                Ok((StatusCode::OK, Json(resp)))
            }
            _ => {
                let schemas: Vec<&str> = matches
                    .iter()
                    .filter_map(|t| t["schema_name"].as_str())
                    .collect();
                Err((
                    StatusCode::NOT_FOUND,
                    Json(
                        json!({"error": format!("multiple tables named '{}' found in schemas: {}. Specify as schema.table", name_filter, schemas.join(", ")), "code": "not_found"}),
                    ),
                ))
            }
        }
    } else if query.summary.unwrap_or(true) {
        let summary_tables: Vec<Value> = tables
            .iter()
            .map(|t| {
                json!({
                    "name": t["name"],
                    "schema_name": t["schema_name"],
                    "estimated_rows": t["estimated_rows"],
                    "column_count": t["columns"].as_array().map(|a| a.len()).unwrap_or(0),
                    "constraint_count": t["constraints"].as_array().map(|a| a.len()).unwrap_or(0),
                    "index_count": t["indexes"].as_array().map(|a| a.len()).unwrap_or(0),
                })
            })
            .collect();
        let mut resp = base;
        resp["tables"] = json!(summary_tables);
        Ok((StatusCode::OK, Json(resp)))
    } else {
        let mut resp = base;
        resp["tables"] = json!(tables);
        Ok((StatusCode::OK, Json(resp)))
    }
}

fn map_error(e: impl std::fmt::Display) -> (StatusCode, Json<Value>) {
    tracing::error!(error = %e, "schema endpoint internal error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": "internal error", "code": "internal"})),
    )
}

fn map_internal(msg: &str) -> (StatusCode, Json<Value>) {
    tracing::error!(msg, "schema endpoint internal error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": "internal error", "code": "internal"})),
    )
}
