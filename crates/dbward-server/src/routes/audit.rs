use axum::{
    Json,
    extract::{Extension, Query, State},
    http::StatusCode,
};
use chrono::{DateTime, Utc};
use dbward_app::ports::AuditFilter;
use dbward_app::use_cases::audit_query::{AuditListInput, AuditQuery};
use dbward_domain::auth::AuthUser;
use serde::Deserialize;

use crate::state::AppState;

use super::map_error;

#[derive(Deserialize, Default)]
pub struct ListParams {
    pub actor_id: Option<String>,
    pub event_type: Option<String>,
    pub event_category: Option<String>,
    pub outcome: Option<String>,
    pub environment: Option<String>,
    pub database: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

pub async fn list_events(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Query(params): Query<ListParams>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let uc = AuditQuery {
        authorizer: state.authorizer.clone(),
        audit_repo: state.audit_repo.clone(),
    };
    let output = uc
        .list(
            AuditListInput {
                filter: AuditFilter {
                    actor_id: params.actor_id,
                    event_type: params.event_type,
                    event_category: params.event_category,
                    outcome: params.outcome,
                    environment: params.environment,
                    database: params.database,
                    since: params.since,
                    until: params.until,
                    limit: params.limit.unwrap_or(50).min(200),
                    offset: params.offset.unwrap_or(0),
                },
            },
            &user,
        )
        .map_err(map_error)?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({ "events": output.events })),
    ))
}

pub async fn verify_chain(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let uc = AuditQuery {
        authorizer: state.authorizer.clone(),
        audit_repo: state.audit_repo.clone(),
    };
    let output = uc.verify(&user).map_err(map_error)?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "total_events": output.total_events,
            "first_broken_id": output.first_broken_id,
            "valid": output.first_broken_id.is_none(),
        })),
    ))
}
