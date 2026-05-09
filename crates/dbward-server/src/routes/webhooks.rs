use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use tracing::error;

use crate::api_error::ApiError;
use crate::auth;
use crate::authz::{self, Action, Resource};
use crate::state::AppState;
use crate::webhook::validate_webhook_url;

#[derive(Deserialize)]
pub(crate) struct CreateWebhookRequest {
    pub url: String,
    #[serde(default)]
    pub events: Vec<String>,
    #[serde(default = "default_format")]
    pub format: String,
    pub secret: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct UpdateWebhookRequest {
    pub url: Option<String>,
    pub events: Option<Vec<String>>,
    pub format: Option<String>,
    /// None = field absent (no change), Some(None) = explicit null (remove), Some(Some(v)) = update
    #[serde(default, deserialize_with = "deserialize_double_option")]
    pub secret: Option<Option<String>>,
}

fn deserialize_double_option<'de, D>(deserializer: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    // If the field is present at all, we get called. null → Some(None), "value" → Some(Some(value))
    Option::<String>::deserialize(deserializer).map(Some)
}


fn default_format() -> String {
    "generic".to_string()
}

pub(crate) async fn create_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateWebhookRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::ManageWebhook, Resource::Global).await?;

    validate_webhook_url(&body.url)
        .map_err(|e| ApiError::bad_request(e).with_code("invalid_webhook_url"))?;

    if let Some(ref s) = body.secret {
        if s.is_empty() {
            return Err(
                ApiError::bad_request("secret must not be empty").with_code("validation_error")
            );
        }
    }

    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let events_json = serde_json::to_string(&body.events)
        .map_err(|e| ApiError::internal(e.to_string()))?;

    let conn = state.db().await;
    crate::db::webhook_repo::insert_webhook(
        &conn,
        &id,
        &body.url,
        &events_json,
        &body.format,
        body.secret.as_deref(),
        "api",
        &now,
    )
    .map_err(|e| ApiError::internal(e.to_string()))?;
    drop(conn);

    {
        let mut conn = state.db().await;
        let _ = crate::db::audit_event_repo::record_audit_event(
            &mut conn,
            crate::db::audit_event_repo::AuditEvent {
                event_type: "webhook_created",
                event_category: "policy",
                outcome: "success",
                actor_id: &user.user,
                actor_type: "user",
                resource_type: Some("webhook"),
                resource_id: Some(&id),
                peer_ip: None, client_ip: None, client_ip_source: None,
                request_id: None, operation: None, environment: None, database_name: None,
                detail_fingerprint: None, detail_raw: None, reason: None,
                metadata_json: &serde_json::json!({"url": body.url, "format": body.format}).to_string(),
            },
            &headers, &state.audit_config, &state.trusted_proxies,
        );
    }

    reload_webhooks(&state).await;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": id,
            "url": body.url,
            "events": body.events,
            "format": body.format,
            "has_secret": body.secret.is_some(),
            "status": "active",
            "source": "api",
            "created_at": now,
            "updated_at": now,
        })),
    ))
}

pub(crate) async fn list_webhooks(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::ManageWebhook, Resource::Global).await?;

    let conn = state.db().await;
    let webhooks = crate::db::webhook_repo::list_webhooks(&conn)
        .map_err(|e| ApiError::internal(e.to_string()))?;

    let items: Vec<serde_json::Value> = webhooks
        .into_iter()
        .map(|w| {
            let events: Vec<String> =
                serde_json::from_str(&w.events_json).unwrap_or_default();
            json!({
                "id": w.id,
                "url": w.url,
                "events": events,
                "format": w.format,
                "has_secret": w.has_secret,
                "status": w.status,
                "source": w.source,
                "created_at": w.created_at,
                "updated_at": w.updated_at,
            })
        })
        .collect();

    Ok(Json(json!({ "webhooks": items })))
}

pub(crate) async fn get_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::ManageWebhook, Resource::Global).await?;

    let conn = state.db().await;
    let w = crate::db::webhook_repo::get_webhook(&conn, &id)
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::not_found("webhook not found").with_code("webhook_not_found"))?;

    let events: Vec<String> = serde_json::from_str(&w.events_json).unwrap_or_default();
    Ok(Json(json!({
        "id": w.id,
        "url": w.url,
        "events": events,
        "format": w.format,
        "has_secret": w.has_secret,
        "status": w.status,
        "source": w.source,
        "created_at": w.created_at,
        "updated_at": w.updated_at,
    })))
}

pub(crate) async fn update_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<UpdateWebhookRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::ManageWebhook, Resource::Global).await?;

    if let Some(ref url) = body.url {
        validate_webhook_url(url)
            .map_err(|e| ApiError::bad_request(e).with_code("invalid_webhook_url"))?;
    }
    if let Some(Some(ref s)) = body.secret {
        if s.is_empty() {
            return Err(
                ApiError::bad_request("secret must not be empty").with_code("validation_error")
            );
        }
    }

    let now = chrono::Utc::now().to_rfc3339();
    let events_json = body
        .events
        .as_ref()
        .map(|e| serde_json::to_string(e).unwrap_or_default());

    let secret_param: Option<Option<&str>> = match &body.secret {
        None => None,
        Some(None) => Some(None),
        Some(Some(s)) => Some(Some(s.as_str())),
    };

    let conn = state.db().await;
    let updated = crate::db::webhook_repo::update_webhook(
        &conn,
        &id,
        body.url.as_deref(),
        events_json.as_deref(),
        body.format.as_deref(),
        secret_param,
        &now,
    )
    .map_err(|e| ApiError::internal(e.to_string()))?;

    if !updated {
        return Err(ApiError::not_found("webhook not found").with_code("webhook_not_found"));
    }

    let w = crate::db::webhook_repo::get_webhook(&conn, &id)
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::internal("webhook disappeared after update"))?;
    drop(conn);

    reload_webhooks(&state).await;

    {
        let mut conn = state.db().await;
        let _ = crate::db::audit_event_repo::record_audit_event(
            &mut conn,
            crate::db::audit_event_repo::AuditEvent {
                event_type: "webhook_updated",
                event_category: "policy",
                outcome: "success",
                actor_id: &user.user,
                actor_type: "user",
                resource_type: Some("webhook"),
                resource_id: Some(&id),
                peer_ip: None, client_ip: None, client_ip_source: None,
                request_id: None, operation: None, environment: None, database_name: None,
                detail_fingerprint: None, detail_raw: None, reason: None,
                metadata_json: &serde_json::json!({"url": w.url}).to_string(),
            },
            &headers, &state.audit_config, &state.trusted_proxies,
        );
    }

    let events: Vec<String> = serde_json::from_str(&w.events_json).unwrap_or_default();
    Ok(Json(json!({
        "id": w.id,
        "url": w.url,
        "events": events,
        "format": w.format,
        "has_secret": w.has_secret,
        "status": w.status,
        "source": w.source,
        "created_at": w.created_at,
        "updated_at": w.updated_at,
    })))
}

pub(crate) async fn delete_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user = auth::authenticate(&headers, &state).await?;
    authz::authorize(&user, Action::ManageWebhook, Resource::Global).await?;

    let conn = state.db().await;
    let deleted = crate::db::webhook_repo::delete_webhook(&conn, &id)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    drop(conn);

    if !deleted {
        return Err(ApiError::not_found("webhook not found").with_code("webhook_not_found"));
    }

    reload_webhooks(&state).await;

    {
        let mut conn = state.db().await;
        let _ = crate::db::audit_event_repo::record_audit_event(
            &mut conn,
            crate::db::audit_event_repo::AuditEvent {
                event_type: "webhook_deleted",
                event_category: "policy",
                outcome: "success",
                actor_id: &user.user,
                actor_type: "user",
                resource_type: Some("webhook"),
                resource_id: Some(&id),
                peer_ip: None, client_ip: None, client_ip_source: None,
                request_id: None, operation: None, environment: None, database_name: None,
                detail_fingerprint: None, detail_raw: None, reason: None,
                metadata_json: "{}",
            },
            &headers, &state.audit_config, &state.trusted_proxies,
        );
    }

    Ok(Json(json!({ "id": id, "deleted": true })))
}

/// Reload WebhookDispatcher from DB after CRUD operations.
async fn reload_webhooks(state: &AppState) {
    let conn = state.db().await;
    let configs = match crate::db::webhook_repo::load_active_webhook_configs(&conn) {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "BUG: failed to reload webhooks");
            return;
        }
    };
    drop(conn);

    let mut dispatcher = state.webhooks.write().unwrap();
    dispatcher.reload(configs);
}
