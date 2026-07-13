use axum::{
    Json,
    extract::{Extension, Path, State},
    http::StatusCode,
};
use dbward_app::use_cases::user_manage::{UserAddInput, UserSuspendInput, UserUpdateInput};
use dbward_domain::auth::AuthUser;

use crate::middleware::trusted_proxies::ClientIp;
use crate::state::AppState;

use super::map_error;

pub async fn create(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    client_ip: Option<Extension<ClientIp>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let ctx = super::extract_audit_context(
        client_ip.as_ref().map(|e| &e.0),
        connect_info.as_ref().map(|e| &e.0),
    );

    let id = body
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            map_error(dbward_app::error::AppError::Validation(
                "id is required".into(),
            ))
        })?
        .to_string();

    let roles: Vec<String> = body
        .get("roles")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let groups: Vec<String> = body
        .get("groups")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let uc = state.users().manage();
    let output = uc
        .add(
            UserAddInput {
                id,
                roles,
                groups,
                slack_user_id: None,
                source: None,
                onboarding_claim: None,
            },
            &user,
            &ctx,
        )
        .map_err(map_error)?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": output.id,
            "token": output.token,
            "token_prefix": output.token_prefix,
            "roles": output.roles,
            "groups": output.groups,
        })),
    ))
}

pub async fn show(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let uc = state.users().manage();
    let output = uc.show(&id, &user).map_err(map_error)?;
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "id": output.user.id,
            "display_name": output.user.display_name,
            "email": output.user.email,
            "status": format!("{:?}", output.user.status).to_lowercase(),
            "roles": output.roles,
            "groups": output.groups,
            "created_at": output.user.created_at.to_rfc3339(),
        })),
    ))
}

pub async fn delete(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    client_ip: Option<Extension<ClientIp>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let ctx = super::extract_audit_context(
        client_ip.as_ref().map(|e| &e.0),
        connect_info.as_ref().map(|e| &e.0),
    );
    let uc = state.users().manage();
    uc.remove(&id, &user, &ctx).map_err(map_error)?;
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({ "id": id, "deleted": true })),
    ))
}

pub async fn update_roles_groups(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    client_ip: Option<Extension<ClientIp>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let ctx = super::extract_audit_context(
        client_ip.as_ref().map(|e| &e.0),
        connect_info.as_ref().map(|e| &e.0),
    );

    let set_roles = body.get("roles").and_then(|v| v.as_array()).map(|arr| {
        arr.iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect()
    });
    let add_roles: Vec<String> = body
        .get("add_roles")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let rm_roles: Vec<String> = body
        .get("rm_roles")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let add_groups: Vec<String> = body
        .get("add_groups")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let rm_groups: Vec<String> = body
        .get("rm_groups")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // Parse slack_user_id with proper null/type handling
    let slack_user_id: Option<Option<String>> = match body.get("slack_user_id") {
        Some(serde_json::Value::String(s)) => {
            let valid = s.is_empty()
                || (s.len() >= 2
                    && matches!(s.as_bytes()[0], b'U' | b'W')
                    && s[1..]
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()));
            if !valid {
                return Err(map_error(dbward_app::error::AppError::Validation(
                    "invalid slack_user_id format (expected ^[UW][A-Z0-9]+$ or empty string to clear)".into(),
                )));
            }
            Some(if s.is_empty() { None } else { Some(s.clone()) })
        }
        Some(serde_json::Value::Null) => Some(None), // explicit clear
        Some(_) => {
            return Err(map_error(dbward_app::error::AppError::Validation(
                "slack_user_id must be a string or null".into(),
            )));
        }
        None => None, // field absent
    };

    if set_roles.is_none()
        && add_roles.is_empty()
        && rm_roles.is_empty()
        && add_groups.is_empty()
        && rm_groups.is_empty()
        && slack_user_id.is_none()
    {
        return Err(map_error(dbward_app::error::AppError::Validation(
            "no updateable fields provided (use roles, add_roles, rm_roles, add_groups, rm_groups, slack_user_id)"
                .into(),
        )));
    }

    let has_role_group_changes = set_roles.is_some()
        || !add_roles.is_empty()
        || !rm_roles.is_empty()
        || !add_groups.is_empty()
        || !rm_groups.is_empty();

    // Authorization check (UserWrite required for any user mutation including slack_user_id link).
    // Design: slack_user_id linking is an admin-only operation. Self-service linking is done via
    // Slack onboarding flow, not direct API.
    state
        .authorizer()
        .authorize_global(&user, dbward_domain::auth::Permission::UserWrite)
        .map_err(|e| map_error(dbward_app::error::AppError::Forbidden(e)))?;

    // Reject if user is deleted
    if state.user_repo().is_deleted(&id).map_err(map_error)? {
        return Err(map_error(dbward_app::error::AppError::Gone(
            "user has been deleted".into(),
        )));
    }

    // Execute role/group update first (may fail validation)
    if has_role_group_changes {
        let uc = state.users().manage();
        uc.update(
            UserUpdateInput {
                user_id: id.clone(),
                set_roles,
                add_roles,
                rm_roles,
                add_groups,
                rm_groups,
            },
            &user,
            &ctx,
        )
        .map_err(map_error)?;
    }

    // Persist slack_user_id only after role/group update succeeds.
    // Note: not fully atomic with role/group UoW — if this write fails, roles are already
    // committed. Acceptable trade-off: slack_user_id is a link field, not a security-critical
    // mutation. Full atomicity would require extending UserUpdateInput (deferred to v0.2).
    if let Some(ref link_value) = slack_user_id {
        state
            .user_repo()
            .update_slack_user_id(&id, link_value.as_deref())
            .map_err(map_error)?;
    }

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({ "id": id, "updated": true })),
    ))
}

pub async fn me(Extension(user): Extension<AuthUser>) -> (StatusCode, Json<serde_json::Value>) {
    let roles: Vec<serde_json::Value> = user
        .roles
        .iter()
        .map(|r| {
            serde_json::json!({
                "name": r.name,
                "permissions": r.permissions.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
                "databases": r.databases.iter().map(|d| d.as_str()).collect::<Vec<_>>(),
                "environments": r.environments.iter().map(|e| e.as_str()).collect::<Vec<_>>(),
            })
        })
        .collect();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "subject_id": user.subject_id,
            "subject_type": user.subject_type,
            "roles": roles,
            "groups": user.groups,
        })),
    )
}

pub async fn list(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let uc = state.users().manage();
    let output = uc.list(&user).map_err(map_error)?;
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({ "users": output.users })),
    ))
}

pub async fn suspend(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    client_ip: Option<Extension<ClientIp>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let ctx = super::extract_audit_context(
        client_ip.as_ref().map(|e| &e.0),
        connect_info.as_ref().map(|e| &e.0),
    );
    let uc = state.users().manage();
    let output = uc
        .suspend(
            UserSuspendInput {
                user_id: id.clone(),
            },
            &user,
            &ctx,
        )
        .map_err(map_error)?;

    // Check if user is config-managed → add warning
    let source = get_user_source(state.user_repo(), &id);
    let mut resp = serde_json::json!({
        "id": output.id,
        "revoked_tokens": output.revoked_tokens,
        "cancelled_requests": output.cancelled_requests,
    });
    if source.as_deref() == Some("config") {
        resp["warning"] = serde_json::json!(
            "this user is config-managed; status will revert to config value on next server restart"
        );
        resp["source"] = serde_json::json!("config");
    }

    Ok((StatusCode::OK, Json(resp)))
}

pub async fn activate(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    client_ip: Option<Extension<ClientIp>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let ctx = super::extract_audit_context(
        client_ip.as_ref().map(|e| &e.0),
        connect_info.as_ref().map(|e| &e.0),
    );
    let uc = state.users().manage();
    uc.activate(&id, &user, &ctx).map_err(map_error)?;

    let source = get_user_source(state.user_repo(), &id);
    let mut resp = serde_json::json!({ "id": id });
    if source.as_deref() == Some("config") {
        resp["warning"] = serde_json::json!(
            "this user is config-managed; status will revert to config value on next server restart"
        );
        resp["source"] = serde_json::json!("config");
    }
    Ok((StatusCode::OK, Json(resp)))
}

/// Query the source column for a user (returns None if user not found or error).
fn get_user_source(
    repo: &std::sync::Arc<dyn dbward_app::ports::UserRepo>,
    user_id: &str,
) -> Option<String> {
    repo.get_source(user_id).ok().flatten()
}

pub async fn reissue_initial_token(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    client_ip: Option<Extension<ClientIp>>,
    connect_info: Option<Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    Path(user_id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let ctx = super::extract_audit_context(
        client_ip.as_ref().map(|e| &e.0),
        connect_info.as_ref().map(|e| &e.0),
    );

    if user_id.is_empty() {
        return Err(map_error(dbward_app::error::AppError::Validation(
            "user_id is required".into(),
        )));
    }

    let uc = state.tokens().manage();
    let output = uc
        .reissue_initial(&user_id, &user, &ctx)
        .map_err(map_error)?;

    // Attempt Slack DM delivery
    let mut delivery_status = "not_configured";
    let mut delivery_channel: Option<&str> = None;
    let mut token_response: Option<&str> = None;
    let mut plaintext_returned = false;
    let mut dm_error: Option<String> = None;

    let slack_user_id = state.user_repo().get_slack_user_id(&user_id).ok().flatten();

    if let (Some(sc), Some(slack_id)) = (&state.slack_client, &slack_user_id) {
        delivery_channel = Some("slack_dm");
        let dm_text = format!(
            "🔑 Your dbward initial token has been reissued.\n\n\
             Your new API token (save it securely — it won't be shown again):\n\
             ```{}```\n\n\
             Configure it:\n\
             ```export DBWARD_API_TOKEN={}```",
            output.plaintext, output.plaintext
        );
        match sc
            .post_message(
                slack_id,
                &[serde_json::json!({
                    "type": "section",
                    "text": { "type": "mrkdwn", "text": dm_text }
                })],
                "Your dbward token has been reissued.",
            )
            .await
        {
            Ok(_) => {
                delivery_status = "delivered";
            }
            Err(e) => {
                tracing::warn!(error = %e, user_id = %user_id, "reissue: DM delivery failed");
                dm_error = Some(e.to_string());
                delivery_status = "failed";
                token_response = Some(&output.plaintext);
                plaintext_returned = true;
            }
        }
    } else {
        // Slack not configured or user has no slack_user_id
        token_response = Some(&output.plaintext);
        plaintext_returned = true;
    }

    let manual_recovery_required = plaintext_returned;

    // Record delivery outcome in audit (supplements the UC-level audit event)
    {
        let delivery_metadata = serde_json::json!({
            "delivery_attempted": delivery_channel.is_some(),
            "delivery_status": delivery_status,
            "delivery_channel": delivery_channel,
            "dm_error": dm_error,
            "plaintext_returned": plaintext_returned,
            "new_token_id": output.new_token_id,
            "target_user": user_id,
        });
        let mut delivery_audit = dbward_domain::entities::AuditEvent::simple(
            "token.reissued_initial.delivery",
            "token",
            &user.subject_id,
            Some(&output.new_token_id),
            chrono::Utc::now(),
            &ctx,
        );
        delivery_audit.metadata_json = delivery_metadata.to_string();
        if let Err(e) = state.uow().execute(Box::new(move |tx| {
            tx.record(&delivery_audit)?;
            Ok(())
        })) {
            tracing::error!(error = %e, "reissue: failed to record delivery audit event");
        }
    }

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "reissued_token_id": output.new_token_id,
            "reissued_at": chrono::Utc::now().to_rfc3339(),
            "revoked_old_token_id": output.old_token_id,
            "delivery_status": delivery_status,
            "delivery_channel": delivery_channel,
            "token": token_response,
            "manual_recovery_required": manual_recovery_required,
        })),
    ))
}
