use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use dbward_domain::auth::{AuthUser, SubjectType};
use dbward_domain::entities::AuditContext;

use crate::state::AppState;

/// Resolve a Slack user into a fully-populated AuthUser with suspended check.
/// Shared by button callback and modal submission to prevent auth bypass.
async fn resolve_slack_auth_user(
    state: &AppState,
    slack_user_id: &str,
) -> Result<AuthUser, String> {
    let user_repo = state.user_repo();
    let subject_id = user_repo
        .find_by_slack_user_id(slack_user_id)
        .map_err(|e| format!("DB error: {e}"))?
        .ok_or_else(|| "not_linked".to_string())?;

    if user_repo
        .is_suspended(&subject_id)
        .map_err(|e| format!("DB error: {e}"))?
    {
        return Err("suspended".to_string());
    }

    let user = user_repo
        .get(&subject_id)
        .map_err(|e| format!("DB error: {e}"))?
        .ok_or_else(|| "user not found".to_string())?;

    let roles = state
        .reloadable
        .load()
        .role_resolver
        .resolve(&subject_id, SubjectType::User, &user.groups)
        .map_err(|e| format!("{e}"))?;

    let mut auth_user = AuthUser {
        subject_id,
        subject_type: SubjectType::User,
        roles,
        groups: user.groups,
        token_id: None,
    };
    // Augment with TOML [[auth.groups]] membership
    if let Some(config_groups) = state
        .reloadable
        .load()
        .role_resolver
        .config_groups_for(&auth_user.subject_id)
    {
        for g in config_groups {
            if !auth_user.groups.contains(g) {
                auth_user.groups.push(g.clone());
            }
        }
    }
    Ok(auth_user)
}

/// Verify Slack request signature and return the SlackConfig if valid.
#[allow(clippy::result_large_err)]
fn verify_slack_request<'a>(
    state: &'a AppState,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<&'a dbward_infra::slack::SlackConfig, Response> {
    let slack_config = state
        .slack_config
        .as_ref()
        .ok_or_else(|| StatusCode::NOT_FOUND.into_response())?;

    let timestamp = headers
        .get("x-slack-request-timestamp")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let signature = headers
        .get("x-slack-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !verify_signature(&slack_config.signing_secret, timestamp, body, signature) {
        tracing::warn!("slack signature verification failed");
        return Err(StatusCode::UNAUTHORIZED.into_response());
    }

    Ok(slack_config)
}

/// Slack interaction endpoint. Receives button clicks (approve/reject).
/// No auth middleware — uses Slack signature verification instead.
pub async fn interactions(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let slack_config = match verify_slack_request(&state, &headers, &body) {
        Ok(cfg) => cfg,
        Err(resp) => return resp,
    };

    // Parse payload (form-encoded: payload=<json>)
    let payload_str = form_urlencoded::parse(body.as_ref())
        .find(|(key, _)| key == "payload")
        .map(|(_, value)| value.into_owned())
        .unwrap_or_default();

    let payload: serde_json::Value = match serde_json::from_str(&payload_str) {
        Ok(v) => v,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let payload_type = payload["type"].as_str().unwrap_or("");

    match payload_type {
        "block_actions" => handle_block_actions(&state, slack_config, &payload)
            .await
            .into_response(),
        "view_submission" => handle_view_submission(&state, slack_config, &payload).await,
        other => {
            tracing::debug!(payload_type = other, "unknown slack interaction type");
            StatusCode::OK.into_response()
        }
    }
}

/// Button click → check user linked → open Review Modal → hydrate with context.
async fn handle_block_actions(
    state: &AppState,
    _slack_config: &dbward_infra::slack::SlackConfig,
    payload: &serde_json::Value,
) -> StatusCode {
    let action = match payload["actions"].as_array().and_then(|a| a.first()) {
        Some(a) => a,
        None => return StatusCode::OK,
    };

    let action_id = action["action_id"].as_str().unwrap_or("");
    let request_id = action["value"].as_str().unwrap_or("").to_string();
    let trigger_id = payload["trigger_id"].as_str().unwrap_or("").to_string();
    let slack_user_id = payload["user"]["id"].as_str().unwrap_or("").to_string();
    let channel_id = payload["channel"]["id"].as_str().unwrap_or("").to_string();

    if action_id != "dbward_review"
        && action_id != "dbward_resume"
        && action_id != "dbward_view_result"
    {
        return StatusCode::OK;
    }
    if request_id.is_empty() {
        return StatusCode::OK;
    }

    // DX-12: Resume button handler — open confirmation modal
    if action_id == "dbward_resume" {
        if trigger_id.is_empty() {
            return StatusCode::OK;
        }
        let state_clone = state.clone();
        tokio::spawn(async move {
            let auth_user = match resolve_slack_auth_user(&state_clone, &slack_user_id).await {
                Ok(u) => u,
                Err(e) => {
                    if let Some(ref sc) = state_clone.slack_client {
                        let msg = if e == "not_linked" {
                            format!(
                                "⚠️ Your Slack account is not linked to dbward.\nRun: `dbward user link-slack {slack_user_id}`"
                            )
                        } else {
                            "⚠️ Authentication failed.".to_string()
                        };
                        let _ = sc.post_ephemeral(&channel_id, &slack_user_id, &msg).await;
                    }
                    return;
                }
            };

            // Use GetRequest UC for consistent permission check
            let get_output = match state_clone
                .requests()
                .get()
                .execute(&request_id, &auth_user)
            {
                Ok(o) => o,
                Err(dbward_app::error::AppError::Forbidden(_)) => {
                    if let Some(ref sc) = state_clone.slack_client {
                        let _ = sc
                            .post_ephemeral(
                                &channel_id,
                                &slack_user_id,
                                "⚠️ You don't have permission to view this request.",
                            )
                            .await;
                    }
                    return;
                }
                Err(_) => {
                    if let Some(ref sc) = state_clone.slack_client {
                        let _ = sc
                            .post_ephemeral(
                                &channel_id,
                                &slack_user_id,
                                "⚠️ Request not found or expired.",
                            )
                            .await;
                    }
                    return;
                }
            };

            // Additionally check RequestResume permission (GetRequest only checks View)
            if get_output.request.requester != auth_user.subject_id
                && state_clone
                    .authorizer
                    .authorize_scoped(
                        &auth_user,
                        dbward_domain::auth::Permission::RequestResume,
                        &get_output.request.database,
                        &get_output.request.environment,
                        &dbward_domain::auth::ResourceContext::Request {
                            requester_id: get_output.request.requester.clone(),
                        },
                    )
                    .is_err()
            {
                if let Some(ref sc) = state_clone.slack_client {
                    let _ = sc
                        .post_ephemeral(
                            &channel_id,
                            &slack_user_id,
                            "⚠️ You don't have permission to resume this request.",
                        )
                        .await;
                }
                return;
            }

            let modal = dbward_infra::slack::block_kit::build_resume_confirm_modal(
                &request_id,
                &get_output.detail,
                get_output.request.database.as_str(),
                get_output.request.environment.as_str(),
            );
            if let Some(ref sc) = state_clone.slack_client
                && let Err(e) = sc.open_modal(&trigger_id, &modal).await
            {
                tracing::warn!(error = %e, "failed to open resume confirm modal");
            }
        });
        return StatusCode::OK;
    }

    // DX-13: View Result button handler
    if action_id == "dbward_view_result" {
        if trigger_id.is_empty() {
            return StatusCode::OK;
        }
        let state_clone = state.clone();
        tokio::spawn(async move {
            // Open loading modal immediately (trigger_id expires quickly)
            let loading = dbward_infra::slack::block_kit::build_result_modal_unavailable(
                &request_id,
                "Loading...",
            );
            let view_id = if let Some(ref sc) = state_clone.slack_client {
                match sc.open_modal(&trigger_id, &loading).await {
                    Ok(id) => id,
                    Err(_) => return,
                }
            } else {
                return;
            };

            let auth_user = match resolve_slack_auth_user(&state_clone, &slack_user_id).await {
                Ok(u) => u,
                Err(_) => {
                    if let Some(ref sc) = state_clone.slack_client {
                        let err_modal =
                            dbward_infra::slack::block_kit::build_result_modal_unavailable(
                                &request_id,
                                "Authentication failed.",
                            );
                        if let Err(e) = sc.update_modal(&view_id, &err_modal).await {
                            tracing::debug!(error = %e, "slack modal update failed");
                        }
                    }
                    return;
                }
            };
            let uc = state_clone.requests().get_result();
            let input = dbward_app::use_cases::get_result::GetResultInput {
                request_id: request_id.clone(),
                execution_id: None,
            };
            match uc.execute(input, &auth_user).await {
                Ok(output) => {
                    let mut buf = Vec::new();
                    let content_length = output.stream.content_length;
                    let mut stream = output.stream.stream;
                    loop {
                        use std::pin::Pin;
                        let next =
                            std::future::poll_fn(|cx| Pin::as_mut(&mut stream).poll_next(cx)).await;
                        match next {
                            Some(Ok(bytes)) => {
                                buf.extend_from_slice(&bytes);
                                if buf.len() > 64 * 1024 {
                                    break;
                                }
                            }
                            _ => break,
                        }
                    }
                    let text = String::from_utf8_lossy(&buf);
                    let sql = state_clone
                        .requests()
                        .get()
                        .execute(&request_id, &auth_user)
                        .ok()
                        .map(|o| o.detail);
                    let modal = dbward_infra::slack::block_kit::build_result_modal(
                        &request_id,
                        sql.as_deref(),
                        &text,
                        content_length,
                    );
                    if let Some(ref sc) = state_clone.slack_client
                        && let Err(e) = sc.update_modal(&view_id, &modal).await
                    {
                        tracing::debug!(error = %e, "slack modal update failed");
                    }
                }
                Err(dbward_app::error::AppError::Gone(msg)) => {
                    let modal = dbward_infra::slack::block_kit::build_result_modal_unavailable(
                        &request_id,
                        &msg,
                    );
                    if let Some(ref sc) = state_clone.slack_client
                        && let Err(e) = sc.update_modal(&view_id, &modal).await
                    {
                        tracing::debug!(error = %e, "slack modal update failed");
                    }
                }
                Err(dbward_app::error::AppError::Forbidden(_)) => {
                    if let Some(ref sc) = state_clone.slack_client {
                        let modal = dbward_infra::slack::block_kit::build_result_modal_unavailable(
                            &request_id,
                            "You don't have permission to view this result.",
                        );
                        if let Err(e) = sc.update_modal(&view_id, &modal).await {
                            tracing::debug!(error = %e, "slack modal update failed");
                        }
                    }
                }
                Err(e) => {
                    if let Some(ref sc) = state_clone.slack_client {
                        let msg = match &e {
                            dbward_app::error::AppError::NotFound(m) => m.as_str(),
                            dbward_app::error::AppError::Conflict(m) => m.as_str(),
                            dbward_app::error::AppError::Gone(m) => m.as_str(),
                            _ => "Failed to load result.",
                        };
                        let modal = dbward_infra::slack::block_kit::build_result_modal_unavailable(
                            &request_id,
                            msg,
                        );
                        if let Err(e) = sc.update_modal(&view_id, &modal).await {
                            tracing::debug!(error = %e, "slack modal update failed");
                        }
                    }
                }
            }
        });
        return StatusCode::OK;
    }

    // dbward_review: open review modal
    if trigger_id.is_empty() {
        return StatusCode::OK;
    }

    // Resolve user with suspended check
    let auth_user = match resolve_slack_auth_user(state, &slack_user_id).await {
        Ok(u) => u,
        Err(e) => {
            tracing::warn!(slack_user_id = %slack_user_id, error = %e, "slack auth resolution failed");
            if let Some(ref slack_client) = state.slack_client {
                let msg = if e == "not_linked" {
                    format!(
                        "⚠️ Your Slack account is not linked to dbward.\nRun: `dbward user link-slack {slack_user_id}`"
                    )
                } else {
                    "⚠️ Account suspended or not found".to_string()
                };
                if let Err(e) = slack_client
                    .post_ephemeral(&channel_id, &slack_user_id, &msg)
                    .await
                {
                    tracing::warn!(error = %e, "slack notification failed");
                }
            }
            return StatusCode::OK;
        }
    };

    // Check if request exists + user can view (delegates to GetRequest UC)
    let get_output = match state.requests().get().execute(&request_id, &auth_user) {
        Ok(output) => output,
        Err(dbward_app::error::AppError::Forbidden(_)) => {
            if let Some(ref slack_client) = state.slack_client
                && let Err(e) = slack_client
                    .post_ephemeral(
                        &channel_id,
                        &slack_user_id,
                        "⚠️ You are not authorized to view this request",
                    )
                    .await
            {
                tracing::warn!(error = %e, "slack notification failed");
            }
            return StatusCode::OK;
        }
        Err(_) => {
            if let Some(ref slack_client) = state.slack_client
                && let Err(e) = slack_client
                    .post_ephemeral(
                        &channel_id,
                        &slack_user_id,
                        "⚠️ Request not found or expired",
                    )
                    .await
            {
                tracing::warn!(error = %e, "slack notification failed");
            }
            return StatusCode::OK;
        }
    };
    let review_detail = get_output.detail;
    let review_context = get_output.context;

    // Open modal + hydrate async (return 200 immediately for Slack retry safety)
    let state_clone = state.clone();
    tokio::spawn(async move {
        let loading_view = dbward_infra::slack::block_kit::build_review_modal(
            &request_id,
            Some("Loading..."),
            None,
        );
        let view_id = if let Some(ref slack_client) = state_clone.slack_client {
            match slack_client.open_modal(&trigger_id, &loading_view).await {
                Ok(id) => id,
                Err(e) => {
                    tracing::warn!(error = %e, "failed to open modal");
                    return;
                }
            }
        } else {
            return;
        };
        let full_view = dbward_infra::slack::block_kit::build_review_modal(
            &request_id,
            Some(&review_detail),
            review_context.as_ref(),
        );
        if let Some(ref slack_client) = state_clone.slack_client
            && let Err(e) = slack_client.update_modal(&view_id, &full_view).await
        {
            tracing::warn!(error = %e, "failed to update modal");
        }
    });
    StatusCode::OK
}

/// Modal submit → extract decision + validate + execute UC.
async fn handle_view_submission(
    state: &AppState,
    _slack_config: &dbward_infra::slack::SlackConfig,
    payload: &serde_json::Value,
) -> Response {
    match payload["view"]["callback_id"].as_str() {
        Some("dbward_review_modal") => {}
        Some("dbward_create_modal") => return handle_create_submission(state, payload).await,
        Some("dbward_resume_modal") => return handle_resume_submission(state, payload).await,
        _ => return StatusCode::OK.into_response(),
    }

    let request_id = payload["view"]["private_metadata"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let slack_user_id = payload["user"]["id"].as_str().unwrap_or("");
    if request_id.is_empty() || slack_user_id.is_empty() {
        return StatusCode::OK.into_response();
    }

    let values = &payload["view"]["state"]["values"];

    // Decision radio
    let decision = values["decision_block"]["decision_input"]["selected_option"]["value"]
        .as_str()
        .unwrap_or("");
    if decision.is_empty() {
        return modal_error("decision_block", "Please select Approve or Reject");
    }

    // Comment
    let comment = values["comment_block"]["comment_input"]["value"]
        .as_str()
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string());

    if decision == "reject" && comment.is_none() {
        return modal_error("comment_block", "Comment is required for rejection");
    }

    // Resolve user with suspended check
    let auth_user = match resolve_slack_auth_user(state, slack_user_id).await {
        Ok(u) => u,
        Err(e) => {
            let msg = if e == "not_linked" {
                "Slack account not linked"
            } else if e == "suspended" {
                "Account suspended"
            } else {
                "Permission denied or account suspended"
            };
            return modal_error("decision_block", msg);
        }
    };

    let ctx = AuditContext::Request(dbward_domain::entities::ClientInfo {
        peer_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        client_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        source: dbward_domain::entities::IpSource::Direct,
    });

    let result = match decision {
        "approve" => {
            let uc = state.requests().approve();
            uc.execute(
                dbward_app::use_cases::approve_request::ApproveRequestInput {
                    request_id,
                    comment,
                },
                &auth_user,
                &ctx,
            )
            .map(|_| ())
        }
        "reject" => {
            let uc = state.requests().reject();
            uc.execute(
                dbward_app::use_cases::reject_request::RejectRequestInput {
                    request_id,
                    comment,
                },
                &auth_user,
                &ctx,
            )
            .map(|_| ())
        }
        _ => return modal_error("decision_block", "Invalid decision"),
    };

    match result {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => {
            let msg = match &e {
                dbward_app::error::AppError::Conflict(m) => m.as_str(),
                dbward_app::error::AppError::Gone(_) => "Request has expired",
                dbward_app::error::AppError::NotFound(_) => "Request not found",
                dbward_app::error::AppError::Forbidden(_) => {
                    "Not eligible to approve/reject this request"
                }
                _ => "An error occurred. Please try again.",
            };
            tracing::info!(error = %e, "slack review action failed");
            modal_error("decision_block", msg)
        }
    }
}

/// Slack Slash Command endpoint (`/dbward`).
/// No auth middleware — uses Slack signature verification.
pub async fn commands(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    if let Err(resp) = verify_slack_request(&state, &headers, &body) {
        return resp;
    }

    // Parse form-urlencoded payload
    let params: std::collections::HashMap<String, String> = form_urlencoded::parse(body.as_ref())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    let trigger_id = params.get("trigger_id").cloned().unwrap_or_default();
    let user_id = params.get("user_id").cloned().unwrap_or_default();
    let text = params.get("text").cloned().unwrap_or_default();

    if trigger_id.is_empty() {
        return ephemeral_response("⚠️ Unable to open form (missing trigger).");
    }

    // Subcommand routing
    let subcommand = text.split_whitespace().next().unwrap_or("");

    match subcommand {
        "execute" => { /* continue to open modal */ }
        "help" => {
            return ephemeral_response(
                "*Usage:*\n\
                 • `/dbward execute` — Submit SQL for approval\n\
                 • `/dbward help` — Show this message",
            );
        }
        _ => {
            return ephemeral_response("Unknown command. Try `/dbward help` for usage.");
        }
    }

    // Resolve auth user (in-memory SQLite, sub-ms)
    let auth_user = match resolve_slack_auth_user(&state, &user_id).await {
        Ok(u) => u,
        Err(e) => {
            let msg = if e == "not_linked" {
                format!(
                    "⚠️ Your Slack account is not linked to dbward.\nRun: `dbward user link-slack {user_id}`"
                )
            } else {
                "⚠️ Authentication failed. Please contact an administrator.".to_string()
            };
            return ephemeral_response(&msg);
        }
    };

    // Build modal with filtered DB/Env list (in-memory, sub-ms)
    let all = match state.database_registry().list_active() {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!(error = %e, "slack command: failed to list databases");
            return ephemeral_response("⚠️ Failed to load databases.");
        }
    };
    let accessible = state.authorizer.filter_accessible(&auth_user, &all);
    if accessible.is_empty() {
        return ephemeral_response("⚠️ No databases available for your account.");
    }

    let modal = dbward_infra::slack::block_kit::build_create_request_modal(&accessible, None);

    // Open modal
    let sc = match &state.slack_client {
        Some(c) => c,
        None => return ephemeral_response("⚠️ Slack integration not configured."),
    };
    if let Err(e) = sc.open_modal(&trigger_id, &modal).await {
        tracing::warn!(error = %e, "failed to open create request modal");
        return ephemeral_response("⚠️ Failed to open form. Please try again.");
    }

    // Empty 200 ACK — modal is already open via views.open
    StatusCode::OK.into_response()
}

/// Handle view_submission for "dbward_create_modal" → CreateRequest UC.
async fn handle_create_submission(state: &AppState, payload: &serde_json::Value) -> Response {
    use dbward_app::use_cases::create_request::{CreateRequestInput, RequestChannel};
    use dbward_domain::entities::{AuditContext, ClientInfo, IpSource};
    use dbward_domain::values::{DatabaseName, Environment, Operation};

    let slack_user_id = payload["user"]["id"].as_str().unwrap_or("");
    let values = &payload["view"]["state"]["values"];
    let view_id = payload["view"]["id"].as_str().unwrap_or("");

    let db_env = values["db_env_block"]["db_env_input"]["selected_option"]["value"].as_str();
    let sql = values["sql_block"]["sql_input"]["value"].as_str();
    let reason = values["reason_block"]["reason_input"]["value"]
        .as_str()
        .filter(|s| !s.trim().is_empty());

    if db_env.is_none() {
        return modal_error("db_env_block", "Database/Environment is required");
    }
    if sql.is_none() || sql.unwrap().trim().is_empty() {
        return modal_error("sql_block", "SQL is required");
    }

    let (db_str, env_str) = match db_env.unwrap().split_once('/') {
        Some((d, e)) => (d, e),
        None => return modal_error("db_env_block", "Invalid selection"),
    };

    let auth_user = match resolve_slack_auth_user(state, slack_user_id).await {
        Ok(u) => u,
        Err(e) => {
            let msg = match e.as_str() {
                "not_linked" => "Slack account not linked to dbward",
                "suspended" => "Account suspended",
                _ => "Authentication failed",
            };
            return modal_error("db_env_block", msg);
        }
    };

    let db = match DatabaseName::new(db_str) {
        Ok(d) => d,
        Err(_) => return modal_error("db_env_block", "Invalid database name"),
    };
    let env = match Environment::new(env_str) {
        Ok(e) => e,
        Err(_) => return modal_error("db_env_block", "Invalid environment"),
    };

    let input = CreateRequestInput {
        database: db,
        environment: env,
        operation: Operation::ExecuteSelect,
        detail: sql.unwrap().to_string(),
        reason: reason.map(|s| s.trim().to_string()),
        emergency: false,
        allow_ddl: false,
        idempotency_key: Some(format!("slack-{view_id}")),
        share_with: vec![],
        no_result_store: false,
        metadata_json: serde_json::json!({
            "source": "slack",
            "slack_user_id": slack_user_id,
        })
        .to_string(),
        channel: RequestChannel::Slack,
    };

    let audit_ctx = AuditContext::Request(ClientInfo {
        peer_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        client_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        source: IpSource::Direct,
    });

    let uc = state.requests().create();
    match uc.execute(input, &auth_user, &audit_ctx) {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => {
            let msg = match &e {
                dbward_app::error::AppError::Validation(m) => m.as_str(),
                dbward_app::error::AppError::Forbidden(_) => "Permission denied",
                dbward_app::error::AppError::NotFound(_) => "Database not found or not registered",
                dbward_app::error::AppError::Conflict(_) => "Duplicate request (already submitted)",
                dbward_app::error::AppError::PlanLimit(m) => m.as_str(),
                _ => "Request creation failed. Try again or use CLI.",
            };
            modal_error("sql_block", msg)
        }
    }
}

/// Handle view_submission for "dbward_resume_modal" → ResumeRequest UC.
async fn handle_resume_submission(state: &AppState, payload: &serde_json::Value) -> Response {
    let slack_user_id = payload["user"]["id"].as_str().unwrap_or("");
    let request_id = payload["view"]["private_metadata"]
        .as_str()
        .unwrap_or("")
        .to_string();

    if request_id.is_empty() {
        return StatusCode::OK.into_response();
    }

    let auth_user = match resolve_slack_auth_user(state, slack_user_id).await {
        Ok(u) => u,
        Err(e) => {
            let msg = match e.as_str() {
                "not_linked" => "Slack account not linked to dbward",
                "suspended" => "Account suspended",
                _ => "Authentication failed",
            };
            return modal_update_error(msg);
        }
    };

    let uc = state.requests().resume();
    let input = dbward_app::use_cases::resume_request::ResumeRequestInput {
        request_id: request_id.clone(),
    };
    let audit_ctx =
        dbward_domain::entities::AuditContext::Request(dbward_domain::entities::ClientInfo {
            peer_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            client_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            source: dbward_domain::entities::IpSource::Direct,
        });

    match uc.execute(input, &auth_user, &audit_ctx) {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => {
            let msg = match &e {
                dbward_app::error::AppError::Forbidden(_) => {
                    "You don't have permission to resume this request."
                }
                dbward_app::error::AppError::Conflict(m) => m.as_str(),
                dbward_app::error::AppError::NotFound(_) => "Request not found.",
                dbward_app::error::AppError::Gone(_) => "Request has expired.",
                _ => "Resume failed. Please try again or use the CLI.",
            };
            modal_update_error(msg)
        }
    }
}

/// Return an ephemeral Slack command response.
fn ephemeral_response(text: &str) -> Response {
    let body = serde_json::json!({
        "response_type": "ephemeral",
        "text": text
    });
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        body.to_string(),
    )
        .into_response()
}

/// Return a Slack view_submission error response (inline error on modal field).
fn modal_error(block_id: &str, message: &str) -> Response {
    let body = serde_json::json!({
        "response_action": "errors",
        "errors": {
            block_id: message
        }
    });
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        body.to_string(),
    )
        .into_response()
}

/// Replace modal content with an error message (for modals without input blocks).
fn modal_update_error(message: &str) -> Response {
    let body = serde_json::json!({
        "response_action": "update",
        "view": {
            "type": "modal",
            "title": {"type": "plain_text", "text": "Error"},
            "blocks": [{
                "type": "section",
                "text": {"type": "mrkdwn", "text": format!("❌ {message}")}
            }]
        }
    });
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        body.to_string(),
    )
        .into_response()
}

fn verify_signature(signing_secret: &str, timestamp: &str, body: &[u8], signature: &str) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    // Timestamp check (±5 minutes)
    let ts: i64 = timestamp.parse().unwrap_or(0);
    let now = chrono::Utc::now().timestamp();
    if (now - ts).abs() > 300 {
        return false;
    }

    // Slack signs: "v0:{timestamp}:{raw_body_bytes}"
    let mut mac = match Hmac::<Sha256>::new_from_slice(signing_secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(b"v0:");
    mac.update(timestamp.as_bytes());
    mac.update(b":");
    mac.update(body);
    let expected = format!("v0={}", hex::encode(mac.finalize().into_bytes()));

    // Constant-time comparison
    use subtle::ConstantTimeEq;
    expected.as_bytes().ct_eq(signature.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_signature_rejects_old_timestamp() {
        let old_ts = (chrono::Utc::now().timestamp() - 600).to_string();
        assert!(!verify_signature("secret", &old_ts, b"body", "v0=abc"));
    }

    #[test]
    fn verify_signature_rejects_invalid_signature() {
        let ts = chrono::Utc::now().timestamp().to_string();
        assert!(!verify_signature("secret", &ts, b"body", "v0=invalid"));
    }

    #[test]
    fn verify_signature_accepts_valid() {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let secret = "test_secret";
        let ts = chrono::Utc::now().timestamp().to_string();
        let body = b"payload=test";

        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(b"v0:");
        mac.update(ts.as_bytes());
        mac.update(b":");
        mac.update(body);
        let sig = format!("v0={}", hex::encode(mac.finalize().into_bytes()));

        assert!(verify_signature(secret, &ts, body, &sig));
    }
}
