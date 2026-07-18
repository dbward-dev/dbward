use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use dbward_domain::auth::{AuthUser, Permission, SubjectType};
use dbward_domain::entities::AuditContext;

use super::slack_messages as msg;
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

    let reloadable = state.reloadable.load();
    let roles = reloadable
        .role_resolver
        .resolve(&subject_id, SubjectType::User, &[])
        .map_err(|e| format!("{e}"))?;

    if roles.is_empty() {
        return Err("no_roles".to_string());
    }

    let groups = reloadable.role_resolver.groups_for_subject(&subject_id);

    let auth_user = AuthUser {
        subject_id,
        subject_type: SubjectType::User,
        roles,
        groups,
        token_id: None,
    };
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
    slack_config: &dbward_infra::slack::SlackConfig,
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
        && action_id != "dbward_onboarding_review"
    {
        return StatusCode::OK;
    }
    if request_id.is_empty() {
        return StatusCode::OK;
    }

    // Onboarding: open review modal
    if action_id == "dbward_onboarding_review" {
        let state_clone = state.clone();
        let slack_config_clone = slack_config.clone();
        let payload_clone = payload.clone();
        let request_id_clone = request_id.clone();
        tokio::spawn(async move {
            handle_onboarding_review_button(
                &state_clone,
                &slack_config_clone,
                &payload_clone,
                &request_id_clone,
            )
            .await;
        });
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
                            format!("⚠️ {}", msg::AUTH_FAILED)
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
                                &format!("⚠️ {}", msg::PERMISSION_DENIED_ACCESS),
                            )
                            .await;
                    }
                    return;
                }
                Err(dbward_app::error::AppError::NotFound(_)) => {
                    if let Some(ref sc) = state_clone.slack_client {
                        let _ = sc
                            .post_ephemeral(
                                &channel_id,
                                &slack_user_id,
                                &format!("⚠️ {}", msg::REQUEST_NOT_FOUND),
                            )
                            .await;
                    }
                    return;
                }
                Err(dbward_app::error::AppError::Gone(_)) => {
                    if let Some(ref sc) = state_clone.slack_client {
                        let _ = sc
                            .post_ephemeral(
                                &channel_id,
                                &slack_user_id,
                                &format!("⚠️ {}", msg::REQUEST_EXPIRED),
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
                                &format!("⚠️ {}", msg::GENERIC_ERROR),
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
                        &dbward_domain::auth::ResourceContext::RequestMutate {
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
                            &format!("⚠️ {}", msg::PERMISSION_DENIED_RESUME),
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
                                msg::AUTH_FAILED,
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
                            msg::PERMISSION_DENIED_VIEW_RESULT,
                        );
                        if let Err(e) = sc.update_modal(&view_id, &modal).await {
                            tracing::debug!(error = %e, "slack modal update failed");
                        }
                    }
                }
                Err(e) => {
                    if let Some(ref sc) = state_clone.slack_client {
                        let m = match &e {
                            dbward_app::error::AppError::NotFound(m) => m.as_str(),
                            dbward_app::error::AppError::Conflict(m) => m.as_str(),
                            dbward_app::error::AppError::Gone(m) => m.as_str(),
                            _ => msg::RESULT_LOAD_FAILED,
                        };
                        let modal = dbward_infra::slack::block_kit::build_result_modal_unavailable(
                            &request_id,
                            m,
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
                let m = if e == "not_linked" {
                    format!(
                        "⚠️ Your Slack account is not linked to dbward.\nRun: `dbward user link-slack {slack_user_id}`"
                    )
                } else {
                    format!("⚠️ {}", msg::AUTH_FAILED)
                };
                if let Err(e) = slack_client
                    .post_ephemeral(&channel_id, &slack_user_id, &m)
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
                        &format!("⚠️ {}", msg::PERMISSION_DENIED_VIEW),
                    )
                    .await
            {
                tracing::warn!(error = %e, "slack notification failed");
            }
            return StatusCode::OK;
        }
        Err(dbward_app::error::AppError::NotFound(_)) => {
            if let Some(ref slack_client) = state.slack_client
                && let Err(e) = slack_client
                    .post_ephemeral(
                        &channel_id,
                        &slack_user_id,
                        &format!("⚠️ {}", msg::REQUEST_NOT_FOUND),
                    )
                    .await
            {
                tracing::warn!(error = %e, "slack notification failed");
            }
            return StatusCode::OK;
        }
        Err(dbward_app::error::AppError::Gone(_)) => {
            if let Some(ref slack_client) = state.slack_client
                && let Err(e) = slack_client
                    .post_ephemeral(
                        &channel_id,
                        &slack_user_id,
                        &format!("⚠️ {}", msg::REQUEST_EXPIRED),
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
                        &format!("⚠️ {}", msg::GENERIC_ERROR),
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

    // Compute selector options for ambiguous users (unsatisfied groups only)
    let selector_options: Option<Vec<String>> = get_output
        .request
        .workflow_snapshot_json
        .as_deref()
        .and_then(|json| {
            let wf: dbward_domain::policies::Workflow = serde_json::from_str(json).ok()?;
            let current_step = get_output
                .approval_progress
                .as_ref()
                .map(|p| p.current_step)
                .unwrap_or(0);
            let step = wf.steps.get(current_step as usize)?;
            let role_names: Vec<String> = auth_user.roles.iter().map(|r| r.name.clone()).collect();
            let matched = dbward_domain::services::approval_checker::matched_selectors_by_attrs(
                &role_names,
                &auth_user.groups,
                &auth_user.subject_id,
                &step.approvers,
            );
            // Filter to unsatisfied selectors only
            let unsatisfied: Vec<String> = if let Some(progress) = &get_output.approval_progress
                && let Some(step_prog) = progress.steps.get(current_step as usize)
            {
                matched
                    .into_iter()
                    .filter(|sel| {
                        step_prog
                            .approvers_required
                            .iter()
                            .any(|r| r.selector.to_string() == *sel && r.current < r.min)
                    })
                    .collect()
            } else {
                matched
            };
            if unsatisfied.len() >= 2 {
                Some(unsatisfied)
            } else {
                None
            }
        });

    // Open modal + hydrate async (return 200 immediately for Slack retry safety)
    let state_clone = state.clone();
    tokio::spawn(async move {
        let loading_view = dbward_infra::slack::block_kit::build_review_modal(
            &request_id,
            Some("Loading..."),
            None,
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
            selector_options.as_deref(),
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
        Some("dbward_onboarding") => {
            return handle_onboarding_submission(state, _slack_config, payload).await;
        }
        Some("dbward_onboarding_review_submit") => {
            return handle_onboarding_review_submit(state, _slack_config, payload).await;
        }
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
        return modal_error("decision_block", msg::DECISION_REQUIRED);
    }

    // Comment
    let comment = values["comment_block"]["comment_input"]["value"]
        .as_str()
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string());

    // Selector (present only for ambiguous users)
    let selector = values
        .get("selector_block")
        .and_then(|b| b["selector_input"]["selected_option"]["value"].as_str())
        .map(|s| s.to_string());

    if decision == "reject" && comment.is_none() {
        return modal_error("comment_block", msg::COMMENT_REQUIRED);
    }

    // Resolve user with suspended check
    let auth_user = match resolve_slack_auth_user(state, slack_user_id).await {
        Ok(u) => u,
        Err(e) => {
            let m = match e.as_str() {
                "not_linked" => msg::ACCOUNT_NOT_LINKED,
                "suspended" => msg::ACCOUNT_SUSPENDED,
                _ => msg::AUTH_FAILED,
            };
            return modal_error("decision_block", m);
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
                    request_id: request_id.clone(),
                    comment: comment.clone(),
                    selector,
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
                    request_id: request_id.clone(),
                    comment: comment.clone(),
                },
                &auth_user,
                &ctx,
            )
            .map(|_| ())
        }
        _ => return modal_error("decision_block", msg::INVALID_DECISION),
    };

    match result {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => {
            let m = match &e {
                dbward_app::error::AppError::Conflict(m) => m.as_str(),
                dbward_app::error::AppError::Gone(_) => msg::REQUEST_EXPIRED,
                dbward_app::error::AppError::NotFound(_) => msg::REQUEST_NOT_FOUND,
                dbward_app::error::AppError::Forbidden(_) => msg::PERMISSION_DENIED_APPROVE,
                dbward_app::error::AppError::Validation(m) => m.as_str(),
                _ => msg::GENERIC_ERROR,
            };
            tracing::info!(error = %e, "slack review action failed");
            modal_error("decision_block", m)
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
        "join" => {
            return handle_join_command(&state, &trigger_id, &user_id).await;
        }
        "help" => {
            return ephemeral_response(
                "*Usage:*\n\
                 • `/dbward execute` — Submit SQL for approval\n\
                 • `/dbward join` — Request access to dbward\n\
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
            return ephemeral_response(&format!("⚠️ {}", msg::DB_LOAD_FAILED));
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
        return modal_error("db_env_block", msg::DB_ENV_REQUIRED);
    }
    if sql.is_none() || sql.unwrap().trim().is_empty() {
        return modal_error("sql_block", msg::SQL_REQUIRED);
    }

    let (db_str, env_str) = match db_env.unwrap().split_once('/') {
        Some((d, e)) => (d, e),
        None => return modal_error("db_env_block", msg::INVALID_SELECTION),
    };

    let auth_user = match resolve_slack_auth_user(state, slack_user_id).await {
        Ok(u) => u,
        Err(e) => {
            let m = match e.as_str() {
                "not_linked" => msg::ACCOUNT_NOT_LINKED,
                "suspended" => msg::ACCOUNT_SUSPENDED,
                _ => msg::AUTH_FAILED,
            };
            return modal_error("db_env_block", m);
        }
    };

    let db = match DatabaseName::new(db_str) {
        Ok(d) => d,
        Err(_) => return modal_error("db_env_block", msg::INVALID_DB_NAME),
    };
    let env = match Environment::new(env_str) {
        Ok(e) => e,
        Err(_) => return modal_error("db_env_block", msg::INVALID_ENVIRONMENT),
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
            let m = match &e {
                dbward_app::error::AppError::Validation(m) => m.as_str(),
                dbward_app::error::AppError::Forbidden(_) => msg::PERMISSION_DENIED_GENERIC,
                dbward_app::error::AppError::NotFound(_) => msg::DB_NOT_FOUND,
                dbward_app::error::AppError::Conflict(_) => msg::DUPLICATE_REQUEST,
                dbward_app::error::AppError::PlanLimit(m) => m.as_str(),
                _ => msg::CREATE_FAILED,
            };
            modal_error("sql_block", m)
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
            let m = match e.as_str() {
                "not_linked" => msg::ACCOUNT_NOT_LINKED,
                "suspended" => msg::ACCOUNT_SUSPENDED,
                _ => msg::AUTH_FAILED,
            };
            return modal_update_error(m);
        }
    };

    let uc = state.requests().resume();
    let input = dbward_app::use_cases::resume_request::ResumeRequestInput {
        request_id: request_id.clone(),
        reason: None,
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
            let m = match &e {
                dbward_app::error::AppError::Forbidden(_) => msg::PERMISSION_DENIED_RESUME,
                dbward_app::error::AppError::Conflict(m) => m.as_str(),
                dbward_app::error::AppError::NotFound(_) => msg::REQUEST_NOT_FOUND,
                dbward_app::error::AppError::Gone(_) => msg::REQUEST_EXPIRED,
                _ => msg::RESUME_FAILED,
            };
            modal_update_error(m)
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

// ─── Onboarding (/dbward join) ───────────────────────────────────────────

/// Handle `/dbward join` slash command — open onboarding modal.
async fn handle_join_command(state: &AppState, trigger_id: &str, slack_user_id: &str) -> Response {
    // Check if onboarding is configured
    let onboarding_cfg = match state.slack_onboarding.as_ref() {
        Some(cfg) if cfg.enabled => cfg.clone(),
        _ => return ephemeral_response("⚠️ Onboarding is not enabled on this server."),
    };

    // Check if user already exists
    let user_repo = state.user_repo();
    if let Ok(Some(existing_id)) = user_repo.find_by_slack_user_id(slack_user_id) {
        if user_repo.is_deleted(&existing_id).unwrap_or(false) {
            return ephemeral_response(
                "❌ Your account has been deleted. Contact an admin to create a new account.",
            );
        }
        if user_repo.is_suspended(&existing_id).unwrap_or(false) {
            return ephemeral_response(
                "⚠️ Your account is suspended. Contact an admin to reactivate it.",
            );
        }
        return ephemeral_response("✅ You already have a dbward account.");
    }

    // Check if there's a pending onboarding request
    let has_pending = match state.onboarding_repo().has_pending(slack_user_id) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "onboarding: failed to check pending status");
            // Fail-closed: reject the request if we can't verify pending status
            return ephemeral_response(
                "❌ Unable to process your request. Please try again later.",
            );
        }
    };
    if has_pending {
        return ephemeral_response("⏳ You already have a pending onboarding request.");
    }

    // Build modal
    let view = build_onboarding_modal(&onboarding_cfg, slack_user_id);
    if let Some(ref sc) = state.slack_client
        && sc.open_modal(trigger_id, &view).await.is_err()
    {
        return ephemeral_response("⚠️ Failed to open the form. Please try again.");
    }
    StatusCode::OK.into_response()
}

fn build_onboarding_modal(
    cfg: &dbward_config::server::SlackOnboardingConfig,
    slack_user_id: &str,
) -> serde_json::Value {
    let role_options: Vec<serde_json::Value> = cfg
        .assignable_roles
        .iter()
        .filter(|r| !cfg.restricted_roles.contains(r))
        .map(|r| {
            serde_json::json!({
                "text": { "type": "plain_text", "text": r },
                "value": r
            })
        })
        .collect();

    let group_options: Vec<serde_json::Value> = cfg
        .assignable_groups
        .iter()
        .map(|g| {
            serde_json::json!({
                "text": { "type": "plain_text", "text": g },
                "value": g
            })
        })
        .collect();

    let mut blocks = vec![];

    if !role_options.is_empty() {
        blocks.push(serde_json::json!({
            "type": "input",
            "block_id": "roles_block",
            "optional": true,
            "element": {
                "type": "multi_static_select",
                "action_id": "roles_select",
                "placeholder": { "type": "plain_text", "text": "Select roles" },
                "options": role_options
            },
            "label": { "type": "plain_text", "text": "Roles" }
        }));
    }

    if !group_options.is_empty() {
        blocks.push(serde_json::json!({
            "type": "input",
            "block_id": "groups_block",
            "optional": true,
            "element": {
                "type": "multi_static_select",
                "action_id": "groups_select",
                "placeholder": { "type": "plain_text", "text": "Select groups" },
                "options": group_options
            },
            "label": { "type": "plain_text", "text": "Groups" }
        }));
    }

    blocks.push(serde_json::json!({
        "type": "input",
        "block_id": "reason_block",
        "optional": true,
        "element": {
            "type": "plain_text_input",
            "action_id": "reason_input",
            "multiline": true,
            "placeholder": { "type": "plain_text", "text": "Why do you need access?" }
        },
        "label": { "type": "plain_text", "text": "Reason" }
    }));

    serde_json::json!({
        "type": "modal",
        "callback_id": "dbward_onboarding",
        "private_metadata": slack_user_id,
        "title": { "type": "plain_text", "text": "Join dbward" },
        "submit": { "type": "plain_text", "text": "Submit" },
        "close": { "type": "plain_text", "text": "Cancel" },
        "blocks": blocks
    })
}

/// Handle onboarding modal submission → create onboarding_request + notify approval channel.
async fn handle_onboarding_submission(
    state: &AppState,
    _slack_config: &dbward_infra::slack::SlackConfig,
    payload: &serde_json::Value,
) -> Response {
    let slack_user_id = payload["view"]["private_metadata"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let display_name = payload["user"]["name"].as_str().unwrap_or("").to_string();
    let values = &payload["view"]["state"]["values"];

    // Extract selected roles
    let roles: Vec<String> = values["roles_block"]["roles_select"]["selected_options"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v["value"].as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    // Extract selected groups
    let groups: Vec<String> = values["groups_block"]["groups_select"]["selected_options"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v["value"].as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let reason = values["reason_block"]["reason_input"]["value"]
        .as_str()
        .unwrap_or("")
        .to_string();

    // Insert onboarding_request
    let request_id = state.id_gen().generate();
    let now = chrono::Utc::now();
    let ttl_hours = state
        .slack_onboarding
        .as_ref()
        .map(|c| c.request_ttl_hours)
        .unwrap_or(72);
    let expires_at = now + chrono::Duration::hours(ttl_hours as i64);
    let insert_result = state
        .onboarding_repo()
        .create(&dbward_app::ports::CreateOnboardingInput {
            id: request_id.clone(),
            slack_user_id: slack_user_id.to_string(),
            display_name: Some(display_name.clone()),
            requested_roles: roles.clone(),
            requested_groups: groups.clone(),
            reason: if reason.is_empty() {
                None
            } else {
                Some(reason.clone())
            },
            created_at: now,
            expires_at,
        });
    if let Err(e) = insert_result {
        let err_msg = e.to_string();
        if err_msg.contains("UNIQUE") || err_msg.contains("unique") {
            return ephemeral_response("⏳ You already have a pending onboarding request.");
        }
        tracing::error!(error = %e, "failed to insert onboarding request");
        return ephemeral_response("❌ An error occurred. Please try again later.");
    }

    // Notify approval channel
    if let Some(ref sc) = state.slack_client {
        let channel = state
            .slack_config
            .as_ref()
            .map(|s| s.channel.clone())
            .unwrap_or_default();

        let reason_text = if reason.is_empty() {
            "_(no reason provided)_".to_string()
        } else {
            reason.clone()
        };

        let blocks = serde_json::json!([
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": format!(
                        "🆕 *Onboarding request* from <@{slack_user_id}>\n\
                         • Roles: {}\n\
                         • Groups: {}\n\
                         • Reason: {reason_text}",
                        if roles.is_empty() { "_(none)_".to_string() } else { roles.join(", ") },
                        if groups.is_empty() { "_(none)_".to_string() } else { groups.join(", ") },
                    )
                }
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": { "type": "plain_text", "text": "Review Request" },
                        "style": "primary",
                        "action_id": "dbward_onboarding_review",
                        "value": request_id
                    }
                ]
            }
        ]);

        match sc
            .post_message(
                &channel,
                blocks.as_array().unwrap(),
                &format!("Onboarding request from <@{slack_user_id}>"),
            )
            .await
        {
            Ok(ts) => {
                if let Err(e) = state.onboarding_repo().set_message_ts(&request_id, &ts) {
                    tracing::warn!(error = %e, "onboarding: failed to save message_ts");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "onboarding: failed to post approval channel message");
            }
        }
    }

    // Acknowledge modal submission (close it)
    StatusCode::OK.into_response()
}

/// Handle "Review Request" button click — open review modal.
async fn handle_onboarding_review_button(
    state: &AppState,
    _slack_config: &dbward_infra::slack::SlackConfig,
    payload: &serde_json::Value,
    request_id: &str,
) {
    let approver_slack_id = payload["user"]["id"].as_str().unwrap_or("").to_string();
    let channel_id = payload["channel"]["id"].as_str().unwrap_or("").to_string();
    let trigger_id = payload["trigger_id"].as_str().unwrap_or("");

    if trigger_id.is_empty() {
        return;
    }

    // Verify approver is admin
    let auth_user = match resolve_slack_auth_user(state, &approver_slack_id).await {
        Ok(u) => u,
        Err(_) => {
            if let Some(ref sc) = state.slack_client {
                let _ = sc
                    .post_ephemeral(
                        &channel_id,
                        &approver_slack_id,
                        "⚠️ You must be a linked dbward user to review requests.",
                    )
                    .await;
            }
            return;
        }
    };

    let is_admin = state
        .authorizer
        .authorize_global(&auth_user, Permission::UserWrite)
        .is_ok();
    if !is_admin {
        if let Some(ref sc) = state.slack_client {
            let _ = sc
                .post_ephemeral(
                    &channel_id,
                    &approver_slack_id,
                    "⚠️ Only admins can review onboarding requests.",
                )
                .await;
        }
        return;
    }

    // Load onboarding request
    let req_data = match state.onboarding_repo().get_pending(request_id) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, request_id = %request_id, "onboarding: failed to load request");
            None
        }
    };

    let (target_slack_id, display_name, roles, groups, reason) = match req_data {
        Some(req) => (
            req.slack_user_id,
            req.display_name.unwrap_or_default(),
            req.requested_roles,
            req.requested_groups,
            req.reason.unwrap_or_default(),
        ),
        None => {
            if let Some(ref sc) = state.slack_client {
                let _ = sc
                    .post_ephemeral(
                        &channel_id,
                        &approver_slack_id,
                        "⚠️ Request not found or already processed.",
                    )
                    .await;
            }
            return;
        }
    };

    // Build and open review modal
    let view = build_review_modal(
        state.slack_onboarding.as_ref(),
        request_id,
        &target_slack_id,
        &display_name,
        &roles,
        &groups,
        &reason,
    );
    if let Some(ref sc) = state.slack_client {
        let _ = sc.open_modal(trigger_id, &view).await;
    }
}

// ─── Onboarding Review Modal ─────────────────────────────────────────────

fn build_review_modal(
    onboarding_cfg: Option<&dbward_config::server::SlackOnboardingConfig>,
    request_id: &str,
    target_slack_id: &str,
    display_name: &str,
    initial_roles: &[String],
    initial_groups: &[String],
    reason: &str,
) -> serde_json::Value {
    let (assignable_roles, assignable_groups, restricted_roles) = match onboarding_cfg {
        Some(cfg) => (
            cfg.assignable_roles.clone(),
            cfg.assignable_groups.clone(),
            cfg.restricted_roles.clone(),
        ),
        None => (vec![], vec![], vec![]),
    };

    // Admin review modal: show ALL roles (assignable + restricted) for admin override
    let role_options: Vec<serde_json::Value> = assignable_roles
        .iter()
        .chain(restricted_roles.iter())
        .map(|r| serde_json::json!({"text": {"type": "plain_text", "text": r}, "value": r}))
        .collect();
    let group_options: Vec<serde_json::Value> = assignable_groups
        .iter()
        .map(|g| serde_json::json!({"text": {"type": "plain_text", "text": g}, "value": g}))
        .collect();

    let all_roles: Vec<String> = assignable_roles
        .iter()
        .chain(restricted_roles.iter())
        .cloned()
        .collect();
    let initial_role_options: Vec<serde_json::Value> = initial_roles
        .iter()
        .filter(|r| all_roles.contains(r))
        .map(|r| serde_json::json!({"text": {"type": "plain_text", "text": r}, "value": r}))
        .collect();
    let initial_group_options: Vec<serde_json::Value> = initial_groups
        .iter()
        .filter(|g| assignable_groups.contains(g))
        .map(|g| serde_json::json!({"text": {"type": "plain_text", "text": g}, "value": g}))
        .collect();

    let reason_display = if reason.is_empty() {
        "_(no reason provided)_"
    } else {
        reason
    };

    let mut blocks = vec![
        serde_json::json!({
            "type": "section",
            "text": {"type": "mrkdwn", "text": format!(
                "*Applicant:* <@{target_slack_id}> (`{display_name}`)\n*Requested Roles:* {}\n*Requested Groups:* {}\n*Reason:* {reason_display}",
                if initial_roles.is_empty() { "_(none)_".to_string() } else { initial_roles.join(", ") },
                if initial_groups.is_empty() { "_(none)_".to_string() } else { initial_groups.join(", ") },
            )}
        }),
        serde_json::json!({"type": "divider"}),
        serde_json::json!({
            "type": "input",
            "block_id": "decision_block",
            "element": {
                "type": "radio_buttons",
                "action_id": "decision_input",
                "options": [
                    {"text": {"type": "plain_text", "text": "Approve"}, "value": "approve"},
                    {"text": {"type": "plain_text", "text": "Reject"}, "value": "reject"}
                ]
            },
            "label": {"type": "plain_text", "text": "Decision"}
        }),
    ];

    if !role_options.is_empty() {
        let mut element = serde_json::json!({
            "type": "multi_static_select",
            "action_id": "roles_select",
            "placeholder": {"type": "plain_text", "text": "Select roles"},
            "options": role_options
        });
        if !initial_role_options.is_empty() {
            element["initial_options"] = serde_json::json!(initial_role_options);
        }
        blocks.push(serde_json::json!({
            "type": "input",
            "block_id": "roles_block",
            "optional": true,
            "element": element,
            "label": {"type": "plain_text", "text": "Roles (editable for Approve)"}
        }));
    }

    if !group_options.is_empty() {
        let mut element = serde_json::json!({
            "type": "multi_static_select",
            "action_id": "groups_select",
            "placeholder": {"type": "plain_text", "text": "Select groups"},
            "options": group_options
        });
        if !initial_group_options.is_empty() {
            element["initial_options"] = serde_json::json!(initial_group_options);
        }
        blocks.push(serde_json::json!({
            "type": "input",
            "block_id": "groups_block",
            "optional": true,
            "element": element,
            "label": {"type": "plain_text", "text": "Groups (editable for Approve)"}
        }));
    }

    blocks.push(serde_json::json!({
        "type": "input",
        "block_id": "comment_block",
        "optional": true,
        "element": {
            "type": "plain_text_input",
            "action_id": "comment_input",
            "multiline": true,
            "placeholder": {"type": "plain_text", "text": "Optional comment"}
        },
        "label": {"type": "plain_text", "text": "Comment"}
    }));

    serde_json::json!({
        "type": "modal",
        "callback_id": "dbward_onboarding_review_submit",
        "private_metadata": request_id,
        "title": {"type": "plain_text", "text": "Review Request"},
        "submit": {"type": "plain_text", "text": "Submit"},
        "close": {"type": "plain_text", "text": "Cancel"},
        "blocks": blocks
    })
}

/// Handle onboarding review modal submission (approve or reject).
async fn handle_onboarding_review_submit(
    state: &AppState,
    _slack_config: &dbward_infra::slack::SlackConfig,
    payload: &serde_json::Value,
) -> Response {
    let request_id = payload["view"]["private_metadata"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let approver_slack_id = payload["user"]["id"].as_str().unwrap_or("").to_string();
    let values = &payload["view"]["state"]["values"];

    let decision = values["decision_block"]["decision_input"]["selected_option"]["value"]
        .as_str()
        .unwrap_or("");

    let roles: Vec<String> = values["roles_block"]["roles_select"]["selected_options"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v["value"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let groups: Vec<String> = values["groups_block"]["groups_select"]["selected_options"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v["value"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let comment = values["comment_block"]["comment_input"]["value"]
        .as_str()
        .unwrap_or("")
        .to_string();

    // Verify admin
    let auth_user = match resolve_slack_auth_user(state, &approver_slack_id).await {
        Ok(u) => u,
        Err(_) => return StatusCode::OK.into_response(),
    };
    if state
        .authorizer
        .authorize_global(&auth_user, Permission::UserWrite)
        .is_err()
    {
        let err_response = serde_json::json!({
            "response_action": "errors",
            "errors": {
                "decision_block": "Only admins can approve or reject onboarding requests."
            }
        });
        return (StatusCode::OK, axum::Json(err_response)).into_response();
    }

    // Note: Role/group validation is handled by UserManage::add() (unknown role → Validation error).
    // Admin can assign any known role during approval, including restricted_roles.

    // Load onboarding request
    let req_data = match state.onboarding_repo().get_pending(&request_id) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, request_id = %request_id, "onboarding: failed to load request");
            None
        }
    };

    let (target_slack_id, display_name, message_ts) = match req_data {
        Some(req) => (
            req.slack_user_id,
            req.display_name.unwrap_or_default(),
            req.message_ts,
        ),
        None => return StatusCode::OK.into_response(),
    };

    let now = chrono::Utc::now();
    let channel_id = state
        .slack_config
        .as_ref()
        .map(|c| c.channel.clone())
        .unwrap_or_default();
    let comment_opt: Option<&str> = if comment.is_empty() {
        None
    } else {
        Some(&comment)
    };

    if decision == "approve" {
        // Create user with atomic onboarding claim (claim + user creation in same tx)
        let user_id = if display_name.is_empty() {
            format!("slack-{target_slack_id}")
        } else {
            // Slugify: lowercase, replace non-ASCII-alnum with hyphens, collapse, trim
            let slug: String = display_name
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '@' || c == '.' {
                        c
                    } else {
                        '-'
                    }
                })
                .collect::<String>()
                .to_ascii_lowercase();
            let slug = slug
                .split('-')
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join("-");
            if slug.is_empty() {
                format!("slack-{target_slack_id}")
            } else {
                slug
            }
        };

        let add_input = dbward_app::use_cases::user_manage::UserAddInput {
            id: user_id.clone(),
            roles: roles.clone(),
            groups: groups.clone(),
            slack_user_id: Some(target_slack_id.clone()),
            source: Some("slack".to_string()),
            onboarding_claim: Some(dbward_app::use_cases::user_manage::OnboardingClaimInput {
                request_id: request_id.to_string(),
                decided_by: auth_user.subject_id.clone(),
                decided_at: now,
                approved_roles: roles.clone(),
                approved_groups: groups.clone(),
                decision_comment: comment_opt.map(|s| s.to_string()),
            }),
        };

        let result = state.users().manage().add(
            add_input,
            &auth_user,
            &dbward_domain::entities::AuditContext::System,
        );

        match result {
            Ok(output) => {
                // DM token to user
                if let Some(ref sc) = state.slack_client {
                    let dm_text = format!(
                        "🎉 Your dbward access has been approved!\n\n\
                         Your API token (save it securely — it won't be shown again):\n\
                         ```{}```\n\n\
                         Configure it:\n\
                         ```export DBWARD_API_TOKEN={}```",
                        output.token, output.token
                    );
                    if let Err(e) = sc
                        .post_message(
                            &target_slack_id,
                            &[serde_json::json!({
                                "type": "section",
                                "text": { "type": "mrkdwn", "text": dm_text }
                            })],
                            "Your dbward access has been approved!",
                        )
                        .await
                    {
                        tracing::warn!(error = %e, "onboarding: DM delivery failed");
                        if let Some(ref sc2) = state.slack_client {
                            let _ = sc2.post_ephemeral(
                                &channel_id,
                                &approver_slack_id,
                                &format!("⚠️ DM delivery to <@{target_slack_id}> failed. Use `dbward user reissue-initial-token {user_id}` to retry."),
                            ).await;
                        }
                    }
                }

                // Update approval channel message
                if let (Some(sc), Some(ts)) = (state.slack_client.as_ref(), message_ts.as_ref()) {
                    let comment_line = comment_opt
                        .map(|c| format!("\n• Comment: {c}"))
                        .unwrap_or_default();
                    let updated_blocks = serde_json::json!([{
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": format!(
                                "✅ *Approved* — <@{target_slack_id}> → user `{user_id}`\n\
                                 • Roles: {}\n• Groups: {}\n• Approved by: <@{approver_slack_id}>{comment_line}",
                                if roles.is_empty() { "_(none)_".to_string() } else { roles.join(", ") },
                                if groups.is_empty() { "_(none)_".to_string() } else { groups.join(", ") },
                            )
                        }
                    }]);
                    if let Err(e) = sc
                        .update_message(
                            &channel_id,
                            ts,
                            updated_blocks.as_array().unwrap(),
                            &format!("Approved: {user_id}"),
                        )
                        .await
                    {
                        tracing::warn!(error = %e, "onboarding: chat.update failed");
                    }
                }
            }
            Err(dbward_app::error::AppError::Conflict(ref msg))
                if msg.contains("already processed") =>
            {
                // Idempotent: onboarding request already claimed — silent no-op
                tracing::info!("onboarding: duplicate approval (already processed)");
            }
            Err(e) => {
                tracing::error!(error = %e, "onboarding: user creation failed (tx rolled back atomically)");
                if let Some(ref sc) = state.slack_client {
                    let _ = sc
                        .post_ephemeral(
                            &channel_id,
                            &approver_slack_id,
                            &format!("⚠️ User creation failed: {e}. Please try again."),
                        )
                        .await;
                }
            }
        }
    } else {
        // Reject — claim with affected rows check
        let claimed = match state.onboarding_repo().claim_rejected(
            &request_id,
            &auth_user.subject_id,
            now,
            comment_opt,
        ) {
            Ok(result) => result.claimed,
            Err(e) => {
                tracing::error!(error = %e, "onboarding: claim update failed");
                false
            }
        };
        if !claimed {
            return StatusCode::OK.into_response();
        }

        // DM rejection
        if let Some(ref sc) = state.slack_client {
            let reject_msg = if comment.is_empty() {
                "❌ Your dbward access request was rejected. Contact an admin for details."
                    .to_string()
            } else {
                format!("❌ Your dbward access request was rejected.\n• Reason: {comment}")
            };
            let _ = sc
                .post_message(
                    &target_slack_id,
                    &[serde_json::json!({
                        "type": "section",
                        "text": { "type": "mrkdwn", "text": reject_msg }
                    })],
                    "Your dbward access request was rejected.",
                )
                .await;
        }

        // Update approval channel message
        if let (Some(sc), Some(ts)) = (state.slack_client.as_ref(), message_ts.as_ref()) {
            let comment_line = comment_opt
                .map(|c| format!("\n• Comment: {c}"))
                .unwrap_or_default();
            let updated_blocks = serde_json::json!([{
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": format!(
                        "❌ *Rejected* — <@{target_slack_id}>'s request\n• Rejected by: <@{approver_slack_id}>{comment_line}",
                    )
                }
            }]);
            if let Err(e) = sc
                .update_message(
                    &channel_id,
                    ts,
                    updated_blocks.as_array().unwrap(),
                    &format!("Rejected: <@{target_slack_id}>"),
                )
                .await
            {
                tracing::warn!(error = %e, "onboarding: chat.update failed");
            }
        }
    }

    StatusCode::OK.into_response()
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
