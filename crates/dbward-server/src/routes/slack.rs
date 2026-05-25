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
    let subject_id = state
        .user_repo
        .find_by_slack_user_id(slack_user_id)
        .map_err(|e| format!("DB error: {e}"))?
        .ok_or_else(|| "not_linked".to_string())?;

    if state.user_repo.is_suspended(&subject_id).unwrap_or(true) {
        return Err("suspended".to_string());
    }

    let user = state
        .user_repo
        .get(&subject_id)
        .map_err(|e| format!("DB error: {e}"))?
        .ok_or_else(|| "user not found".to_string())?;

    let roles = state
        .role_resolver
        .resolve(&subject_id, SubjectType::User, &user.groups)
        .map_err(|e| format!("{e}"))?;

    Ok(AuthUser {
        subject_id,
        subject_type: SubjectType::User,
        roles,
        groups: user.groups,
        token_id: None,
    })
}

/// Slack interaction endpoint. Receives button clicks (approve/reject).
/// No auth middleware — uses Slack signature verification instead.
pub async fn interactions(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let slack_config = match &state.slack_config {
        Some(cfg) => cfg,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    // Signature verification
    let timestamp = headers
        .get("x-slack-request-timestamp")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let signature = headers
        .get("x-slack-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !verify_signature(&slack_config.signing_secret, timestamp, &body, signature) {
        tracing::warn!("slack signature verification failed");
        return StatusCode::UNAUTHORIZED.into_response();
    }

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

    if action_id != "dbward_review" || request_id.is_empty() || trigger_id.is_empty() {
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
                let _ = slack_client
                    .post_ephemeral(&channel_id, &slack_user_id, &msg)
                    .await;
            }
            return StatusCode::OK;
        }
    };

    // Check if request exists + user can approve
    let req = match state.request_reader.get(&request_id).ok().flatten() {
        Some(r) => r,
        None => {
            if let Some(ref slack_client) = state.slack_client {
                let _ = slack_client
                    .post_ephemeral(
                        &channel_id,
                        &slack_user_id,
                        "⚠️ Request not found or expired",
                    )
                    .await;
            }
            return StatusCode::OK;
        }
    };
    {
        use dbward_domain::auth::{Permission, ResourceContext};
        let can_view = state
            .authorizer
            .authorize_scoped(
                &auth_user,
                Permission::RequestApprove,
                &req.database,
                &req.environment,
                &ResourceContext::Global,
            )
            .is_ok()
            || req.requester == auth_user.subject_id;
        if !can_view {
            if let Some(ref slack_client) = state.slack_client {
                let _ = slack_client
                    .post_ephemeral(
                        &channel_id,
                        &slack_user_id,
                        "⚠️ You are not an approver for this request",
                    )
                    .await;
            }
            return StatusCode::OK;
        }
    }

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
        let sql = state_clone
            .request_reader
            .get(&request_id)
            .ok()
            .flatten()
            .map(|r| r.detail);
        let context = state_clone.context_repo.get(&request_id).ok().flatten();
        let full_view = dbward_infra::slack::block_kit::build_review_modal(
            &request_id,
            sql.as_deref(),
            context.as_ref(),
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
    if payload["view"]["callback_id"].as_str() != Some("dbward_review_modal") {
        return StatusCode::OK.into_response();
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
            let uc = dbward_app::use_cases::approve_request::ApproveRequest {
                authorizer: state.authorizer.clone(),
                request_reader: state.request_reader.clone(),
                approval_repo: state.approval_repo.clone(),
                event_dispatcher: state.event_dispatcher.clone(),
                clock: state.clock.clone(),
                id_gen: state.id_generator.clone(),
            };
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
            let uc = dbward_app::use_cases::reject_request::RejectRequest {
                authorizer: state.authorizer.clone(),
                request_reader: state.request_reader.clone(),
                approval_repo: state.approval_repo.clone(),
                event_dispatcher: state.event_dispatcher.clone(),
                clock: state.clock.clone(),
                id_gen: state.id_generator.clone(),
            };
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
