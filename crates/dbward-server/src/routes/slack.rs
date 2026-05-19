use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};

use dbward_domain::auth::SubjectType;
use dbward_domain::entities::AuditContext;

use crate::state::AppState;

/// Slack interaction endpoint. Receives button clicks (approve/reject).
/// No auth middleware — uses Slack signature verification instead.
pub async fn interactions(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let slack_config = match &state.slack_config {
        Some(cfg) => cfg,
        None => return StatusCode::NOT_FOUND,
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
        return StatusCode::UNAUTHORIZED;
    }

    // Parse payload (form-encoded: payload=<json>)
    let payload_str = form_urlencoded::parse(body.as_ref())
        .find(|(key, _)| key == "payload")
        .map(|(_, value)| value.into_owned())
        .unwrap_or_default();

    let payload: serde_json::Value = match serde_json::from_str(&payload_str) {
        Ok(v) => v,
        Err(_) => return StatusCode::BAD_REQUEST,
    };

    let action = match payload["actions"].as_array().and_then(|a| a.first()) {
        Some(a) => a,
        None => return StatusCode::OK,
    };

    let action_id = action["action_id"].as_str().unwrap_or("");
    let request_id = action["value"].as_str().unwrap_or("").to_string();
    let slack_user_id = payload["user"]["id"].as_str().unwrap_or("").to_string();

    if request_id.is_empty() || slack_user_id.is_empty() {
        return StatusCode::OK;
    }

    // Resolve Slack user → dbward subject
    let dbward_subject = match slack_config.resolve_subject(&slack_user_id) {
        Some(s) => s.to_string(),
        None => {
            tracing::info!(slack_user_id, "unmapped slack user attempted action");
            return StatusCode::OK;
        }
    };

    // Resolve AuthUser via RoleResolver (includes suspension check)
    let auth_user = match state
        .role_resolver
        .resolve(&dbward_subject, SubjectType::User, &[])
    {
        Ok(roles) => dbward_domain::auth::AuthUser {
            subject_id: dbward_subject.clone(),
            subject_type: SubjectType::User,
            roles,
            groups: vec![],
            token_id: None,
        },
        Err(e) => {
            tracing::warn!(error = %e, dbward_subject, "failed to resolve roles for slack action");
            return StatusCode::OK;
        }
    };

    let action_id = action_id.to_string();
    let state_clone = state.clone();

    // Process async (Slack expects <3s response)
    tokio::spawn(async move {
        let ctx = AuditContext::Request(dbward_domain::entities::ClientInfo {
            peer_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            client_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            source: dbward_domain::entities::IpSource::Direct,
        });
        let result = match action_id.as_str() {
            "dbward_approve" => {
                let uc = dbward_app::use_cases::approve_request::ApproveRequest {
                    authorizer: state_clone.authorizer.clone(),
                    request_reader: state_clone.request_reader.clone(),
                    approval_repo: state_clone.approval_repo.clone(),
                    event_dispatcher: state_clone.event_dispatcher.clone(),
                    clock: state_clone.clock.clone(),
                    id_gen: state_clone.id_generator.clone(),
                };
                uc.execute(
                    dbward_app::use_cases::approve_request::ApproveRequestInput {
                        request_id,
                        comment: Some("Approved via Slack".into()),
                    },
                    &auth_user,
                    &ctx,
                )
                .map(|_| ())
            }
            "dbward_reject" => {
                let uc = dbward_app::use_cases::reject_request::RejectRequest {
                    authorizer: state_clone.authorizer.clone(),
                    request_reader: state_clone.request_reader.clone(),
                    approval_repo: state_clone.approval_repo.clone(),
                    event_dispatcher: state_clone.event_dispatcher.clone(),
                    clock: state_clone.clock.clone(),
                    id_gen: state_clone.id_generator.clone(),
                };
                uc.execute(
                    dbward_app::use_cases::reject_request::RejectRequestInput {
                        request_id,
                        comment: Some("Rejected via Slack".into()),
                    },
                    &auth_user,
                    &ctx,
                )
                .map(|_| ())
            }
            _ => return,
        };

        if let Err(e) = result {
            tracing::info!(error = %e, "slack action failed (expected for permission/conflict errors)");
        }
    });

    StatusCode::OK
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
