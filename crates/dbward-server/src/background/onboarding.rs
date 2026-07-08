use tokio::time::interval;
use tokio_util::sync::CancellationToken;

use crate::state::AppState;

use super::TTL_EXPIRY_INTERVAL;

/// Expire pending onboarding requests past their TTL (60s check interval).
pub(super) async fn onboarding_expiry_loop(state: AppState, shutdown: CancellationToken) {
    let mut ticker = interval(TTL_EXPIRY_INTERVAL);
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = ticker.tick() => {
                expire_pending_requests(&state).await;
            }
        }
    }
}

async fn expire_pending_requests(state: &AppState) {
    let now = chrono::Utc::now();

    let expired = match state.onboarding_repo().expire_pending(now) {
        Ok(data) => data,
        Err(e) => {
            tracing::error!(error = %e, "onboarding_expiry: failed to expire pending requests");
            return;
        }
    };

    if let Some(ref sc) = state.slack_client {
        let channel = state
            .slack_config
            .as_ref()
            .map(|s| s.default_channel.clone())
            .unwrap_or_default();

        for notification in expired {
            // DM the requester
            if let Err(e) = sc
                .post_message(
                    &notification.slack_user_id,
                    &[serde_json::json!({
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "⏰ Your dbward access request has expired. Please submit a new request with `/dbward join`."
                        }
                    })],
                    "Your dbward access request has expired.",
                )
                .await
            {
                tracing::warn!(error = %e, slack_user_id = %notification.slack_user_id, "onboarding_expiry: failed to DM expired user");
            }

            // Update approval channel message to show expired state
            if let Some(ts) = notification.message_ts
                && !channel.is_empty()
                && let Err(e) = sc
                    .update_message(
                        &channel,
                        &ts,
                        &[serde_json::json!({
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": format!("⏰ *Expired* — Request from <@{}> has expired.", notification.slack_user_id)
                            }
                        })],
                        &format!("Request from <@{}> expired.", notification.slack_user_id),
                    )
                    .await
            {
                tracing::warn!(error = %e, slack_user_id = %notification.slack_user_id, "onboarding_expiry: chat.update failed");
            }
        }
    }
}
