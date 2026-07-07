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
    let now = chrono::Utc::now().to_rfc3339();

    // (slack_user_id, message_ts) pairs of just-expired requests
    let expired: Vec<(String, Option<String>)> = {
        let conn = state.db_conn().lock();
        // Find and update expired pending requests
        if let Err(e) = conn.execute(
            "UPDATE onboarding_requests SET status = 'expired', decided_at = ?1 \
             WHERE status = 'pending' AND expires_at <= ?1",
            dbward_infra::rusqlite::params![now],
        ) {
            tracing::error!(error = %e, "onboarding_expiry: failed to expire pending requests");
            return;
        }

        // Get slack_user_ids + message_ts of just-expired requests
        match conn.prepare(
            "SELECT slack_user_id, message_ts FROM onboarding_requests \
             WHERE status = 'expired' AND decided_at = ?1",
        )
        .and_then(|mut stmt| {
            let rows = stmt.query_map(dbward_infra::rusqlite::params![now], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
            })?;
            Ok(rows.filter_map(|r| r.ok()).collect())
        }) {
            Ok(data) => data,
            Err(e) => {
                tracing::error!(error = %e, "onboarding_expiry: failed to query expired requests");
                return;
            }
        }
    };

    if let Some(ref sc) = state.slack_client {
        let channel = state
            .slack_config
            .as_ref()
            .map(|s| s.default_channel.clone())
            .unwrap_or_default();

        for (slack_user_id, message_ts) in expired {
            // DM the requester
            if let Err(e) = sc
                .post_message(
                    &slack_user_id,
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
                tracing::warn!(error = %e, %slack_user_id, "onboarding_expiry: failed to DM expired user");
            }

            // Update approval channel message to show expired state
            if let Some(ts) = message_ts
                && !channel.is_empty()
                && let Err(e) = sc
                    .update_message(
                        &channel,
                        &ts,
                        &[serde_json::json!({
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": format!("⏰ *Expired* — Request from <@{slack_user_id}> has expired.")
                            }
                        })],
                        &format!("Request from <@{slack_user_id}> expired."),
                    )
                    .await
            {
                tracing::warn!(error = %e, %slack_user_id, "onboarding_expiry: chat.update failed");
            }
        }
    }
}
