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
    let expired_users: Vec<String> = {
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

        // Get slack_user_ids of just-expired requests for DM notification
        match conn.prepare(
            "SELECT slack_user_id FROM onboarding_requests \
             WHERE status = 'expired' AND decided_at = ?1",
        )
        .and_then(|mut stmt| {
            let rows = stmt.query_map(dbward_infra::rusqlite::params![now], |r| {
                r.get::<_, String>(0)
            })?;
            Ok(rows.filter_map(|r| r.ok()).collect())
        }) {
            Ok(users) => users,
            Err(e) => {
                tracing::error!(error = %e, "onboarding_expiry: failed to query expired users");
                return;
            }
        }
    };

    // DM expired users
    if let Some(ref sc) = state.slack_client {
        for slack_user_id in expired_users {
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
        }
    }
}
