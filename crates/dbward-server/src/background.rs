use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::Duration;
use tokio::time::{interval, Duration as TokioDuration};
use tracing::info;

use crate::state::AppState;

pub fn spawn_background_tasks(
    state: AppState,
    draining: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = interval(TokioDuration::from_secs(60));
        let mut purge_counter: u64 = 0;

        loop {
            tick.tick().await;
            if draining.load(Ordering::SeqCst) {
                break;
            }

            let now = state.clock.now();
            let now_str = now.to_rfc3339();

            // Lease reclaim
            if let Ok(expired) = state.agent_repo.find_expired_leases(&now_str) {
                for (exec_id, req_id) in expired {
                    if let Ok(true) = state.agent_repo.mark_execution_lost(&exec_id, &req_id, &now_str) {
                        info!(execution_id = %exec_id, request_id = %req_id, "lease expired, marked execution_lost");
                    }
                }
            }

            // Approval TTL expiry
            if let Ok(ids) = state.request_repo.find_expired_approved(&now_str) {
                for id in ids {
                    if let Ok(true) = state.request_repo.mark_expired(&id, &now_str) {
                        info!(request_id = %id, "approval TTL expired");
                    }
                }
            }

            // Pending TTL expiry
            if let Ok(ids) = state.request_repo.find_expired_pending(&now_str) {
                for id in ids {
                    if let Ok(true) = state.request_repo.mark_expired(&id, &now_str) {
                        info!(request_id = %id, "pending TTL expired");
                    }
                }
            }

            // Dispatch timeout (300s)
            if let Ok(ids) = state.request_repo.find_stale_dispatched(&now_str) {
                for id in ids {
                    if let Ok(true) = state.request_repo.mark_approved_from_dispatched(&id, &now_str) {
                        info!(request_id = %id, "dispatch timeout, reverted to approved");
                    }
                }
            }

            // Record purge (every 60 ticks = ~1 hour)
            purge_counter += 1;
            if purge_counter % 60 == 0 {
                let ninety_days_ago = (now - Duration::days(90)).to_rfc3339();
                let year_ago = (now - Duration::days(365)).to_rfc3339();

                if let Ok(n) = state.token_repo.purge_revoked(&ninety_days_ago) {
                    if n > 0 {
                        info!(count = n, "purged revoked tokens");
                    }
                }
                if let Ok(n) = state.audit_repo.purge_old(&year_ago) {
                    if n > 0 {
                        info!(count = n, "purged old audit events");
                    }
                }
                if let Ok(n) = state.request_repo.purge_old_requests(&ninety_days_ago) {
                    if n > 0 {
                        info!(count = n, "purged old requests");
                    }
                }

                // WAL checkpoint after purge
                if let Err(e) = state.request_repo.wal_checkpoint() {
                    tracing::warn!(error = %e, "WAL checkpoint failed");
                }

                // TODO: result store expiry (requires list/delete-expired on ResultStore)
            }
        }
    })
}
