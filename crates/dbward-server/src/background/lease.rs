use super::*;

pub(super) async fn lease_reclaim_loop(state: AppState, shutdown: CancellationToken) {
    let mut ticker = interval(LEASE_RECLAIM_INTERVAL);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let r = run_lease_reclaim_once(&state).await;
                if r.processed > 0 || r.failed > 0 {
                    info!(task = "lease_reclaim", processed = r.processed, failed = r.failed, "tick completed");
                }
            }
            _ = shutdown.cancelled() => break,
        }
    }
}

pub(crate) async fn run_lease_reclaim_once(state: &AppState) -> TickResult {
    let mut result = TickResult::default();
    let bg = state.background();
    let now_str = bg.clock().now().to_rfc3339();

    let expired = match bg.agent_repo().find_expired_leases(&now_str) {
        Ok(v) => v,
        Err(e) => {
            error!(task = "lease_reclaim", error = %e, "db query failed");
            result.failed += 1;
            return result;
        }
    };

    for (exec_id, req_id) in expired {
        let audit = make_audit_event("execution_lost", EventCategory::Agent, &req_id, state);
        match bg
            .agent_repo()
            .mark_execution_lost_and_record(&exec_id, &req_id, &audit, &now_str)
        {
            Ok(true) => {
                result.processed += 1;
                emit_webhook(state, "execution_lost", &req_id);
            }
            Ok(false) => {} // already processed
            Err(e) => {
                result.failed += 1;
                error!(task = "lease_reclaim", execution_id = %exec_id, error = %e, "failed to mark execution_lost");
            }
        }
    }
    result
}
