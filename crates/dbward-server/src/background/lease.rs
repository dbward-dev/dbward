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
    let now = bg.clock().now();
    let now_str = now.to_rfc3339();

    let expired = match bg.agent_repo().find_expired_leases(&now_str) {
        Ok(v) => v,
        Err(e) => {
            error!(task = "lease_reclaim", error = %e, "db query failed");
            result.failed += 1;
            return result;
        }
    };

    for (exec_id, req_id) in expired {
        let mut audit = make_audit_event("execution.lost", EventCategory::Agent, &req_id, state);
        audit.resource_id = Some(exec_id.clone());
        let exec_id_owned = exec_id.clone();
        let req_id_owned = req_id.clone();
        let should_notify = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let should_notify_tx = should_notify.clone();
        match bg.uow().execute(Box::new(move |tx| {
            // Mark execution as failed (lease expired)
            let exec_updated = tx.mark_failed_lease_expired(&exec_id_owned, now)?;
            if !exec_updated {
                return Ok(()); // already completed/cancelled, skip
            }
            // Revert request to execution_lost state
            let req_updated = tx.mark_execution_lost(&req_id_owned, now)?;
            if !req_updated {
                // Execution failed but request was already execution_lost (e.g. late-completion path).
                // Commit the execution update but suppress the webhook to avoid duplicate notification.
                return Ok(());
            }
            tx.record(&audit)?;
            should_notify_tx.store(true, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        })) {
            Ok(()) => {
                result.processed += 1;
                if should_notify.load(std::sync::atomic::Ordering::Relaxed) {
                    emit_webhook(state, "execution.lost", &req_id);
                }
            }
            Err(e) => {
                result.failed += 1;
                error!(task = "lease_reclaim", execution_id = %exec_id, error = %e, "failed to mark execution_lost");
            }
        }
    }
    result
}
