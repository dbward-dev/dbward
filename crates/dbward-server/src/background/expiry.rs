use super::*;

pub(super) async fn ttl_expiry_loop(state: AppState, shutdown: CancellationToken) {
    let mut ticker = interval(TTL_EXPIRY_INTERVAL);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let r = run_ttl_expiry_once(&state).await;
                if r.processed > 0 || r.failed > 0 {
                    info!(task = "ttl_expiry", processed = r.processed, failed = r.failed, "tick completed");
                }
            }
            _ = shutdown.cancelled() => break,
        }
    }
}

pub(crate) async fn run_ttl_expiry_once(state: &AppState) -> TickResult {
    let mut result = TickResult::default();
    let bg = state.background();
    let now_str = bg.clock().now().to_rfc3339();

    // Approval TTL
    match bg.background_task_repo().find_expired_approved(&now_str) {
        Ok(ids) => {
            for id in ids {
                let audit =
                    make_audit_event("request_expired", EventCategory::Approval, &id, state);
                match bg
                    .background_task_repo()
                    .mark_expired_and_record(&id, &audit, &now_str)
                {
                    Ok(true) => {
                        result.processed += 1;
                        emit_webhook(state, "request_expired", &id);
                    }
                    Ok(false) => {}
                    Err(e) => {
                        result.failed += 1;
                        error!(task = "ttl_expiry", request_id = %id, error = %e, "failed to expire approved request");
                    }
                }
            }
        }
        Err(e) => {
            error!(task = "ttl_expiry", error = %e, "find_expired_approved failed");
            result.failed += 1;
        }
    }

    // Pending TTL
    match bg.background_task_repo().find_expired_pending(&now_str) {
        Ok(ids) => {
            for id in ids {
                let audit =
                    make_audit_event("request_expired", EventCategory::Approval, &id, state);
                match bg
                    .background_task_repo()
                    .mark_expired_and_record(&id, &audit, &now_str)
                {
                    Ok(true) => {
                        result.processed += 1;
                        emit_webhook(state, "request_expired", &id);
                    }
                    Ok(false) => {}
                    Err(e) => {
                        result.failed += 1;
                        error!(task = "ttl_expiry", request_id = %id, error = %e, "failed to expire pending request");
                    }
                }
            }
        }
        Err(e) => {
            error!(task = "ttl_expiry", error = %e, "find_expired_pending failed");
            result.failed += 1;
        }
    }

    result
}
