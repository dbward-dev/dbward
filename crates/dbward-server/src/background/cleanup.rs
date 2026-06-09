use super::*;

pub(super) async fn record_purge_loop(
    state: AppState,
    shutdown: CancellationToken,
    retention: &RetentionConfig,
) {
    // Delay first execution by one interval
    let start = Instant::now() + RECORD_PURGE_INTERVAL;
    let mut ticker = interval_at(start, RECORD_PURGE_INTERVAL);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let r = run_record_purge_once(&state, retention).await;
                info!(task = "record_purge", processed = r.processed, failed = r.failed, "tick completed");
            }
            _ = shutdown.cancelled() => break,
        }
    }
}

pub(crate) async fn run_record_purge_once(
    state: &AppState,
    retention: &RetentionConfig,
) -> TickResult {
    let mut result = TickResult::default();
    let now = state.background().clock().now();
    let request_cutoff = (now - Duration::days(retention.request_ttl_days as i64)).to_rfc3339();
    let audit_cutoff = (now - Duration::days(retention.audit_ttl_days as i64)).to_rfc3339();

    // Revoked tokens
    match state
        .background()
        .token_repo()
        .purge_revoked(&request_cutoff)
    {
        Ok(n) => {
            if n > 0 {
                result.processed += n;
                info!(task = "record_purge", count = n, "purged revoked tokens");
            }
        }
        Err(e) => {
            result.failed += 1;
            error!(task = "record_purge", error = %e, "purge_revoked failed");
        }
    }

    // Old audit events
    match state.background().audit_repo().purge_old(&audit_cutoff) {
        Ok(n) => {
            if n > 0 {
                result.processed += n;
                info!(task = "record_purge", count = n, "purged old audit events");
                // A8: Record the purge action itself
                let _ = state
                    .background()
                    .audit_logger()
                    .record(&AuditEvent::simple(
                        "audit_purged",
                        "policy",
                        "system",
                        None,
                        state.background().clock().now(),
                        &AuditContext::System,
                    ));
            }
        }
        Err(e) => {
            result.failed += 1;
            error!(task = "record_purge", error = %e, "purge_old audit failed");
        }
    }

    // Old requests
    match state
        .background()
        .background_task_repo()
        .purge_old_requests(&request_cutoff)
    {
        Ok(n) => {
            if n > 0 {
                result.processed += n;
                info!(task = "record_purge", count = n, "purged old requests");
            }
        }
        Err(e) => {
            result.failed += 1;
            error!(task = "record_purge", error = %e, "purge_old_requests failed");
        }
    }

    // Expired results (storage delete → DB delete)
    let now_str = now.to_rfc3339();
    match state
        .background()
        .agent_repo()
        .find_expired_results(&now_str)
    {
        Ok(expired) => {
            for (result_id, storage_key) in expired {
                match state.background().result_store().delete(&storage_key).await {
                    Ok(()) => {
                        // Storage deleted successfully → safe to remove DB record
                        if let Err(e) = state.background().agent_repo().delete_result(&result_id) {
                            error!(task = "record_purge", result_id = %result_id, error = %e, "db delete failed after storage delete");
                            result.failed += 1;
                        } else {
                            result.processed += 1;
                        }
                    }
                    Err(e) => {
                        // Storage delete failed → keep DB record for retry next cycle
                        warn!(task = "record_purge", result_id = %result_id, error = %e, "storage delete failed, will retry");
                        result.failed += 1;
                    }
                }
            }
        }
        Err(e) => {
            result.failed += 1;
            error!(task = "record_purge", error = %e, "find_expired_results failed");
        }
    }

    result
}
