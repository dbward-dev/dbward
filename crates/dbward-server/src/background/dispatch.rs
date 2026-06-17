use super::*;

pub(super) async fn dispatch_timeout_loop(state: AppState, shutdown: CancellationToken) {
    let mut ticker = interval(DISPATCH_TIMEOUT_INTERVAL);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let r = run_dispatch_timeout_once(&state).await;
                if r.processed > 0 || r.failed > 0 {
                    info!(task = "request.dispatch_timeout", processed = r.processed, failed = r.failed, "tick completed");
                }
            }
            _ = shutdown.cancelled() => break,
        }
    }
}

pub(crate) async fn run_dispatch_timeout_once(state: &AppState) -> TickResult {
    let mut result = TickResult::default();
    let bg = state.background();
    let now = bg.clock().now();
    let cutoff = (now - Duration::seconds(DISPATCH_TIMEOUT_SECS)).to_rfc3339();

    let ids = match bg
        .background_task_repo()
        .find_dispatched_older_than(&cutoff)
    {
        Ok(v) => v,
        Err(e) => {
            error!(task = "request.dispatch_timeout", error = %e, "db query failed");
            result.failed += 1;
            return result;
        }
    };

    for id in ids {
        let mut audit_event = AuditEvent::simple(
            "request.dispatch_timeout",
            "approval",
            "system",
            Some(&id),
            now,
            &AuditContext::System,
        );
        audit_event.request_id = Some(id.clone());
        let id_owned = id.clone();
        match bg.uow().execute(Box::new(move |tx| {
            // Revert dispatched → approved
            let updated = tx.mark_approved(&id_owned, now)?;
            if !updated {
                return Ok(()); // already transitioned, skip audit
            }
            tx.record(&audit_event)?;
            Ok(())
        })) {
            Ok(()) => {
                result.processed += 1;
            }
            Err(e) => {
                result.failed += 1;
                error!(task = "request.dispatch_timeout", request_id = %id, error = %e, "failed to revert to approved");
            }
        }
    }
    result
}
