use super::*;

pub(super) async fn webhook_retry_loop(state: AppState, shutdown: CancellationToken) {
    let start = Instant::now() + WEBHOOK_RETRY_INTERVAL;
    let mut ticker = interval_at(start, WEBHOOK_RETRY_INTERVAL);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let r = run_webhook_retry_once(&state).await;
                if r.processed > 0 || r.failed > 0 {
                    info!(task = "webhook_retry", processed = r.processed, failed = r.failed, "tick completed");
                }
            }
            _ = shutdown.cancelled() => break,
        }
    }
}

pub(crate) async fn run_webhook_retry_once(state: &AppState) -> TickResult {
    let mut result = TickResult::default();
    let now = state.background().clock().now();

    // Reclaim stale in_progress deliveries (crashed workers)
    let stale_cutoff = (now - Duration::seconds(WEBHOOK_STALE_CLAIM_SECS)).to_rfc3339();
    if let Some(repo) = state.background().webhook_delivery_repo() {
        match repo.reclaim_stale(&stale_cutoff) {
            Ok(n) if n > 0 => info!(
                task = "webhook_retry",
                count = n,
                "reclaimed stale deliveries"
            ),
            Err(e) => error!(task = "webhook_retry", error = %e, "reclaim_stale failed"),
            _ => {}
        }

        // Claim retryable deliveries
        let now_str = now.to_rfc3339();
        match repo.claim_for_retry(&now_str, 5) {
            Ok(deliveries) => {
                for delivery in deliveries {
                    // Backstop: if webhook was deleted, cancel the delivery
                    let webhook = match state.background().webhook_repo() {
                        Some(r) => match r.get(&delivery.webhook_id) {
                            Ok(w) => w,
                            Err(e) => {
                                // DB error — retry later, don't cancel
                                let next = now + Duration::seconds(60);
                                let _ = repo.mark_failed(
                                    &delivery.id,
                                    &format!("webhook lookup error: {e}"),
                                    &next.to_rfc3339(),
                                    delivery.attempts,
                                );
                                result.failed += 1;
                                continue;
                            }
                        },
                        None => None,
                    };
                    let (url, secret) = match webhook {
                        Some(w) => (w.url, w.secret),
                        None => {
                            let _ = repo.mark_cancelled(&delivery.id);
                            info!(task = "webhook_retry", id = %delivery.id, webhook_id = %delivery.webhook_id, "webhook deleted, delivery cancelled");
                            result.processed += 1;
                            continue;
                        }
                    };

                    let send_result = state
                        .background()
                        .webhook_sender()
                        .send_one(
                            &url,
                            &delivery.payload,
                            secret.as_deref(),
                            Some(&delivery.event_type),
                        )
                        .await;
                    match send_result {
                        Ok(()) => {
                            if let Err(e) = repo.mark_delivered(&delivery.id, &now_str) {
                                error!(task = "webhook_retry", id = %delivery.id, error = %e, "failed to mark delivered");
                            }
                            result.processed += 1;
                        }
                        Err(e) => {
                            let attempts = delivery.attempts + 1;
                            if attempts >= delivery.max_attempts {
                                if let Err(e2) = repo.mark_dead(&delivery.id) {
                                    error!(task = "webhook_retry", id = %delivery.id, error = %e2, "failed to mark dead");
                                }
                                warn!(task = "webhook_retry", id = %delivery.id, "delivery marked dead");
                            } else {
                                let backoff = (attempts as i64).pow(2) * 60;
                                let next = now + Duration::seconds(backoff);
                                if let Err(e2) =
                                    repo.mark_failed(&delivery.id, &e, &next.to_rfc3339(), attempts)
                                {
                                    error!(task = "webhook_retry", id = %delivery.id, error = %e2, "failed to mark failed");
                                }
                            }
                            result.failed += 1;
                        }
                    }
                }
            }
            Err(e) => {
                error!(task = "webhook_retry", error = %e, "claim_for_retry failed");
                result.failed += 1;
            }
        }

        // Purge old delivered/dead entries (7 days)
        let purge_cutoff = (now - Duration::days(7)).to_rfc3339();
        match repo.purge_old(&purge_cutoff) {
            Ok(n) if n > 0 => info!(task = "webhook_retry", count = n, "purged old deliveries"),
            Err(e) => error!(task = "webhook_retry", error = %e, "purge_old failed"),
            _ => {}
        }
    }

    result
}
