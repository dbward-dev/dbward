use super::*;

pub(super) async fn dry_run_reclaim_loop(state: AppState, shutdown: CancellationToken) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = interval.tick() => {
                let cutoff = (state.background().clock().now() - chrono::Duration::seconds(60)).to_rfc3339();
                match state.background().dry_run_repo().reclaim_stale(&cutoff) {
                    Ok(n) if n > 0 => {
                        tracing::info!(task = "dry_run_reclaim", reclaimed = n, "reclaimed stale dry-run jobs");
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!(task = "dry_run_reclaim", error = %e, "reclaim_stale failed");
                    }
                }
            }
        }
    }
}
