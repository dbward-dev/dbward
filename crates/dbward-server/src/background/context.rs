use super::*;

pub(super) async fn context_timeout_loop(state: AppState, shutdown: CancellationToken) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = interval.tick() => {
                let now = state.background().clock().now();
                let cutoff = (now - chrono::Duration::seconds(300)).to_rfc3339();
                let now_str = now.to_rfc3339();
                match state.background().context_repo().timeout_collecting(&cutoff, &now_str) {
                    Ok(n) if n > 0 => {
                        tracing::info!(task = "context_timeout", timed_out = n, "marked collecting contexts as unavailable");
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!(task = "context_timeout", error = %e, "timeout_collecting failed");
                    }
                }
            }
        }
    }
}
