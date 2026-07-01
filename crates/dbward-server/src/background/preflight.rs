use tokio_util::sync::CancellationToken;

use crate::state::AppState;

pub(super) async fn preflight_cleanup_loop(state: AppState, shutdown: CancellationToken) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = interval.tick() => {
                let repo = state.background().preflight_job_repo().clone();
                match tokio::task::spawn_blocking(move || repo.mark_expired()).await {
                    Ok(Ok(n)) if n > 0 => {
                        tracing::info!(task = "preflight_cleanup", expired = n, "marked expired");
                    }
                    Ok(Err(e)) => {
                        tracing::error!(task = "preflight_cleanup", %e, "mark_expired failed");
                    }
                    _ => {}
                }

                let repo = state.background().preflight_job_repo().clone();
                match tokio::task::spawn_blocking(move || repo.purge_old(300)).await {
                    Ok(Ok(n)) if n > 0 => {
                        tracing::info!(task = "preflight_cleanup", purged = n, "purged old");
                    }
                    Ok(Err(e)) => {
                        tracing::error!(task = "preflight_cleanup", %e, "purge_old failed");
                    }
                    _ => {}
                }
            }
        }
    }
}
