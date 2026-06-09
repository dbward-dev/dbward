use super::*;

const LICENSE_CHECK_INTERVAL: TokioDuration = TokioDuration::from_secs(3600);

pub(super) async fn license_expiry_loop(state: AppState, shutdown: CancellationToken) {
    let start = Instant::now() + LICENSE_CHECK_INTERVAL;
    let mut ticker = interval_at(start, LICENSE_CHECK_INTERVAL);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                state.background().license_checker().check_expiry(state.background().clock().now());
            }
            _ = shutdown.cancelled() => break,
        }
    }
}
