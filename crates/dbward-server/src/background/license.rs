use super::*;

#[cfg(feature = "commercial")]
use dbward_app::ports::LicenseChecker as _;

const LOCAL_CHECK_INTERVAL: TokioDuration = TokioDuration::from_secs(3600); // 1h

#[cfg(feature = "commercial")]
const ONLINE_CHECK_INTERVAL: TokioDuration = TokioDuration::from_secs(86400); // 24h
#[cfg(feature = "commercial")]
const INITIAL_ONLINE_DELAY: u64 = 60;

pub(super) async fn license_expiry_loop(state: AppState, shutdown: CancellationToken) {
    #[cfg(feature = "commercial")]
    {
        commercial_license_loop(state, shutdown).await;
    }
    #[cfg(not(feature = "commercial"))]
    {
        legacy_license_loop(state, shutdown).await;
    }
}

#[cfg(not(feature = "commercial"))]
async fn legacy_license_loop(state: AppState, shutdown: CancellationToken) {
    let start = Instant::now() + LOCAL_CHECK_INTERVAL;
    let mut ticker = interval_at(start, LOCAL_CHECK_INTERVAL);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                state.background().license_checker().check_expiry(state.background().clock().now());
            }
            _ = shutdown.cancelled() => break,
        }
    }
}

#[cfg(feature = "commercial")]
async fn commercial_license_loop(state: AppState, shutdown: CancellationToken) {
    let jitter = rand::random::<u64>() % 3600;
    let online_start = Instant::now() + TokioDuration::from_secs(INITIAL_ONLINE_DELAY + jitter);
    let local_start = Instant::now() + LOCAL_CHECK_INTERVAL;

    let mut local_ticker = interval_at(local_start, LOCAL_CHECK_INTERVAL);
    let mut online_ticker = interval_at(online_start, ONLINE_CHECK_INTERVAL);

    loop {
        tokio::select! {
            _ = local_ticker.tick() => {
                state.background().license_checker().check_expiry(state.background().clock().now());

                if let Some(checker) = state.background().license_checker_impl() {
                    let now = state.background().clock().now();

                    if checker.is_grace_expired(now)
                        && checker.force_expire_with_reason("grace_expired")
                    {
                        emit_license_event(&state, "license_downgraded", "grace_expired");
                    }

                    if checker.is_must_validate_expired(now) {
                        warn!("license never validated online within grace period");
                        if checker.force_expire_with_reason("must_validate_expired") {
                            emit_license_event(&state, "license_downgraded", "must_validate_expired");
                        }
                    }

                    if let Some(remaining) = checker.grace_remaining_secs(now)
                        && remaining <= 3 * 86400
                        && checker.try_mark_grace_warned()
                    {
                        let days = std::cmp::max(1, remaining / 86400);
                        emit_license_event(&state, "license_grace_warning", &format!("{}d", days));
                    }
                }
            }
            _ = online_ticker.tick() => {
                if let Some(checker) = state.background().license_checker_impl() {
                    let now = state.background().clock().now();
                    let was_expired = checker.is_expired();
                    let result = checker.validate_online(now).await;
                    match &result {
                        dbward_commercial_license::OnlineValidationResult::Active { validated_until } => {
                            tracing::debug!("license online validation: active");
                            if let Err(e) = state.background().persist_validated_until(*validated_until) {
                                tracing::error!(error = %e, "failed to persist validated_until");
                            }
                            if let Err(e) = state.background().persist_grace_days(checker.grace_days()) {
                                tracing::error!(error = %e, "failed to persist grace_days");
                            }
                            state.metrics.license_online_success.fetch_add(1, Ordering::Relaxed);
                        }
                        dbward_commercial_license::OnlineValidationResult::Revoked { reason } => {
                            warn!(%reason, "license revoked by server");
                            if !was_expired {
                                emit_license_event(&state, "license_downgraded", reason);
                            }
                            state.metrics.license_online_failure.fetch_add(1, Ordering::Relaxed);
                        }
                        dbward_commercial_license::OnlineValidationResult::Expired => {
                            warn!("license expired (confirmed by server)");
                            if !was_expired {
                                emit_license_event(&state, "license_downgraded", "expired_online");
                            }
                            state.metrics.license_online_failure.fetch_add(1, Ordering::Relaxed);
                        }
                        dbward_commercial_license::OnlineValidationResult::Suspended => {
                            warn!("license suspended (payment issue). Grace period active.");
                            state.metrics.license_online_failure.fetch_add(1, Ordering::Relaxed);
                        }
                        dbward_commercial_license::OnlineValidationResult::NetworkError => {
                            info!("license online validation: network error");
                            state.metrics.license_online_network_error.fetch_add(1, Ordering::Relaxed);
                        }
                        dbward_commercial_license::OnlineValidationResult::Offline => {}
                    }
                }
            }
            _ = shutdown.cancelled() => break,
        }
    }
}

#[cfg(feature = "commercial")]
fn emit_license_event(state: &AppState, event_type: &str, detail: &str) {
    let bg = state.background();
    let event = dbward_app::ports::WebhookEvent {
        event_type: event_type.to_string(),
        request_id: None,
        database: None,
        environment: None,
        actor: Some("system".to_string()),
        detail: Some(detail.to_string()),
        requester: None,
        reason: Some(detail.to_string()),
        redacted_detail: Some(detail.to_string()),
        error_summary: None,
        approval_hint: None,
        operation: None,
        step_index: None,
        total_steps: None,
        expires_at: None,
        approvers: None,
    };
    bg.notifier().dispatch(event.clone());
    if let Some(rn) = bg.request_notifier() {
        rn.dispatch(event);
    }
}
