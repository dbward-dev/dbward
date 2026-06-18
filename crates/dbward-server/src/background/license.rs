use super::*;

const LOCAL_CHECK_INTERVAL: TokioDuration = TokioDuration::from_secs(3600);

pub(super) async fn license_expiry_loop(state: AppState, shutdown: CancellationToken) {
    #[cfg(feature = "commercial")]
    {
        if let Some(checker) = state.background().license_checker_impl().cloned() {
            let host = ServerLicenseHost {
                state: state.clone(),
            };
            dbward_commercial_license::runtime::run(checker, host, shutdown).await;
            return;
        }
    }
    // Non-commercial or no license_checker_impl: legacy local-only loop
    legacy_license_loop(state, shutdown).await;
}

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

// --- ServerLicenseHost: thin adapter (no judgment logic) ---

#[cfg(feature = "commercial")]
struct ServerLicenseHost {
    state: AppState,
}

#[cfg(feature = "commercial")]
impl dbward_commercial_license::runtime::LicenseHost for ServerLicenseHost {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        self.state.background().clock().now()
    }

    fn persist_validated_until(&self, ts: chrono::DateTime<chrono::Utc>) -> Result<(), String> {
        self.state
            .background()
            .persist_validated_until(ts)
            .map_err(|e| e.to_string())
    }

    fn persist_grace_days(&self, days: u32) -> Result<(), String> {
        self.state
            .background()
            .persist_grace_days(days)
            .map_err(|e| e.to_string())
    }

    fn emit_event(&self, event: dbward_commercial_license::runtime::LicenseEvent) {
        use dbward_commercial_license::runtime::LicenseEvent;
        let (event_type, detail) = match &event {
            LicenseEvent::GraceWarning {
                remaining_days,
                validated_until,
            } => (
                "license_grace_warning",
                serde_json::json!({
                    "grace_remaining_days": remaining_days,
                    "validated_until": validated_until.to_rfc3339()
                })
                .to_string(),
            ),
            LicenseEvent::Downgraded { reason } => (
                "license_downgraded",
                serde_json::json!({ "reason": reason }).to_string(),
            ),
        };

        let bg = self.state.background();
        let webhook_event = dbward_app::ports::WebhookEvent {
            event_type: event_type.to_string(),
            request_id: None,
            database: None,
            environment: None,
            actor: Some("system".to_string()),
            detail: Some(detail.clone()),
            requester: None,
            reason: Some(detail.clone()),
            redacted_detail: Some(detail),
            error_summary: None,
            approval_hint: None,
            operation: None,
            step_index: None,
            total_steps: None,
            expires_at: None,
            approvers: None,
        };
        bg.notifier().dispatch(webhook_event);
    }

    fn metric_online_success(&self) {
        self.state
            .metrics
            .license_online_success
            .fetch_add(1, Ordering::Relaxed);
    }

    fn metric_online_failure(&self) {
        self.state
            .metrics
            .license_online_failure
            .fetch_add(1, Ordering::Relaxed);
    }

    fn metric_online_network_error(&self) {
        self.state
            .metrics
            .license_online_network_error
            .fetch_add(1, Ordering::Relaxed);
    }
}
