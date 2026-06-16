// Copyright (c) 2026 dbward-dev.
// Licensed under the dbward Commercial License.
// Production use requires a valid Pro or Enterprise subscription.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use tokio::time::{Duration, Instant, interval_at};
use tokio_util::sync::CancellationToken;

use crate::{LicenseCheckerImpl, OnlineValidationResult};
use dbward_app::ports::LicenseChecker as _;

const LOCAL_CHECK_INTERVAL: Duration = Duration::from_secs(3600); // 1h
const DEFAULT_ONLINE_CHECK_INTERVAL: Duration = Duration::from_secs(86400); // 24h
const INITIAL_ONLINE_DELAY: u64 = 60;

/// Events emitted by the license runtime. OSS adapter converts to webhook payloads.
#[derive(Debug, Clone)]
pub enum LicenseEvent {
    GraceWarning {
        remaining_days: u32,
        validated_until: DateTime<Utc>,
    },
    Downgraded {
        reason: String,
    },
}

/// Thin adapter trait implemented by the OSS server layer.
/// Contains no judgment logic — only data plumbing.
pub trait LicenseHost: Send + Sync + 'static {
    fn now(&self) -> DateTime<Utc>;
    fn persist_validated_until(&self, ts: DateTime<Utc>) -> bool;
    fn persist_grace_days(&self, days: u32) -> bool;
    fn emit_event(&self, event: LicenseEvent);
    fn metric_online_success(&self);
    fn metric_online_failure(&self);
    fn metric_online_network_error(&self);
}

/// License enforcement runtime. All scheduling, judgment, and notification
/// logic lives here (under Commercial License).
pub async fn run(
    checker: Arc<LicenseCheckerImpl>,
    host: impl LicenseHost,
    shutdown: CancellationToken,
) {
    let jitter: u64 = std::env::var("DBWARD_LICENSE_JITTER_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| rand::random::<u64>() % 3600);
    let online_interval = std::env::var("DBWARD_LICENSE_ONLINE_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_ONLINE_CHECK_INTERVAL);

    let online_start = Instant::now() + Duration::from_secs(INITIAL_ONLINE_DELAY + jitter);
    let local_start = Instant::now() + LOCAL_CHECK_INTERVAL;

    let mut local_ticker = interval_at(local_start, LOCAL_CHECK_INTERVAL);
    let mut online_ticker = interval_at(online_start, online_interval);

    loop {
        tokio::select! {
            _ = local_ticker.tick() => {
                let now = host.now();

                // Local expires_at check (with reason)
                if checker.is_local_expiry_effective(now)
                    && checker.force_expire_with_reason("local_expires_at")
                {
                    host.emit_event(LicenseEvent::Downgraded {
                        reason: "local_expires_at".into(),
                    });
                }

                // Grace period expired
                if checker.is_grace_expired(now)
                    && checker.force_expire_with_reason("grace_expired")
                {
                    host.emit_event(LicenseEvent::Downgraded {
                        reason: "grace_expired".into(),
                    });
                }

                // Must-validate deadline
                if checker.is_must_validate_expired(now)
                    && checker.force_expire_with_reason("must_validate_expired")
                {
                    host.emit_event(LicenseEvent::Downgraded {
                        reason: "must_validate_expired".into(),
                    });
                }

                // Grace warning (<=3 days remaining)
                if let Some(remaining) = checker.grace_remaining_secs(now)
                    && remaining <= 3 * 86400
                    && checker.try_mark_grace_warned()
                {
                    host.emit_event(LicenseEvent::GraceWarning {
                        remaining_days: std::cmp::max(1, (remaining / 86400) as u32),
                        validated_until: checker.validated_until_datetime().unwrap_or(now),
                    });
                }
            }
            _ = online_ticker.tick() => {
                let now = host.now();
                let was_expired = checker.is_expired();
                let result = checker.validate_online(now).await;
                match &result {
                    OnlineValidationResult::Active { validated_until } => {
                        if !host.persist_validated_until(*validated_until) {
                            tracing::error!("failed to persist validated_until");
                        }
                        if !host.persist_grace_days(checker.grace_days()) {
                            tracing::error!("failed to persist grace_days");
                        }
                        host.metric_online_success();
                    }
                    OnlineValidationResult::Revoked { reason } => {
                        if !was_expired {
                            host.emit_event(LicenseEvent::Downgraded {
                                reason: reason.clone(),
                            });
                        }
                        host.metric_online_failure();
                    }
                    OnlineValidationResult::Expired => {
                        if !was_expired {
                            host.emit_event(LicenseEvent::Downgraded {
                                reason: "expired_online".into(),
                            });
                        }
                        host.metric_online_failure();
                    }
                    OnlineValidationResult::Suspended => {
                        host.metric_online_failure();
                    }
                    OnlineValidationResult::NetworkError => {
                        host.metric_online_network_error();
                    }
                    OnlineValidationResult::Offline => {}
                }
            }
            _ = shutdown.cancelled() => break,
        }
    }
}
