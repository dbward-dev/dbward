// Copyright (c) 2026 dbward-dev.
// Licensed under the dbward Commercial License.
// Production use requires a valid Pro or Enterprise subscription.

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, Ordering};

use chrono::{DateTime, Utc};
use serde::Deserialize;

use dbward_app::ports::LicenseChecker;
use dbward_domain::license::{License, Plan, PlanLimits};

/// Pro plan limits (commercial-only constant).
const PRO: PlanLimits = PlanLimits {
    max_workflows: u32::MAX,
    max_databases: 20,
    max_webhooks: u32::MAX,
    max_users: 50,
    max_roles: u32::MAX,
};

const DEFAULT_GRACE_DAYS: u32 = 7;

// --- Online validation types ---

#[derive(Debug)]
pub enum OnlineValidationResult {
    Active { validated_until: DateTime<Utc> },
    Expired,
    Revoked { reason: String },
    Suspended,
    NetworkError,
    Offline,
}

#[derive(Deserialize)]
struct ValidateResponse {
    status: String,
    validated_until: Option<DateTime<Utc>>,
    #[serde(default)]
    grace_days: Option<u32>,
}

// --- LicenseCheckerImpl ---

pub struct LicenseCheckerImpl {
    license: License,
    expired: AtomicBool,
    validated_until: AtomicI64,
    grace_days: AtomicU32,
    grace_warned: AtomicBool,
    offline: bool,
    http_client: Option<reqwest::Client>,
    validate_url: String,
}

impl LicenseCheckerImpl {
    pub fn new(
        license: License,
        now: DateTime<Utc>,
        validated_until: Option<DateTime<Utc>>,
        offline: bool,
        validate_url: String,
    ) -> Self {
        let vt = validated_until.map(|t| t.timestamp()).unwrap_or(0);

        // Determine initial expired state:
        // If validated_until is within grace, ignore local expires_at
        let grace_days_i64 = DEFAULT_GRACE_DAYS as i64;
        let online_valid = vt != 0 && now.timestamp() <= vt + (grace_days_i64 * 86400);

        let expired = if online_valid {
            false
        } else {
            license.is_expired_at(now)
        };

        if expired {
            tracing::warn!(
                expires_at = ?license.expires_at,
                "License expired. Running with Free plan limits."
            );
        }

        let http_client = if offline {
            None
        } else {
            match reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
            {
                Ok(c) => Some(c),
                Err(e) => {
                    tracing::warn!(error = %e, "failed to build HTTP client for license validation, running offline");
                    None
                }
            }
        };

        // Relaxed ordering: each atomic field is independent. validated_until uses
        // CAS loop for monotonic increase; expired/grace_days/grace_warned are simple
        // flags/counters where eventual visibility is sufficient (checked every 1h).
        Self {
            license,
            expired: AtomicBool::new(expired),
            validated_until: AtomicI64::new(vt),
            grace_days: AtomicU32::new(DEFAULT_GRACE_DAYS),
            grace_warned: AtomicBool::new(false),
            offline,
            http_client,
            validate_url,
        }
    }

    /// Set grace_days (used to restore persisted value on startup).
    pub fn set_grace_days(&self, days: u32) {
        self.grace_days.store(days, Ordering::Relaxed);
    }

    /// Get current grace_days value.
    pub fn grace_days(&self) -> u32 {
        self.grace_days.load(Ordering::Relaxed)
    }

    /// Force-expire with reason. Returns true on first transition (for webhook firing).
    pub fn force_expire_with_reason(&self, reason: &str) -> bool {
        if self
            .expired
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            tracing::warn!(reason, "license force-expired");
            true
        } else {
            false
        }
    }

    /// Backward-compatible force_expire (no reason tracking).
    pub fn force_expire(&self) {
        self.force_expire_with_reason("unknown");
    }

    /// Restore active state when online validation returns active.
    fn restore_active(&self) {
        self.expired.store(false, Ordering::Relaxed);
        // Reset grace warning so it can fire again if needed later
        self.grace_warned.store(false, Ordering::Relaxed);
    }

    /// Record validated_until (monotonic increase only).
    fn record_validated_until(&self, server_ts: DateTime<Utc>) {
        let new_val = server_ts.timestamp();
        loop {
            let current = self.validated_until.load(Ordering::Relaxed);
            if new_val <= current {
                break;
            }
            if self
                .validated_until
                .compare_exchange_weak(current, new_val, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
    }

    /// Check if grace period has expired.
    pub fn is_grace_expired(&self, now: DateTime<Utc>) -> bool {
        let vt = self.validated_until.load(Ordering::Relaxed);
        if vt == 0 {
            return false; // must_validate_by handles this case
        }
        let gd = self.grace_days.load(Ordering::Relaxed) as i64;
        let deadline = vt + (gd * 86400);
        now.timestamp() > deadline
    }

    /// Check if first-validation deadline has passed.
    pub fn is_must_validate_expired(&self, now: DateTime<Utc>) -> bool {
        if self.offline {
            return false;
        }
        let vt = self.validated_until.load(Ordering::Relaxed);
        if vt != 0 {
            return false; // already validated at least once
        }
        let gd = self.grace_days.load(Ordering::Relaxed) as i64;
        match self.license.issued_at {
            Some(issued) => now > issued + chrono::Duration::days(gd),
            None => false, // Free plan (no issued_at) — skip
        }
    }

    /// Local expires_at check (extended: skips if online validation is within grace).
    pub fn check_expiry_at(&self, now: DateTime<Utc>) {
        let vt = self.validated_until.load(Ordering::Relaxed);
        if vt != 0 {
            let gd = self.grace_days.load(Ordering::Relaxed) as i64;
            let deadline = vt + (gd * 86400);
            if now.timestamp() <= deadline {
                return; // Online valid — skip local check
            }
        }
        if self.license.is_expired_at(now) {
            self.force_expire();
        }
    }

    /// Grace remaining seconds (for warning logic). Returns None if not in grace.
    pub fn grace_remaining_secs(&self, now: DateTime<Utc>) -> Option<i64> {
        let vt = self.validated_until.load(Ordering::Relaxed);
        if vt == 0 {
            return None;
        }
        let gd = self.grace_days.load(Ordering::Relaxed) as i64;
        let deadline = vt + (gd * 86400);
        let remaining = deadline - now.timestamp();
        if remaining > 0 { Some(remaining) } else { None }
    }

    /// Try to swap grace_warned flag. Returns true if this is the first warning.
    pub fn try_mark_grace_warned(&self) -> bool {
        !self.grace_warned.swap(true, Ordering::Relaxed)
    }

    /// Online validation against license.dbward.dev.
    pub async fn validate_online(&self, _now: DateTime<Utc>) -> OnlineValidationResult {
        if self.offline {
            return OnlineValidationResult::Offline;
        }
        if !self.validate_url.starts_with("https://") {
            tracing::warn!("license validation URL must use HTTPS, skipping online validation");
            return OnlineValidationResult::Offline;
        }
        let client = match &self.http_client {
            Some(c) => c,
            None => return OnlineValidationResult::Offline,
        };
        let key_id = match &self.license.key_id {
            Some(k) => k.as_str(),
            None => return OnlineValidationResult::Offline,
        };

        let resp = client
            .get(&self.validate_url)
            .bearer_auth(key_id)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await;

        match resp {
            Ok(r) if r.status().is_success() => match r.json::<ValidateResponse>().await {
                Ok(body) => match body.status.as_str() {
                    "active" => {
                        let vt = match body.validated_until {
                            Some(vt) => vt,
                            None => return OnlineValidationResult::NetworkError,
                        };
                        self.record_validated_until(vt);
                        if let Some(gd) = body.grace_days {
                            self.grace_days.store(gd, Ordering::Relaxed);
                        }
                        self.restore_active();
                        OnlineValidationResult::Active {
                            validated_until: vt,
                        }
                    }
                    "expired" => {
                        self.force_expire_with_reason("expired_online");
                        OnlineValidationResult::Expired
                    }
                    _ => {
                        self.force_expire_with_reason("revoked");
                        OnlineValidationResult::Revoked {
                            reason: body.status,
                        }
                    }
                },
                Err(_) => OnlineValidationResult::NetworkError,
            },
            Ok(r) if r.status().as_u16() == 403 => match r.json::<ValidateResponse>().await {
                Ok(body) if body.status == "suspended" => OnlineValidationResult::Suspended,
                _ => {
                    self.force_expire_with_reason("revoked");
                    OnlineValidationResult::Revoked {
                        reason: "revoked".into(),
                    }
                }
            },
            Ok(r) if r.status().as_u16() == 404 => {
                self.force_expire_with_reason("unknown_key");
                OnlineValidationResult::Revoked {
                    reason: "unknown_key".into(),
                }
            }
            _ => OnlineValidationResult::NetworkError,
        }
    }

    fn effective_limits(&self) -> Option<&'static PlanLimits> {
        if self.expired.load(Ordering::Relaxed) {
            Some(&PlanLimits::FREE)
        } else {
            match self.license.plan {
                Plan::Free => Some(&PlanLimits::FREE),
                Plan::Pro => Some(&PRO),
                Plan::Enterprise => None,
            }
        }
    }
}

impl LicenseChecker for LicenseCheckerImpl {
    fn max_databases(&self) -> u32 {
        self.effective_limits()
            .map_or(u32::MAX, |l| l.max_databases)
    }
    fn max_workflows(&self) -> u32 {
        self.effective_limits()
            .map_or(u32::MAX, |l| l.max_workflows)
    }
    fn max_webhooks(&self) -> u32 {
        self.effective_limits().map_or(u32::MAX, |l| l.max_webhooks)
    }
    fn max_users(&self) -> u32 {
        self.effective_limits().map_or(u32::MAX, |l| l.max_users)
    }
    fn max_roles(&self) -> u32 {
        self.effective_limits().map_or(u32::MAX, |l| l.max_roles)
    }
    fn is_enterprise(&self) -> bool {
        !self.expired.load(Ordering::Relaxed) && self.license.is_enterprise()
    }
    fn configured_plan(&self) -> &str {
        match self.license.plan {
            Plan::Free => "free",
            Plan::Pro => "pro",
            Plan::Enterprise => "enterprise",
        }
    }
    fn effective_plan(&self) -> &str {
        if self.expired.load(Ordering::Relaxed) {
            "free"
        } else {
            self.configured_plan()
        }
    }
    fn is_expired(&self) -> bool {
        self.expired.load(Ordering::Relaxed)
    }
    fn check_expiry(&self, now: DateTime<Utc>) {
        self.check_expiry_at(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn make_checker(
        license: License,
        validated_until: Option<DateTime<Utc>>,
    ) -> LicenseCheckerImpl {
        LicenseCheckerImpl::new(license, Utc::now(), validated_until, true, String::new())
    }

    #[test]
    fn valid_pro_license() {
        let future = Utc::now() + Duration::days(30);
        let lic = License {
            plan: Plan::Pro,
            key_id: None,
            issued_to: Some("test".into()),
            issued_at: None,
            expires_at: Some(future),
        };
        let checker = make_checker(lic, None);
        assert!(!checker.is_expired());
        assert_eq!(checker.configured_plan(), "pro");
        assert_eq!(checker.effective_plan(), "pro");
        assert_eq!(checker.max_databases(), 20);
        assert_eq!(checker.max_workflows(), u32::MAX);
        assert_eq!(checker.max_webhooks(), u32::MAX);
        assert_eq!(checker.max_users(), 50);
        assert_eq!(checker.max_roles(), u32::MAX);
        assert!(!checker.is_enterprise());
    }

    #[test]
    fn expired_pro_downgrades_to_free() {
        let past = Utc::now() - Duration::hours(1);
        let lic = License {
            plan: Plan::Pro,
            key_id: None,
            issued_to: Some("test".into()),
            issued_at: None,
            expires_at: Some(past),
        };
        let checker = make_checker(lic, None);
        assert!(checker.is_expired());
        assert_eq!(checker.configured_plan(), "pro");
        assert_eq!(checker.effective_plan(), "free");
        assert_eq!(checker.max_databases(), 3);
        assert!(!checker.is_enterprise());
    }

    #[test]
    fn runtime_expiry_detection() {
        let future = Utc::now() + Duration::hours(1);
        let lic = License {
            plan: Plan::Enterprise,
            key_id: None,
            issued_to: Some("test".into()),
            issued_at: None,
            expires_at: Some(future),
        };
        let checker = make_checker(lic, None);
        assert!(!checker.is_expired());
        assert!(checker.is_enterprise());
        assert_eq!(checker.max_databases(), u32::MAX);

        let after_expiry = future + Duration::seconds(1);
        checker.check_expiry_at(after_expiry);
        assert!(checker.is_expired());
        assert!(!checker.is_enterprise());
        assert_eq!(checker.max_databases(), 3);
        assert_eq!(checker.effective_plan(), "free");
    }

    #[test]
    fn check_expiry_logs_only_once() {
        let future = Utc::now() + Duration::hours(1);
        let lic = License {
            plan: Plan::Pro,
            key_id: None,
            issued_to: None,
            issued_at: None,
            expires_at: Some(future),
        };
        let checker = make_checker(lic, None);
        let after = future + Duration::seconds(1);
        checker.check_expiry_at(after);
        assert!(checker.is_expired());
        checker.check_expiry_at(after);
        assert!(checker.is_expired());
    }

    #[test]
    fn free_plan_never_expires() {
        let lic = License::default();
        let checker = make_checker(lic, None);
        assert!(!checker.is_expired());
        assert_eq!(checker.effective_plan(), "free");
        checker.check_expiry_at(Utc::now() + Duration::days(365));
        assert!(!checker.is_expired());
    }

    #[test]
    fn check_expiry_concurrent_only_flips_once() {
        let future = Utc::now() + Duration::hours(1);
        let lic = License {
            plan: Plan::Pro,
            key_id: None,
            issued_to: None,
            issued_at: None,
            expires_at: Some(future),
        };
        let checker = std::sync::Arc::new(make_checker(lic, None));
        let after = future + Duration::seconds(1);

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let c = checker.clone();
                std::thread::spawn(move || c.check_expiry_at(after))
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert!(checker.is_expired());
        assert_eq!(checker.effective_plan(), "free");
    }

    #[test]
    fn grace_expired_when_validated_until_plus_7d_passed() {
        let vt = Utc::now() - Duration::days(8);
        let lic = License {
            plan: Plan::Pro,
            key_id: None,
            issued_to: None,
            issued_at: None,
            expires_at: Some(Utc::now() + Duration::days(30)),
        };
        let checker = make_checker(lic, Some(vt));
        assert!(checker.is_grace_expired(Utc::now()));
    }

    #[test]
    fn grace_not_expired_within_7d() {
        let vt = Utc::now() - Duration::days(5);
        let lic = License {
            plan: Plan::Pro,
            key_id: None,
            issued_to: None,
            issued_at: None,
            expires_at: Some(Utc::now() + Duration::days(30)),
        };
        let checker = make_checker(lic, Some(vt));
        assert!(!checker.is_grace_expired(Utc::now()));
    }

    #[test]
    fn must_validate_expired_after_issued_at_plus_7d() {
        let issued = Utc::now() - Duration::days(8);
        let lic = License {
            plan: Plan::Pro,
            key_id: Some("k".into()),
            issued_to: None,
            issued_at: Some(issued),
            expires_at: Some(Utc::now() + Duration::days(30)),
        };
        // offline=false, validated_until=None
        let checker = LicenseCheckerImpl::new(lic, Utc::now(), None, false, String::new());
        assert!(checker.is_must_validate_expired(Utc::now()));
    }

    #[test]
    fn must_validate_not_expired_if_already_validated() {
        let issued = Utc::now() - Duration::days(8);
        let vt = Utc::now() - Duration::days(1);
        let lic = License {
            plan: Plan::Pro,
            key_id: Some("k".into()),
            issued_to: None,
            issued_at: Some(issued),
            expires_at: Some(Utc::now() + Duration::days(30)),
        };
        let checker = LicenseCheckerImpl::new(lic, Utc::now(), Some(vt), false, String::new());
        assert!(!checker.is_must_validate_expired(Utc::now()));
    }

    #[test]
    fn check_expiry_at_skips_when_online_valid() {
        // expires_at in the future at construction, but we check at a time after it
        // validated_until is recent → check_expiry_at should NOT expire
        let future = Utc::now() + Duration::hours(1);
        let vt = Utc::now();
        let lic = License {
            plan: Plan::Pro,
            key_id: None,
            issued_to: None,
            issued_at: None,
            expires_at: Some(future),
        };
        let checker = make_checker(lic, Some(vt));
        // Check at a time after expires_at
        let after = future + Duration::seconds(1);
        checker.check_expiry_at(after);
        // Should NOT be expired because validated_until + grace is still valid
        assert!(!checker.is_expired());
    }

    #[test]
    fn record_validated_until_monotonic_increase_only() {
        let lic = License::default();
        let checker = make_checker(lic, None);
        let t1 = Utc::now();
        let t2 = t1 + Duration::hours(1);
        checker.record_validated_until(t2);
        assert_eq!(
            checker.validated_until.load(Ordering::Relaxed),
            t2.timestamp()
        );
        // Older value should not overwrite
        checker.record_validated_until(t1);
        assert_eq!(
            checker.validated_until.load(Ordering::Relaxed),
            t2.timestamp()
        );
    }

    #[test]
    fn force_expire_with_reason_returns_true_only_once() {
        let future = Utc::now() + Duration::days(30);
        let lic = License {
            plan: Plan::Pro,
            key_id: None,
            issued_to: None,
            issued_at: None,
            expires_at: Some(future),
        };
        let checker = make_checker(lic, None);
        assert!(checker.force_expire_with_reason("test"));
        assert!(!checker.force_expire_with_reason("test"));
    }

    #[test]
    fn restore_active_resets_expired() {
        let future = Utc::now() + Duration::days(30);
        let lic = License {
            plan: Plan::Pro,
            key_id: None,
            issued_to: None,
            issued_at: None,
            expires_at: Some(future),
        };
        let checker = make_checker(lic, None);
        checker.force_expire();
        assert!(checker.is_expired());
        checker.restore_active();
        assert!(!checker.is_expired());
        assert_eq!(checker.effective_plan(), "pro");
    }
}
