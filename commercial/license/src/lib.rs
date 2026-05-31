// Copyright (c) 2026 dbward-dev.
// Licensed under the dbward Commercial License.
// Production use requires a valid Pro or Enterprise subscription.

use std::sync::atomic::{AtomicBool, Ordering};

use chrono::{DateTime, Utc};

use dbward_app::ports::LicenseChecker;
use dbward_domain::license::{License, Plan, PlanLimits};

pub struct LicenseCheckerImpl {
    license: License,
    expired: AtomicBool,
}

impl LicenseCheckerImpl {
    pub fn new(license: License, now: DateTime<Utc>) -> Self {
        let expired = license.is_expired_at(now);
        if expired {
            tracing::warn!(
                expires_at = ?license.expires_at,
                "License expired. Running with Free plan limits."
            );
        }
        Self {
            license,
            expired: AtomicBool::new(expired),
        }
    }

    pub fn check_expiry_at(&self, now: DateTime<Utc>) {
        if self.license.is_expired_at(now)
            && self
                .expired
                .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            tracing::warn!("License expired. Effective plan downgraded to Free.");
        }
    }

    fn effective_limits(&self) -> Option<&'static PlanLimits> {
        if self.expired.load(Ordering::Relaxed) {
            Some(&PlanLimits::FREE)
        } else {
            self.license.limits()
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
    fn max_tokens(&self) -> u32 {
        self.effective_limits().map_or(u32::MAX, |l| l.max_tokens)
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

    #[test]
    fn valid_pro_license() {
        let future = Utc::now() + Duration::days(30);
        let lic = License {
            plan: Plan::Pro,
            issued_to: Some("test".into()),
            expires_at: Some(future),
        };
        let checker = LicenseCheckerImpl::new(lic, Utc::now());
        assert!(!checker.is_expired());
        assert_eq!(checker.configured_plan(), "pro");
        assert_eq!(checker.effective_plan(), "pro");
        assert_eq!(checker.max_databases(), 10);
    }

    #[test]
    fn expired_pro_downgrades_to_free() {
        let past = Utc::now() - Duration::hours(1);
        let lic = License {
            plan: Plan::Pro,
            issued_to: Some("test".into()),
            expires_at: Some(past),
        };
        let checker = LicenseCheckerImpl::new(lic, Utc::now());
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
            issued_to: Some("test".into()),
            expires_at: Some(future),
        };
        let checker = LicenseCheckerImpl::new(lic, Utc::now());
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
            issued_to: None,
            expires_at: Some(future),
        };
        let checker = LicenseCheckerImpl::new(lic, Utc::now());
        let after = future + Duration::seconds(1);
        checker.check_expiry_at(after);
        assert!(checker.is_expired());
        checker.check_expiry_at(after);
        assert!(checker.is_expired());
    }

    #[test]
    fn free_plan_never_expires() {
        let lic = License::default();
        let checker = LicenseCheckerImpl::new(lic, Utc::now());
        assert!(!checker.is_expired());
        assert_eq!(checker.effective_plan(), "free");
        checker.check_expiry_at(Utc::now() + Duration::days(365));
        assert!(!checker.is_expired());
    }
}
