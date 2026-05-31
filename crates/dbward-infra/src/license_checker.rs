use chrono::{DateTime, Utc};

use dbward_app::ports::LicenseChecker;

/// Free plan checker — always returns Free plan limits.
/// Used when no commercial license feature is enabled.
pub struct FreePlanChecker;

impl LicenseChecker for FreePlanChecker {
    fn max_databases(&self) -> u32 {
        3
    }
    fn max_workflows(&self) -> u32 {
        5
    }
    fn max_webhooks(&self) -> u32 {
        3
    }
    fn max_tokens(&self) -> u32 {
        10
    }
    fn max_roles(&self) -> u32 {
        8
    }
    fn is_enterprise(&self) -> bool {
        false
    }
    fn configured_plan(&self) -> &str {
        "free"
    }
    fn effective_plan(&self) -> &str {
        "free"
    }
    fn is_expired(&self) -> bool {
        false
    }
    fn check_expiry(&self, _now: DateTime<Utc>) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_plan_limits() {
        let checker = FreePlanChecker;
        assert_eq!(checker.max_databases(), 3);
        assert_eq!(checker.max_workflows(), 5);
        assert_eq!(checker.max_webhooks(), 3);
        assert_eq!(checker.max_tokens(), 10);
        assert_eq!(checker.max_roles(), 8);
    }

    #[test]
    fn free_plan_metadata() {
        let checker = FreePlanChecker;
        assert!(!checker.is_enterprise());
        assert!(!checker.is_expired());
        assert_eq!(checker.configured_plan(), "free");
        assert_eq!(checker.effective_plan(), "free");
    }

    #[test]
    fn check_expiry_is_noop() {
        let checker = FreePlanChecker;
        checker.check_expiry(Utc::now());
        assert!(!checker.is_expired());
    }
}
