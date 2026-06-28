use chrono::{DateTime, Utc};

use dbward_app::ports::LicenseChecker;
use dbward_domain::license::PlanLimits;

/// Free plan checker — always returns Free plan limits.
/// Used when no commercial license feature is enabled.
pub struct FreePlanChecker;

impl LicenseChecker for FreePlanChecker {
    fn max_databases(&self) -> u32 {
        PlanLimits::FREE.max_databases
    }
    fn max_workflows(&self) -> u32 {
        PlanLimits::FREE.max_workflows
    }
    fn max_webhooks(&self) -> u32 {
        PlanLimits::FREE.max_webhooks
    }
    fn max_users(&self) -> u32 {
        PlanLimits::FREE.max_users
    }
    fn max_roles(&self) -> u32 {
        PlanLimits::FREE.max_roles
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
        assert_eq!(checker.max_workflows(), u32::MAX);
        assert_eq!(checker.max_webhooks(), u32::MAX);
        assert_eq!(checker.max_users(), 20);
        assert_eq!(checker.max_roles(), u32::MAX);
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
        // All getters unchanged after check_expiry
        assert!(!checker.is_expired());
        assert!(!checker.is_enterprise());
        assert_eq!(checker.configured_plan(), "free");
        assert_eq!(checker.effective_plan(), "free");
        assert_eq!(checker.max_databases(), 3);
        assert_eq!(checker.max_workflows(), u32::MAX);
        assert_eq!(checker.max_webhooks(), u32::MAX);
        assert_eq!(checker.max_users(), 20);
        assert_eq!(checker.max_roles(), u32::MAX);
    }
}
