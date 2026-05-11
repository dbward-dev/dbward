use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Plan {
    Free,
    Pro,
}

/// Resource limits for the Free plan.
#[derive(Debug, Clone)]
pub struct PlanLimits {
    pub max_workflows: usize,
    pub max_agents: usize,
    pub max_databases: usize,
    pub max_webhooks: usize,
    pub max_execution_policies: usize,
    pub max_tokens: usize,
}

impl PlanLimits {
    pub const FREE: Self = Self {
        max_workflows: 5,
        max_agents: 3,
        max_databases: 3,
        max_webhooks: 3,
        max_execution_policies: 3,
        max_tokens: 10,
    };
}

#[derive(Debug, Clone)]
pub struct License {
    pub plan: Plan,
}

impl License {
    pub fn is_pro(&self) -> bool {
        self.plan == Plan::Pro
    }

    pub fn limits(&self) -> Option<&'static PlanLimits> {
        match self.plan {
            Plan::Free => Some(&PlanLimits::FREE),
            Plan::Pro => None,
        }
    }
}

impl Default for License {
    fn default() -> Self {
        Self { plan: Plan::Free }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_has_limits() {
        let lic = License::default();
        assert!(!lic.is_pro());
        let limits = lic.limits().unwrap();
        assert_eq!(limits.max_workflows, 5);
        assert_eq!(limits.max_tokens, 10);
    }

    #[test]
    fn pro_no_limits() {
        let lic = License { plan: Plan::Pro };
        assert!(lic.is_pro());
        assert!(lic.limits().is_none());
    }
}
