use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::values::{DatabaseName, Environment};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    Active,
    Draining,
}

/// Derived status computed from base status + last_seen + load.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentDerivedStatus {
    Healthy,
    Offline,
    Saturated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseCapability {
    pub database: DatabaseName,
    pub environment: Environment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub id: String,
    pub token_id: String,
    pub databases: Vec<DatabaseCapability>,
    pub status: AgentStatus,
    pub max_concurrent: u32,
    pub in_flight: u32,
    pub last_seen: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl Agent {
    pub fn derived_status(&self, now: DateTime<Utc>) -> AgentDerivedStatus {
        if let Some(last) = self.last_seen {
            if now.signed_duration_since(last).num_seconds() > 60 {
                return AgentDerivedStatus::Offline;
            }
        } else {
            return AgentDerivedStatus::Offline;
        }
        if self.in_flight >= self.max_concurrent {
            return AgentDerivedStatus::Saturated;
        }
        AgentDerivedStatus::Healthy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn make_agent(status: AgentStatus, last_seen_secs_ago: Option<i64>, in_flight: u32) -> Agent {
        let now = Utc::now();
        Agent {
            id: "a1".into(),
            token_id: "t1".into(),
            databases: vec![],
            status,
            max_concurrent: 2,
            in_flight,
            last_seen: last_seen_secs_ago.map(|s| now - Duration::seconds(s)),
            created_at: now,
        }
    }

    #[test]
    fn healthy() {
        let a = make_agent(AgentStatus::Active, Some(10), 0);
        assert_eq!(a.derived_status(Utc::now()), AgentDerivedStatus::Healthy);
    }

    #[test]
    fn offline() {
        let a = make_agent(AgentStatus::Active, Some(120), 0);
        assert_eq!(a.derived_status(Utc::now()), AgentDerivedStatus::Offline);
    }

    #[test]
    fn saturated() {
        let a = make_agent(AgentStatus::Active, Some(5), 2);
        assert_eq!(a.derived_status(Utc::now()), AgentDerivedStatus::Saturated);
    }
}
