use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::values::{DatabaseName, Environment, Operation};

/// Controls re-execution limits and statement timeout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPolicy {
    pub id: String,
    pub database: DatabaseName,
    pub environment: Environment,
    pub max_executions: u32,
    pub execution_window_secs: u64,
    pub retry_on_failure: bool,
    pub statement_timeout_secs: u32,
    pub max_statement_timeout_secs: u32,
    #[serde(default)]
    pub max_rows: Option<u32>,
    /// Override lease duration for migration mutations (MigrateUp/Down).
    #[serde(default)]
    pub migration_lease_duration_secs: Option<u32>,
    #[serde(default)]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub updated_at: Option<DateTime<Utc>>,
}

impl Default for ExecutionPolicy {
    fn default() -> Self {
        Self {
            id: String::new(),
            database: DatabaseName::wildcard(),
            environment: Environment::wildcard(),
            max_executions: 1,
            execution_window_secs: 86400,
            retry_on_failure: false,
            statement_timeout_secs: 30,
            max_statement_timeout_secs: 600,
            max_rows: None,
            migration_lease_duration_secs: None,
            created_at: None,
            updated_at: None,
        }
    }
}

impl ExecutionPolicy {
    /// Compute lease duration: statement_timeout + buffer, capped by max_statement_timeout + buffer.
    /// Minimum 60s to avoid premature expiry on fast queries.
    pub fn lease_duration_secs(&self) -> i64 {
        const BUFFER: i64 = 30;
        let base = self.statement_timeout_secs as i64 + BUFFER;
        let cap = self.max_statement_timeout_secs as i64 + BUFFER;
        base.min(cap).max(60)
    }

    /// Lease duration that accounts for migration-specific override.
    pub fn lease_duration_for_operation(&self, operation: Operation) -> i64 {
        if operation.is_migration_mutation()
            && let Some(duration) = self.migration_lease_duration_secs
        {
            return duration as i64;
        }
        self.lease_duration_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::values::Operation;

    #[test]
    fn lease_duration_default_policy() {
        let p = ExecutionPolicy::default();
        // statement_timeout=30 + buffer=30 = 60, max(60) = 60
        assert_eq!(p.lease_duration_secs(), 60);
    }

    #[test]
    fn lease_duration_long_timeout() {
        let p = ExecutionPolicy {
            statement_timeout_secs: 300,
            max_statement_timeout_secs: 600,
            ..Default::default()
        };
        // 300 + 30 = 330, cap = 630, min(330,630) = 330, max(60) = 330
        assert_eq!(p.lease_duration_secs(), 330);
    }

    #[test]
    fn lease_duration_capped_by_max() {
        let p = ExecutionPolicy {
            statement_timeout_secs: 900,
            max_statement_timeout_secs: 600,
            ..Default::default()
        };
        // 900+30=930, cap=630, min(930,630)=630, max(60)=630
        assert_eq!(p.lease_duration_secs(), 630);
    }

    #[test]
    fn lease_duration_minimum_floor() {
        let p = ExecutionPolicy {
            statement_timeout_secs: 5,
            max_statement_timeout_secs: 10,
            ..Default::default()
        };
        // 5+30=35, cap=40, min(35,40)=35, max(60)=60
        assert_eq!(p.lease_duration_secs(), 60);
    }

    #[test]
    fn lease_duration_for_migration_mutation_with_override() {
        let p = ExecutionPolicy {
            migration_lease_duration_secs: Some(600),
            ..Default::default()
        };
        assert_eq!(p.lease_duration_for_operation(Operation::MigrateUp), 600);
        assert_eq!(p.lease_duration_for_operation(Operation::MigrateDown), 600);
    }

    #[test]
    fn lease_duration_for_migration_status_ignores_override() {
        let p = ExecutionPolicy {
            migration_lease_duration_secs: Some(600),
            ..Default::default()
        };
        // MigrateStatus is not a mutation — uses standard calculation
        assert_eq!(
            p.lease_duration_for_operation(Operation::MigrateStatus),
            p.lease_duration_secs()
        );
    }

    #[test]
    fn lease_duration_for_operation_without_override() {
        let p = ExecutionPolicy::default();
        assert_eq!(
            p.lease_duration_for_operation(Operation::MigrateUp),
            p.lease_duration_secs()
        );
    }
}
