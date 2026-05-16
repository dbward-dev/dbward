use std::sync::Arc;

use dbward_driver::{CancelState, DatabaseDriver, DriverError};

use crate::AgentError;

use super::result::ExecutionResult;

/// Operation dispatch enum. DML fallback for unknown operations (forward-compatible).
pub(crate) enum Operation {
    ExecuteSelect,
    ExecuteDml,
    MigrateUp,
    MigrateDown,
    MigrateStatus,
}

impl Operation {
    pub fn resolve(operation: &str) -> Self {
        match operation {
            "query" | "execute_select" => Self::ExecuteSelect,
            "migrate_up" => Self::MigrateUp,
            "migrate_down" => Self::MigrateDown,
            "migrate_status" => Self::MigrateStatus,
            _ => Self::ExecuteDml,
        }
    }

    pub async fn execute(
        &self,
        driver: &Arc<dyn DatabaseDriver>,
        detail: &str,
        timeout_secs: u64,
        cancel: &CancelState,
        max_rows: Option<usize>,
    ) -> Result<ExecutionResult, AgentError> {
        match self {
            Self::ExecuteSelect => {
                let output = driver
                    .query_cancellable(detail, timeout_secs, cancel, max_rows)
                    .await?;
                let data = serde_json::to_string(&serde_json::json!({
                    "rows": output.rows,
                    "truncated": output.truncated,
                    "truncation_reason": output.truncation_reason,
                }))
                .unwrap();
                Ok(ExecutionResult::Query {
                    data,
                    truncated: output.truncated,
                })
            }
            Self::ExecuteDml => {
                let affected = driver
                    .execute_cancellable(detail, timeout_secs, cancel)
                    .await?;
                Ok(ExecutionResult::Execute {
                    rows_affected: affected,
                })
            }
            Self::MigrateUp => {
                let parsed = dbward_migrate::MigrationDetail::parse(detail)
                    .map_err(|e| AgentError::Driver(DriverError::QueryFailed(e.to_string())))?;
                driver.ensure_migrations_table().await?;
                let already = driver.applied_versions().await?;
                let pending: Vec<_> = parsed
                    .migrations
                    .iter()
                    .filter(|e| !already.contains(&e.version))
                    .take(parsed.max_count.unwrap_or(usize::MAX))
                    .collect();
                let mut applied = vec![];
                for entry in &pending {
                    if cancel.is_cancelled() {
                        return Err(AgentError::Driver(DriverError::Cancelled));
                    }
                    driver.apply_migration(&entry.sql, &entry.version).await?;
                    applied.push(&entry.version);
                }
                Ok(ExecutionResult::Migrate {
                    data: serde_json::json!({"applied": applied}).to_string(),
                })
            }
            Self::MigrateDown => {
                let parsed = dbward_migrate::MigrationDetail::parse(detail)
                    .map_err(|e| AgentError::Driver(DriverError::QueryFailed(e.to_string())))?;
                driver.ensure_migrations_table().await?;
                let already = driver.applied_versions().await?;
                let to_revert: Vec<_> = parsed
                    .migrations
                    .iter()
                    .rev()
                    .filter(|e| already.contains(&e.version))
                    .take(parsed.max_count.unwrap_or(usize::MAX))
                    .collect();
                let mut reverted = vec![];
                for entry in &to_revert {
                    if cancel.is_cancelled() {
                        return Err(AgentError::Driver(DriverError::Cancelled));
                    }
                    driver.revert_migration(&entry.sql, &entry.version).await?;
                    reverted.push(&entry.version);
                }
                Ok(ExecutionResult::Migrate {
                    data: serde_json::json!({"reverted": reverted}).to_string(),
                })
            }
            Self::MigrateStatus => {
                driver.ensure_migrations_table().await?;
                let versions = driver.applied_versions().await?;
                Ok(ExecutionResult::Migrate {
                    data: serde_json::json!({"applied_versions": versions}).to_string(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_known_operations() {
        assert!(matches!(
            Operation::resolve("query"),
            Operation::ExecuteSelect
        ));
        assert!(matches!(
            Operation::resolve("execute_select"),
            Operation::ExecuteSelect
        ));
        assert!(matches!(
            Operation::resolve("execute_dml"),
            Operation::ExecuteDml
        ));
        assert!(matches!(
            Operation::resolve("migrate_up"),
            Operation::MigrateUp
        ));
        assert!(matches!(
            Operation::resolve("migrate_down"),
            Operation::MigrateDown
        ));
        assert!(matches!(
            Operation::resolve("migrate_status"),
            Operation::MigrateStatus
        ));
    }

    #[test]
    fn resolve_unknown_falls_to_dml() {
        assert!(matches!(
            Operation::resolve("future_op"),
            Operation::ExecuteDml
        ));
        assert!(matches!(Operation::resolve(""), Operation::ExecuteDml));
    }
}
