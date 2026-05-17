use std::sync::Arc;

use dbward_driver::{CancelState, DatabaseDriver};
use dbward_migrate::MigrationRunner;

use crate::AgentError;

use super::result::ExecutionResult;

/// Operation dispatch enum. Unknown operations are rejected (fail-closed).
#[derive(Debug)]
pub(crate) enum Operation {
    ExecuteSelect,
    ExecuteDml,
    MigrateUp,
    MigrateDown,
    MigrateStatus,
}

impl Operation {
    pub fn resolve(operation: &str) -> Result<Self, AgentError> {
        let domain_op: dbward_domain::values::Operation = operation
            .parse()
            .map_err(|_| AgentError::UnsupportedOperation(operation.to_owned()))?;
        Ok(match domain_op {
            dbward_domain::values::Operation::ExecuteSelect => Self::ExecuteSelect,
            dbward_domain::values::Operation::ExecuteDml => Self::ExecuteDml,
            dbward_domain::values::Operation::MigrateUp => Self::MigrateUp,
            dbward_domain::values::Operation::MigrateDown => Self::MigrateDown,
            dbward_domain::values::Operation::MigrateStatus => Self::MigrateStatus,
        })
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
                let r = MigrationRunner::run_up(driver.as_ref(), detail, cancel).await?;
                Ok(ExecutionResult::Migrate {
                    data: serde_json::json!({"applied": r.applied}).to_string(),
                })
            }
            Self::MigrateDown => {
                let r = MigrationRunner::run_down(driver.as_ref(), detail, cancel).await?;
                Ok(ExecutionResult::Migrate {
                    data: serde_json::json!({"reverted": r.reverted}).to_string(),
                })
            }
            Self::MigrateStatus => {
                let versions = MigrationRunner::status(driver.as_ref()).await?;
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
            Operation::resolve("query").unwrap(),
            Operation::ExecuteSelect
        ));
        assert!(matches!(
            Operation::resolve("execute_select").unwrap(),
            Operation::ExecuteSelect
        ));
        assert!(matches!(
            Operation::resolve("execute_query").unwrap(),
            Operation::ExecuteSelect
        ));
        assert!(matches!(
            Operation::resolve("execute").unwrap(),
            Operation::ExecuteSelect
        ));
        assert!(matches!(
            Operation::resolve("execute_dml").unwrap(),
            Operation::ExecuteDml
        ));
        assert!(matches!(
            Operation::resolve("migrate_up").unwrap(),
            Operation::MigrateUp
        ));
        assert!(matches!(
            Operation::resolve("migrate_down").unwrap(),
            Operation::MigrateDown
        ));
        assert!(matches!(
            Operation::resolve("migrate_status").unwrap(),
            Operation::MigrateStatus
        ));
    }

    #[test]
    fn resolve_unknown_returns_error() {
        let err = Operation::resolve("future_op").unwrap_err();
        assert!(err.to_string().contains("unsupported operation"));
        let err = Operation::resolve("").unwrap_err();
        assert!(err.to_string().contains("unsupported operation"));
    }
}
