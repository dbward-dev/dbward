use serde::{Deserialize, Serialize};

use crate::values::{DatabaseName, Environment};

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
        }
    }
}
