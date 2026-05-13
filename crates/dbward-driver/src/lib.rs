pub mod cancel_state;
pub mod error;
mod mysql;
mod postgres;

pub use cancel_state::CancelState;
pub use error::DriverError;
pub use mysql::MysqlDriver;
pub use postgres::PostgresDriver;

use std::sync::Arc;

pub const MAX_RESULT_ROWS: usize = 10_000;
pub const MAX_RESULT_BYTES: usize = 10 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct QueryOutput {
    pub rows: Vec<serde_json::Value>,
    pub truncated: bool,
    pub truncation_reason: Option<String>,
}

#[async_trait::async_trait]
pub trait DatabaseDriver: Send + Sync {
    async fn query(&self, sql: &str) -> Result<QueryOutput, DriverError>;
    async fn execute(&self, sql: &str) -> Result<u64, DriverError>;
    async fn apply_migration(&self, sql: &str, version: &str) -> Result<(), DriverError>;
    async fn revert_migration(&self, down_sql: &str, version: &str) -> Result<(), DriverError>;
    async fn ensure_migrations_table(&self) -> Result<(), DriverError>;
    async fn applied_versions(&self) -> Result<Vec<String>, DriverError>;

    /// Cancellable query: acquire connection → set timeout → set pid on cancel_state → execute.
    /// All on the same connection. Cancel state is shared with heartbeat task.
    async fn query_cancellable(
        &self,
        sql: &str,
        timeout_secs: u64,
        cancel: &CancelState,
    ) -> Result<QueryOutput, DriverError>;

    /// Cancellable execute: same guarantees as query_cancellable.
    async fn execute_cancellable(
        &self,
        sql: &str,
        timeout_secs: u64,
        cancel: &CancelState,
    ) -> Result<u64, DriverError>;
}

pub async fn connect(
    url: &str,
    statement_timeout_secs: Option<u64>,
) -> Result<Arc<dyn DatabaseDriver>, DriverError> {
    if url.starts_with("postgres://") || url.starts_with("postgresql://") {
        let driver = PostgresDriver::connect(url, statement_timeout_secs).await?;
        Ok(Arc::new(driver))
    } else if url.starts_with("mysql://") {
        let driver = MysqlDriver::connect(url, statement_timeout_secs).await?;
        Ok(Arc::new(driver))
    } else {
        Err(DriverError::UnsupportedScheme(url.to_string()))
    }
}

// Shared type conversion

#[derive(Debug, Clone, Copy)]
pub(crate) enum JsonMapping {
    Integer,
    Float,
    Bool,
    Json,
    Binary,
    Text,
}

pub(crate) fn text_to_json(text: &str, mapping: JsonMapping) -> serde_json::Value {
    match mapping {
        JsonMapping::Integer => text
            .parse::<i64>()
            .map(Into::into)
            .unwrap_or_else(|_| serde_json::Value::String(text.to_owned())),
        JsonMapping::Float => match text {
            "NaN" | "Infinity" | "-Infinity" => serde_json::Value::String(text.to_owned()),
            _ => text
                .parse::<f64>()
                .ok()
                .and_then(serde_json::Number::from_f64)
                .map(serde_json::Value::Number)
                .unwrap_or_else(|| serde_json::Value::String(text.to_owned())),
        },
        JsonMapping::Bool => serde_json::Value::Bool(text == "t" || text == "true" || text == "1"),
        JsonMapping::Json => {
            serde_json::from_str(text).unwrap_or(serde_json::Value::String(text.to_owned()))
        }
        JsonMapping::Binary => serde_json::Value::String("(binary data)".into()),
        JsonMapping::Text => serde_json::Value::String(text.to_owned()),
    }
}
