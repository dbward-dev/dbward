use crate::DriverError;

/// Classify a sqlx connection error by checking for authentication failure codes.
pub(crate) fn classify_connect_error(e: sqlx::Error, auth_codes: &[&str]) -> DriverError {
    if let sqlx::Error::Database(ref db_err) = e
        && let Some(code) = db_err.code()
        && auth_codes.iter().any(|c| code.as_ref() == *c)
    {
        return DriverError::AuthenticationFailed(e.to_string());
    }
    DriverError::ConnectionFailed(e.to_string())
}

/// Validate a migration version string for safe interpolation into comments.
pub(crate) fn validate_migration_version(version: &str) -> Result<(), DriverError> {
    const FORBIDDEN: &[char] = &['\'', ';', '\\', '\n', '\r', '\0'];
    if version.contains(FORBIDDEN) {
        return Err(DriverError::QueryFailed("invalid migration version".into()));
    }
    Ok(())
}

/// Convert sqlx query errors to DriverError::QueryFailed.
/// The statement_timeout branch is a placeholder for future Timeout variant promotion.
pub(crate) fn query_err(e: sqlx::Error) -> DriverError {
    DriverError::QueryFailed(e.to_string())
}

/// Convert sqlx pool-acquire errors to DriverError::ConnectionFailed.
pub(crate) fn conn_err(e: sqlx::Error) -> DriverError {
    DriverError::ConnectionFailed(e.to_string())
}

// --- Row collection with limit checks ---

use crate::{MAX_RESULT_BYTES, MAX_RESULT_ROWS, QueryOutput};
use serde_json::Value;

/// Streaming collector that accumulates rows with limit checks.
pub(crate) struct RowCollector {
    pub rows: Vec<Value>,
    pub total_bytes: usize,
    max_rows: usize,
}

impl RowCollector {
    pub fn new(max_rows: Option<usize>) -> Self {
        Self {
            rows: Vec::new(),
            total_bytes: 0,
            max_rows: max_rows.unwrap_or(MAX_RESULT_ROWS),
        }
    }

    /// Push a row and return true if collection should stop (limit reached).
    pub fn push(&mut self, json: Value) -> bool {
        self.total_bytes += serde_json::to_string(&json).unwrap_or_default().len();
        self.rows.push(json);
        self.rows.len() >= self.max_rows || self.total_bytes >= MAX_RESULT_BYTES
    }

    pub fn finish(self) -> QueryOutput {
        let truncated = self.rows.len() >= self.max_rows || self.total_bytes >= MAX_RESULT_BYTES;
        let truncation_reason = if self.rows.len() >= self.max_rows {
            Some(format!("row limit reached ({})", self.max_rows))
        } else if self.total_bytes >= MAX_RESULT_BYTES {
            Some(format!(
                "size limit reached ({} MB)",
                MAX_RESULT_BYTES / 1024 / 1024
            ))
        } else {
            None
        };
        QueryOutput {
            rows: self.rows,
            truncated,
            truncation_reason,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    #[test]
    fn serde_json_map_preserves_insertion_order() {
        // Guard: if preserve_order feature is ever removed, this test fails immediately.
        let mut map = serde_json::Map::new();
        map.insert("z".into(), json!(1));
        map.insert("a".into(), json!(2));
        map.insert("m".into(), json!(3));
        let keys: Vec<&String> = map.keys().collect();
        assert_eq!(
            keys,
            &["z", "a", "m"],
            "serde_json preserve_order feature must be enabled"
        );
    }
}
