use dbward_driver::{CancelState, DatabaseDriver};

use crate::approval::{MigrationDetail, MigrationEntry};
use crate::error::MigrateError;

/// Result of a migration run (up or down).
#[derive(Debug, Clone)]
pub struct MigrationRunResult {
    pub applied: Vec<String>,
    pub reverted: Vec<String>,
}

/// Executes migrations from a pre-built MigrationDetail (server-dispatched JSON).
/// Cancel is checked between migrations only — individual migration SQL is not cancellable.
pub struct MigrationRunner;

impl MigrationRunner {
    /// Run pending migrations up. Validates direction == "up".
    pub async fn run_up(
        driver: &dyn DatabaseDriver,
        detail: &str,
        cancel: &CancelState,
    ) -> Result<MigrationRunResult, MigrateError> {
        let parsed = MigrationDetail::parse(detail)?;
        if parsed.direction != "up" {
            return Err(MigrateError::Config(format!(
                "expected direction 'up', got '{}'",
                parsed.direction
            )));
        }
        driver.ensure_migrations_table().await?;
        let already = driver.applied_versions().await?;
        let pending: Vec<&MigrationEntry> = parsed
            .migrations
            .iter()
            .filter(|e| !already.contains(&e.version))
            .take(parsed.max_count.unwrap_or(usize::MAX))
            .collect();
        let mut applied = vec![];
        for entry in &pending {
            if cancel.is_cancelled() {
                return Err(MigrateError::Cancelled);
            }
            if entry.transactional {
                driver.apply_migration(&entry.sql, &entry.version).await?;
            } else {
                driver
                    .apply_migration_no_tx(&entry.sql, &entry.version)
                    .await?;
            }
            applied.push(entry.version.clone());
        }
        Ok(MigrationRunResult {
            applied,
            reverted: vec![],
        })
    }

    /// Revert applied migrations down. Validates direction == "down".
    pub async fn run_down(
        driver: &dyn DatabaseDriver,
        detail: &str,
        cancel: &CancelState,
    ) -> Result<MigrationRunResult, MigrateError> {
        let parsed = MigrationDetail::parse(detail)?;
        if parsed.direction != "down" {
            return Err(MigrateError::Config(format!(
                "expected direction 'down', got '{}'",
                parsed.direction
            )));
        }
        driver.ensure_migrations_table().await?;
        let already = driver.applied_versions().await?;
        let to_revert: Vec<&MigrationEntry> = parsed
            .migrations
            .iter()
            .rev()
            .filter(|e| already.contains(&e.version))
            .take(parsed.max_count.unwrap_or(usize::MAX))
            .collect();
        let mut reverted = vec![];
        for entry in &to_revert {
            if cancel.is_cancelled() {
                return Err(MigrateError::Cancelled);
            }
            if entry.transactional {
                driver.revert_migration(&entry.sql, &entry.version).await?;
            } else {
                driver
                    .revert_migration_no_tx(&entry.sql, &entry.version)
                    .await?;
            }
            reverted.push(entry.version.clone());
        }
        Ok(MigrationRunResult {
            applied: vec![],
            reverted,
        })
    }

    /// Get list of applied versions.
    pub async fn status(driver: &dyn DatabaseDriver) -> Result<Vec<String>, MigrateError> {
        driver.ensure_migrations_table().await?;
        driver.applied_versions().await.map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbward_driver::{DriverError, QueryOutput};
    use std::sync::Arc;

    /// Minimal mock driver for testing migration runner logic.
    struct MockDriver {
        applied: std::sync::Mutex<Vec<String>>,
    }

    impl MockDriver {
        fn new(applied: Vec<String>) -> Self {
            Self {
                applied: std::sync::Mutex::new(applied),
            }
        }
    }

    #[async_trait::async_trait]
    impl DatabaseDriver for MockDriver {
        async fn query(&self, _sql: &str) -> Result<QueryOutput, DriverError> {
            unimplemented!()
        }
        async fn execute(&self, _sql: &str) -> Result<u64, DriverError> {
            Ok(0)
        }
        async fn apply_migration(&self, _sql: &str, version: &str) -> Result<(), DriverError> {
            self.applied.lock().unwrap().push(version.to_owned());
            Ok(())
        }
        async fn revert_migration(&self, _sql: &str, version: &str) -> Result<(), DriverError> {
            self.applied.lock().unwrap().retain(|v| v != version);
            Ok(())
        }
        async fn apply_migration_no_tx(
            &self,
            _sql: &str,
            version: &str,
        ) -> Result<(), DriverError> {
            self.applied.lock().unwrap().push(version.to_owned());
            Ok(())
        }
        async fn revert_migration_no_tx(
            &self,
            _sql: &str,
            version: &str,
        ) -> Result<(), DriverError> {
            self.applied.lock().unwrap().retain(|v| v != version);
            Ok(())
        }
        async fn ensure_migrations_table(&self) -> Result<(), DriverError> {
            Ok(())
        }
        async fn applied_versions(&self) -> Result<Vec<String>, DriverError> {
            Ok(self.applied.lock().unwrap().clone())
        }
        async fn query_cancellable(
            &self,
            _sql: &str,
            _timeout: u64,
            _cancel: &CancelState,
            _max_rows: Option<usize>,
        ) -> Result<QueryOutput, DriverError> {
            unimplemented!()
        }
        async fn execute_cancellable(
            &self,
            _sql: &str,
            _timeout: u64,
            _cancel: &CancelState,
        ) -> Result<u64, DriverError> {
            unimplemented!()
        }
        async fn cancel_query(&self, _connection_id: &str) -> Result<bool, DriverError> {
            Ok(true)
        }
        async fn collect_schema(&self) -> Result<dbward_driver::SchemaSnapshot, DriverError> {
            Ok(dbward_driver::SchemaSnapshot { tables: vec![] })
        }
        async fn explain(&self, _: &str, _: u64) -> Result<serde_json::Value, DriverError> {
            Ok(serde_json::json!({}))
        }
        fn dialect(&self) -> &'static str {
            "postgresql"
        }
    }

    fn make_detail(direction: &str, migrations: Vec<(&str, &str)>) -> String {
        make_detail_with_tx(
            direction,
            migrations.into_iter().map(|(v, s)| (v, s, true)).collect(),
        )
    }

    fn make_detail_with_tx(direction: &str, migrations: Vec<(&str, &str, bool)>) -> String {
        let entries: Vec<MigrationEntry> = migrations
            .into_iter()
            .map(|(v, sql, tx)| MigrationEntry {
                version: v.to_owned(),
                sql: sql.to_owned(),
                transactional: tx,
            })
            .collect();
        let detail = MigrationDetail {
            format: "v2".into(),
            direction: direction.into(),
            versions: entries.iter().map(|e| e.version.clone()).collect(),
            migrations: entries,
            dir_sha256: "abc".into(),
            max_count: None,
        };
        serde_json::to_string(&detail).unwrap()
    }

    #[tokio::test]
    async fn run_up_applies_pending() {
        let driver = Arc::new(MockDriver::new(vec![]));
        let cancel = CancelState::new();
        let detail = make_detail(
            "up",
            vec![("001", "CREATE TABLE t1"), ("002", "CREATE TABLE t2")],
        );
        let result = MigrationRunner::run_up(driver.as_ref(), &detail, &cancel)
            .await
            .unwrap();
        assert_eq!(result.applied, vec!["001", "002"]);
    }

    #[tokio::test]
    async fn run_up_skips_already_applied() {
        let driver = Arc::new(MockDriver::new(vec!["001".into()]));
        let cancel = CancelState::new();
        let detail = make_detail(
            "up",
            vec![("001", "CREATE TABLE t1"), ("002", "CREATE TABLE t2")],
        );
        let result = MigrationRunner::run_up(driver.as_ref(), &detail, &cancel)
            .await
            .unwrap();
        assert_eq!(result.applied, vec!["002"]);
    }

    #[tokio::test]
    async fn run_up_rejects_wrong_direction() {
        let driver = Arc::new(MockDriver::new(vec![]));
        let cancel = CancelState::new();
        let detail = make_detail("down", vec![("001", "DROP TABLE t1")]);
        let err = MigrationRunner::run_up(driver.as_ref(), &detail, &cancel)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("expected direction 'up'"));
    }

    #[tokio::test]
    async fn run_down_reverts_applied() {
        let driver = Arc::new(MockDriver::new(vec!["001".into(), "002".into()]));
        let cancel = CancelState::new();
        let detail = make_detail(
            "down",
            vec![("001", "DROP TABLE t1"), ("002", "DROP TABLE t2")],
        );
        let result = MigrationRunner::run_down(driver.as_ref(), &detail, &cancel)
            .await
            .unwrap();
        assert_eq!(result.reverted, vec!["002", "001"]);
    }

    #[tokio::test]
    async fn run_down_rejects_wrong_direction() {
        let driver = Arc::new(MockDriver::new(vec![]));
        let cancel = CancelState::new();
        let detail = make_detail("up", vec![("001", "CREATE TABLE t1")]);
        let err = MigrationRunner::run_down(driver.as_ref(), &detail, &cancel)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("expected direction 'down'"));
    }

    #[tokio::test]
    async fn run_up_respects_cancel() {
        let driver = Arc::new(MockDriver::new(vec![]));
        let cancel = CancelState::new();
        cancel.mark_cancelled();
        let detail = make_detail("up", vec![("001", "CREATE TABLE t1")]);
        let err = MigrationRunner::run_up(driver.as_ref(), &detail, &cancel)
            .await
            .unwrap_err();
        assert!(matches!(err, MigrateError::Cancelled));
    }

    #[tokio::test]
    async fn status_returns_applied_versions() {
        let driver = Arc::new(MockDriver::new(vec!["001".into(), "003".into()]));
        let versions = MigrationRunner::status(driver.as_ref()).await.unwrap();
        assert_eq!(versions, vec!["001", "003"]);
    }

    /// Mock that tracks whether no_tx methods were called.
    struct TrackingMockDriver {
        applied: std::sync::Mutex<Vec<String>>,
        no_tx_calls: std::sync::Mutex<Vec<String>>,
    }

    impl TrackingMockDriver {
        fn new() -> Self {
            Self {
                applied: std::sync::Mutex::new(vec![]),
                no_tx_calls: std::sync::Mutex::new(vec![]),
            }
        }
    }

    #[async_trait::async_trait]
    impl DatabaseDriver for TrackingMockDriver {
        async fn query(&self, _: &str) -> Result<QueryOutput, DriverError> {
            unimplemented!()
        }
        async fn execute(&self, _: &str) -> Result<u64, DriverError> {
            unimplemented!()
        }
        async fn apply_migration(&self, _sql: &str, version: &str) -> Result<(), DriverError> {
            self.applied.lock().unwrap().push(version.to_owned());
            Ok(())
        }
        async fn revert_migration(&self, _sql: &str, version: &str) -> Result<(), DriverError> {
            self.applied.lock().unwrap().retain(|v| v != version);
            Ok(())
        }
        async fn apply_migration_no_tx(
            &self,
            _sql: &str,
            version: &str,
        ) -> Result<(), DriverError> {
            self.applied.lock().unwrap().push(version.to_owned());
            self.no_tx_calls
                .lock()
                .unwrap()
                .push(format!("apply_no_tx:{version}"));
            Ok(())
        }
        async fn revert_migration_no_tx(
            &self,
            _sql: &str,
            version: &str,
        ) -> Result<(), DriverError> {
            self.applied.lock().unwrap().retain(|v| v != version);
            self.no_tx_calls
                .lock()
                .unwrap()
                .push(format!("revert_no_tx:{version}"));
            Ok(())
        }
        async fn ensure_migrations_table(&self) -> Result<(), DriverError> {
            Ok(())
        }
        async fn applied_versions(&self) -> Result<Vec<String>, DriverError> {
            Ok(self.applied.lock().unwrap().clone())
        }
        async fn query_cancellable(
            &self,
            _: &str,
            _: u64,
            _: &CancelState,
            _: Option<usize>,
        ) -> Result<QueryOutput, DriverError> {
            unimplemented!()
        }
        async fn execute_cancellable(
            &self,
            _: &str,
            _: u64,
            _: &CancelState,
        ) -> Result<u64, DriverError> {
            unimplemented!()
        }
        async fn cancel_query(&self, _: &str) -> Result<bool, DriverError> {
            unimplemented!()
        }
        async fn collect_schema(&self) -> Result<dbward_driver::SchemaSnapshot, DriverError> {
            unimplemented!()
        }
        async fn explain(&self, _: &str, _: u64) -> Result<serde_json::Value, DriverError> {
            unimplemented!()
        }
        fn dialect(&self) -> &'static str {
            "postgresql"
        }
    }

    #[tokio::test]
    async fn run_up_uses_no_tx_when_transactional_false() {
        let driver = Arc::new(TrackingMockDriver::new());
        let cancel = CancelState::new();
        let detail = make_detail_with_tx(
            "up",
            vec![
                ("001", "CREATE INDEX CONCURRENTLY idx ON t(c)", false),
                ("002", "CREATE TABLE t2 (id INT)", true),
            ],
        );
        let result = MigrationRunner::run_up(driver.as_ref(), &detail, &cancel)
            .await
            .unwrap();
        assert_eq!(result.applied, vec!["001", "002"]);
        let no_tx = driver.no_tx_calls.lock().unwrap().clone();
        assert_eq!(no_tx, vec!["apply_no_tx:001"]);
    }

    #[tokio::test]
    async fn run_down_uses_no_tx_when_transactional_false() {
        let driver = Arc::new(TrackingMockDriver::new());
        {
            driver
                .applied
                .lock()
                .unwrap()
                .extend(vec!["001".into(), "002".into()]);
        }
        let cancel = CancelState::new();
        let detail = make_detail_with_tx(
            "down",
            vec![
                ("001", "DROP TABLE t1", true),
                ("002", "DROP INDEX CONCURRENTLY idx", false),
            ],
        );
        let result = MigrationRunner::run_down(driver.as_ref(), &detail, &cancel)
            .await
            .unwrap();
        assert_eq!(result.reverted, vec!["002", "001"]);
        let no_tx = driver.no_tx_calls.lock().unwrap().clone();
        assert_eq!(no_tx, vec!["revert_no_tx:002"]);
    }
}
