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
            driver.apply_migration(&entry.sql, &entry.version).await?;
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
            driver.revert_migration(&entry.sql, &entry.version).await?;
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
