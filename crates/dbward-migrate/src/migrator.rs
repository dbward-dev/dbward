use std::sync::Arc;

use serde::Serialize;

use crate::error::MigrateError;
use crate::parser::{Migration, create_migration_file, parse_migrations_dir};
use dbward_driver::DatabaseDriver;

#[derive(Debug, Serialize)]
pub struct MigrationResult {
    pub applied: Vec<String>,
    pub rolled_back: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct MigrationStatus {
    pub version: String,
    pub name: String,
    pub applied: bool,
}

pub struct Migrator {
    driver: Arc<dyn DatabaseDriver>,
    migrations_dir: std::path::PathBuf,
}

impl Migrator {
    pub fn new(
        driver: Arc<dyn DatabaseDriver>,
        migrations_dir: impl Into<std::path::PathBuf>,
    ) -> Self {
        Self {
            driver,
            migrations_dir: migrations_dir.into(),
        }
    }

    pub async fn status(&self) -> Result<Vec<MigrationStatus>, MigrateError> {
        self.driver.ensure_migrations_table().await?;
        let applied = self.driver.applied_versions().await?;
        let migrations = parse_migrations_dir(&self.migrations_dir)?;

        Ok(migrations
            .into_iter()
            .map(|m| MigrationStatus {
                applied: applied.contains(&m.version),
                version: m.version,
                name: m.name,
            })
            .collect())
    }

    pub async fn up(&self, count: Option<usize>) -> Result<MigrationResult, MigrateError> {
        self.driver.ensure_migrations_table().await?;
        let applied = self.driver.applied_versions().await?;
        let migrations = parse_migrations_dir(&self.migrations_dir)?;

        let pending: Vec<&Migration> = migrations
            .iter()
            .filter(|m| !applied.contains(&m.version))
            .collect();

        let to_apply = match count {
            Some(n) => &pending[..n.min(pending.len())],
            None => &pending,
        };

        let mut result = MigrationResult {
            applied: vec![],
            rolled_back: vec![],
        };

        for migration in to_apply {
            self.driver
                .apply_migration(&migration.up_sql, &migration.version)
                .await?;
            result
                .applied
                .push(format!("{}_{}", migration.version, migration.name));
        }

        Ok(result)
    }

    pub async fn down(&self, count: Option<usize>) -> Result<MigrationResult, MigrateError> {
        self.driver.ensure_migrations_table().await?;
        let applied = self.driver.applied_versions().await?;
        let migrations = parse_migrations_dir(&self.migrations_dir)?;

        let mut to_rollback: Vec<&Migration> = migrations
            .iter()
            .filter(|m| applied.contains(&m.version))
            .collect();
        to_rollback.reverse();

        let count = count.unwrap_or(1);
        let to_rollback = &to_rollback[..count.min(to_rollback.len())];

        let mut result = MigrationResult {
            applied: vec![],
            rolled_back: vec![],
        };

        for migration in to_rollback {
            let down_sql = migration.down_sql.as_deref().ok_or_else(|| {
                MigrateError::Config(format!("no down migration for {}", migration.version))
            })?;

            self.driver
                .revert_migration(down_sql, &migration.version)
                .await?;
            result
                .rolled_back
                .push(format!("{}_{}", migration.version, migration.name));
        }

        Ok(result)
    }

    pub fn create(&self, name: &str) -> Result<std::path::PathBuf, MigrateError> {
        create_migration_file(&self.migrations_dir, name)
    }
}

/// Migrator that only supports local file operations (no DB connection).
pub struct LocalMigrator {
    migrations_dir: std::path::PathBuf,
}

impl LocalMigrator {
    pub fn new(migrations_dir: impl Into<std::path::PathBuf>) -> Self {
        Self {
            migrations_dir: migrations_dir.into(),
        }
    }

    pub fn create(&self, name: &str) -> Result<std::path::PathBuf, MigrateError> {
        create_migration_file(&self.migrations_dir, name)
    }
}
