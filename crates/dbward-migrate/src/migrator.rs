use serde::Serialize;
use sqlx::PgPool;

use crate::parser::{Migration, create_migration_file, parse_migrations_dir};

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
    pool: PgPool,
    migrations_dir: std::path::PathBuf,
}

impl Migrator {
    pub fn new(pool: PgPool, migrations_dir: impl Into<std::path::PathBuf>) -> Self {
        Self {
            pool,
            migrations_dir: migrations_dir.into(),
        }
    }

    async fn ensure_table(&self) -> Result<(), dbward_core::Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY)",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| dbward_core::Error::Database(e.to_string()))?;
        Ok(())
    }

    async fn applied_versions(&self) -> Result<Vec<String>, dbward_core::Error> {
        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT version FROM schema_migrations ORDER BY version")
                .fetch_all(&self.pool)
                .await
                .map_err(|e| dbward_core::Error::Database(e.to_string()))?;
        Ok(rows.into_iter().map(|(v,)| v).collect())
    }

    pub async fn status(&self) -> Result<Vec<MigrationStatus>, dbward_core::Error> {
        self.ensure_table().await?;
        let applied = self.applied_versions().await?;
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

    pub async fn up(&self, count: Option<usize>) -> Result<MigrationResult, dbward_core::Error> {
        self.ensure_table().await?;
        let applied = self.applied_versions().await?;
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
            let mut tx = self
                .pool
                .begin()
                .await
                .map_err(|e| dbward_core::Error::Database(e.to_string()))?;

            sqlx::query(&migration.up_sql)
                .execute(&mut *tx)
                .await
                .map_err(|e| dbward_core::Error::Database(e.to_string()))?;

            sqlx::query("INSERT INTO schema_migrations (version) VALUES ($1)")
                .bind(&migration.version)
                .execute(&mut *tx)
                .await
                .map_err(|e| dbward_core::Error::Database(e.to_string()))?;

            tx.commit()
                .await
                .map_err(|e| dbward_core::Error::Database(e.to_string()))?;

            result
                .applied
                .push(format!("{}_{}", migration.version, migration.name));
        }

        Ok(result)
    }

    pub async fn down(
        &self,
        count: Option<usize>,
    ) -> Result<MigrationResult, dbward_core::Error> {
        self.ensure_table().await?;
        let applied = self.applied_versions().await?;
        let migrations = parse_migrations_dir(&self.migrations_dir)?;

        // Rollback in reverse order
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
                dbward_core::Error::Config(format!(
                    "no down migration for {}",
                    migration.version
                ))
            })?;

            let mut tx = self
                .pool
                .begin()
                .await
                .map_err(|e| dbward_core::Error::Database(e.to_string()))?;

            sqlx::query(down_sql)
                .execute(&mut *tx)
                .await
                .map_err(|e| dbward_core::Error::Database(e.to_string()))?;

            sqlx::query("DELETE FROM schema_migrations WHERE version = $1")
                .bind(&migration.version)
                .execute(&mut *tx)
                .await
                .map_err(|e| dbward_core::Error::Database(e.to_string()))?;

            tx.commit()
                .await
                .map_err(|e| dbward_core::Error::Database(e.to_string()))?;

            result
                .rolled_back
                .push(format!("{}_{}", migration.version, migration.name));
        }

        Ok(result)
    }

    pub fn create(&self, name: &str) -> Result<std::path::PathBuf, dbward_core::Error> {
        create_migration_file(&self.migrations_dir, name)
    }
}
