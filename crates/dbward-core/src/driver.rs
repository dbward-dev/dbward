use std::sync::Arc;

use crate::Error;

/// Default limits for query results to prevent OOM.
pub const DEFAULT_MAX_RESULT_ROWS: usize = 10_000;
pub const DEFAULT_MAX_RESULT_BYTES: usize = 50 * 1024 * 1024; // 50 MB

/// Result of a query execution, including truncation metadata.
pub struct QueryOutput {
    pub rows: Vec<serde_json::Value>,
    pub truncated: bool,
    pub truncation_reason: Option<String>,
}

/// Abstraction over database backends. Implementations handle connection pooling,
/// query execution, and migration bookkeeping for a specific database engine.
#[async_trait::async_trait]
pub trait DatabaseDriver: Send + Sync {
    /// Execute a read query, returning rows as JSON objects.
    async fn query(&self, sql: &str) -> Result<QueryOutput, Error>;

    /// Execute a write statement, returning rows affected.
    async fn execute(&self, sql: &str) -> Result<u64, Error>;

    /// Execute SQL within a transaction alongside a migration version record.
    async fn apply_migration(&self, sql: &str, version: &str) -> Result<(), Error>;

    /// Remove a migration version record within a transaction that runs down SQL.
    async fn revert_migration(&self, down_sql: &str, version: &str) -> Result<(), Error>;

    /// Ensure the schema_migrations table exists.
    async fn ensure_migrations_table(&self) -> Result<(), Error>;

    /// Get all applied migration versions, sorted.
    async fn applied_versions(&self) -> Result<Vec<String>, Error>;
}

/// Create a driver from a database URL. Scheme determines the backend.
pub async fn connect(url: &str) -> Result<Arc<dyn DatabaseDriver>, Error> {
    if url.starts_with("postgres://") || url.starts_with("postgresql://") {
        let pool = sqlx::PgPool::connect(url)
            .await
            .map_err(|e| Error::Database(e.to_string()))?;
        Ok(Arc::new(PostgresDriver { pool }))
    } else if url.starts_with("mysql://") {
        let pool = sqlx::MySqlPool::connect(url)
            .await
            .map_err(|e| Error::Database(e.to_string()))?;
        Ok(Arc::new(MysqlDriver { pool }))
    } else {
        Err(Error::Config(format!(
            "unsupported database URL scheme: {url}"
        )))
    }
}

// ── PostgreSQL ──────────────────────────────────────────────

pub struct PostgresDriver {
    pool: sqlx::PgPool,
}

#[async_trait::async_trait]
impl DatabaseDriver for PostgresDriver {
    async fn query(&self, sql: &str) -> Result<QueryOutput, Error> {
        use futures::TryStreamExt;
        let mut stream = sqlx::query(sql).fetch(&self.pool);
        let mut rows = Vec::new();
        let mut total_bytes: usize = 0;
        let mut truncated = false;
        let mut truncation_reason = None;
        while let Some(row) = stream
            .try_next()
            .await
            .map_err(|e| Error::Database(e.to_string()))?
        {
            let json = pg_row_to_json(&row);
            total_bytes += serde_json::to_string(&json).unwrap_or_default().len();
            rows.push(json);
            if rows.len() >= DEFAULT_MAX_RESULT_ROWS {
                truncated = true;
                truncation_reason = Some(format!("row limit reached ({DEFAULT_MAX_RESULT_ROWS})"));
                break;
            }
            if total_bytes >= DEFAULT_MAX_RESULT_BYTES {
                truncated = true;
                truncation_reason = Some(format!("size limit reached ({} MB)", DEFAULT_MAX_RESULT_BYTES / 1024 / 1024));
                break;
            }
        }
        Ok(QueryOutput { rows, truncated, truncation_reason })
    }

    async fn execute(&self, sql: &str) -> Result<u64, Error> {
        let result = sqlx::raw_sql(sql)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Database(e.to_string()))?;
        Ok(result.rows_affected())
    }
    async fn apply_migration(&self, sql: &str, version: &str) -> Result<(), Error> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Error::Database(e.to_string()))?;
        sqlx::query(sql)
            .execute(&mut *tx)
            .await
            .map_err(|e| Error::Database(e.to_string()))?;
        sqlx::query("INSERT INTO schema_migrations (version) VALUES ($1)")
            .bind(version)
            .execute(&mut *tx)
            .await
            .map_err(|e| Error::Database(e.to_string()))?;
        tx.commit()
            .await
            .map_err(|e| Error::Database(e.to_string()))
    }

    async fn revert_migration(&self, down_sql: &str, version: &str) -> Result<(), Error> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Error::Database(e.to_string()))?;
        sqlx::query(down_sql)
            .execute(&mut *tx)
            .await
            .map_err(|e| Error::Database(e.to_string()))?;
        sqlx::query("DELETE FROM schema_migrations WHERE version = $1")
            .bind(version)
            .execute(&mut *tx)
            .await
            .map_err(|e| Error::Database(e.to_string()))?;
        tx.commit()
            .await
            .map_err(|e| Error::Database(e.to_string()))
    }

    async fn ensure_migrations_table(&self) -> Result<(), Error> {
        sqlx::query("CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY)")
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Database(e.to_string()))?;
        Ok(())
    }

    async fn applied_versions(&self) -> Result<Vec<String>, Error> {
        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT version FROM schema_migrations ORDER BY version")
                .fetch_all(&self.pool)
                .await
                .map_err(|e| Error::Database(e.to_string()))?;
        Ok(rows.into_iter().map(|(v,)| v).collect())
    }
}

fn pg_row_to_json(row: &sqlx::postgres::PgRow) -> serde_json::Value {
    use sqlx::{Column, Row, TypeInfo};
    let mut map = serde_json::Map::new();
    for col in row.columns() {
        let name = col.name();
        let val: serde_json::Value = match col.type_info().name() {
            "BOOL" => row
                .try_get::<bool, _>(name)
                .map(Into::into)
                .unwrap_or(serde_json::Value::Null),
            "INT2" => row
                .try_get::<i16, _>(name)
                .map(|v| v.into())
                .unwrap_or(serde_json::Value::Null),
            "INT4" => row
                .try_get::<i32, _>(name)
                .map(Into::into)
                .unwrap_or(serde_json::Value::Null),
            "INT8" => row
                .try_get::<i64, _>(name)
                .map(Into::into)
                .unwrap_or(serde_json::Value::Null),
            "FLOAT4" => row
                .try_get::<f32, _>(name)
                .map(|v| v.into())
                .unwrap_or(serde_json::Value::Null),
            "FLOAT8" => row
                .try_get::<f64, _>(name)
                .map(Into::into)
                .unwrap_or(serde_json::Value::Null),
            "JSONB" | "JSON" => row
                .try_get::<String, _>(name)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or(serde_json::Value::Null),
            // TIMESTAMPTZ, TIMESTAMP, DATE, UUID, NUMERIC → string via fallback
            _ => row
                .try_get::<String, _>(name)
                .map(Into::into)
                .unwrap_or(serde_json::Value::Null),
        };
        map.insert(name.to_string(), val);
    }
    serde_json::Value::Object(map)
}

// ── MySQL ───────────────────────────────────────────────────

pub struct MysqlDriver {
    pool: sqlx::MySqlPool,
}

#[async_trait::async_trait]
impl DatabaseDriver for MysqlDriver {
    async fn query(&self, sql: &str) -> Result<QueryOutput, Error> {
        use futures::TryStreamExt;
        let mut stream = sqlx::query(sql).fetch(&self.pool);
        let mut rows = Vec::new();
        let mut total_bytes: usize = 0;
        let mut truncated = false;
        let mut truncation_reason = None;
        while let Some(row) = stream
            .try_next()
            .await
            .map_err(|e| Error::Database(e.to_string()))?
        {
            let json = mysql_row_to_json(&row);
            total_bytes += serde_json::to_string(&json).unwrap_or_default().len();
            rows.push(json);
            if rows.len() >= DEFAULT_MAX_RESULT_ROWS {
                truncated = true;
                truncation_reason = Some(format!("row limit reached ({DEFAULT_MAX_RESULT_ROWS})"));
                break;
            }
            if total_bytes >= DEFAULT_MAX_RESULT_BYTES {
                truncated = true;
                truncation_reason = Some(format!("size limit reached ({} MB)", DEFAULT_MAX_RESULT_BYTES / 1024 / 1024));
                break;
            }
        }
        Ok(QueryOutput { rows, truncated, truncation_reason })
    }

    async fn execute(&self, sql: &str) -> Result<u64, Error> {
        let result = sqlx::raw_sql(sql)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Database(e.to_string()))?;
        Ok(result.rows_affected())
    }
    async fn apply_migration(&self, sql: &str, version: &str) -> Result<(), Error> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Error::Database(e.to_string()))?;
        sqlx::query(sql)
            .execute(&mut *tx)
            .await
            .map_err(|e| Error::Database(e.to_string()))?;
        sqlx::query("INSERT INTO schema_migrations (version) VALUES (?)")
            .bind(version)
            .execute(&mut *tx)
            .await
            .map_err(|e| Error::Database(e.to_string()))?;
        tx.commit()
            .await
            .map_err(|e| Error::Database(e.to_string()))
    }

    async fn revert_migration(&self, down_sql: &str, version: &str) -> Result<(), Error> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Error::Database(e.to_string()))?;
        sqlx::query(down_sql)
            .execute(&mut *tx)
            .await
            .map_err(|e| Error::Database(e.to_string()))?;
        sqlx::query("DELETE FROM schema_migrations WHERE version = ?")
            .bind(version)
            .execute(&mut *tx)
            .await
            .map_err(|e| Error::Database(e.to_string()))?;
        tx.commit()
            .await
            .map_err(|e| Error::Database(e.to_string()))
    }

    async fn ensure_migrations_table(&self) -> Result<(), Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version VARCHAR(255) PRIMARY KEY)",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Database(e.to_string()))?;
        Ok(())
    }

    async fn applied_versions(&self) -> Result<Vec<String>, Error> {
        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT version FROM schema_migrations ORDER BY version")
                .fetch_all(&self.pool)
                .await
                .map_err(|e| Error::Database(e.to_string()))?;
        Ok(rows.into_iter().map(|(v,)| v).collect())
    }
}

fn mysql_row_to_json(row: &sqlx::mysql::MySqlRow) -> serde_json::Value {
    use sqlx::{Column, Row, TypeInfo};
    let mut map = serde_json::Map::new();
    for col in row.columns() {
        let name = col.name();
        let val: serde_json::Value = match col.type_info().name() {
            "BOOLEAN" | "TINYINT(1)" => row
                .try_get::<bool, _>(name)
                .map(Into::into)
                .unwrap_or(serde_json::Value::Null),
            "SMALLINT" | "TINYINT" => row
                .try_get::<i16, _>(name)
                .map(|v| v.into())
                .unwrap_or(serde_json::Value::Null),
            "INT" | "MEDIUMINT" => row
                .try_get::<i32, _>(name)
                .map(Into::into)
                .unwrap_or(serde_json::Value::Null),
            "BIGINT" => row
                .try_get::<i64, _>(name)
                .map(Into::into)
                .unwrap_or(serde_json::Value::Null),
            "FLOAT" => row
                .try_get::<f32, _>(name)
                .map(|v| v.into())
                .unwrap_or(serde_json::Value::Null),
            "DOUBLE" => row
                .try_get::<f64, _>(name)
                .map(Into::into)
                .unwrap_or(serde_json::Value::Null),
            "JSON" => row
                .try_get::<String, _>(name)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or(serde_json::Value::Null),
            // TIMESTAMP, DATETIME, DATE, DECIMAL → string via fallback
            _ => row
                .try_get::<String, _>(name)
                .map(Into::into)
                .unwrap_or(serde_json::Value::Null),
        };
        map.insert(name.to_string(), val);
    }
    serde_json::Value::Object(map)
}
