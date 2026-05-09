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
    connect_with_timeout(url, None).await
}

pub async fn connect_with_timeout(
    url: &str,
    statement_timeout_secs: Option<u64>,
) -> Result<Arc<dyn DatabaseDriver>, Error> {
    if url.starts_with("postgres://") || url.starts_with("postgresql://") {
        let mut opts = sqlx::postgres::PgPoolOptions::new().max_connections(5);
        if let Some(secs) = statement_timeout_secs {
            opts = opts.after_connect(move |conn, _meta| {
                Box::pin(async move {
                    sqlx::query(&format!("SET statement_timeout = '{secs}s'"))
                        .execute(&mut *conn)
                        .await?;
                    Ok(())
                })
            });
        }
        let pool = opts
            .connect(url)
            .await
            .map_err(|e| Error::Database(e.to_string()))?;
        Ok(Arc::new(PostgresDriver { pool }))
    } else if url.starts_with("mysql://") {
        let mut opts = sqlx::mysql::MySqlPoolOptions::new().max_connections(5);
        if let Some(secs) = statement_timeout_secs {
            let ms = secs * 1000;
            opts = opts.after_connect(move |conn, _meta| {
                Box::pin(async move {
                    sqlx::query(&format!("SET SESSION max_execution_time = {ms}"))
                        .execute(&mut *conn)
                        .await?;
                    Ok(())
                })
            });
        }
        let pool = opts
            .connect(url)
            .await
            .map_err(|e| Error::Database(e.to_string()))?;
        Ok(Arc::new(MysqlDriver { pool }))
    } else {
        Err(Error::Config(format!(
            "unsupported database URL scheme: {url}"
        )))
    }
}

// ── Shared type conversion ───────────────────────────────────

#[derive(Debug, Clone, Copy)]
enum JsonMapping {
    Integer,
    Float,
    Bool,
    Json,
    Binary,
    Text,
}

fn text_to_json(text: &str, mapping: JsonMapping) -> serde_json::Value {
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

// ── PostgreSQL ──────────────────────────────────────────────

pub struct PostgresDriver {
    pool: sqlx::PgPool,
}

#[async_trait::async_trait]
impl DatabaseDriver for PostgresDriver {
    async fn query(&self, sql: &str) -> Result<QueryOutput, Error> {
        use futures::TryStreamExt;
        let mut stream = sqlx::raw_sql(sql).fetch(&self.pool);
        let mut rows = Vec::new();
        let mut total_bytes: usize = 0;
        let mut truncated = false;
        let mut truncation_reason = None;
        while let Some(row) = stream
            .try_next()
            .await
            .map_err(|e| Error::Database(e.to_string()))?
        {
            let json = pg_row_to_json_text(&row);
            total_bytes += serde_json::to_string(&json).unwrap_or_default().len();
            rows.push(json);
            if rows.len() >= DEFAULT_MAX_RESULT_ROWS {
                truncated = true;
                truncation_reason = Some(format!("row limit reached ({DEFAULT_MAX_RESULT_ROWS})"));
                break;
            }
            if total_bytes >= DEFAULT_MAX_RESULT_BYTES {
                truncated = true;
                truncation_reason = Some(format!(
                    "size limit reached ({} MB)",
                    DEFAULT_MAX_RESULT_BYTES / 1024 / 1024
                ));
                break;
            }
        }
        Ok(QueryOutput {
            rows,
            truncated,
            truncation_reason,
        })
    }

    async fn execute(&self, sql: &str) -> Result<u64, Error> {
        // PostgreSQL simple query protocol guarantees atomicity for multi-statement
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

fn pg_row_to_json_text(row: &sqlx::postgres::PgRow) -> serde_json::Value {
    use sqlx::{Column, Row, TypeInfo, ValueRef};
    let mut map = serde_json::Map::new();
    for col in row.columns() {
        let name = col.name();
        let raw = row
            .try_get_raw(col.ordinal())
            .expect("column ordinal from row.columns() must be valid");
        let val = if raw.is_null() {
            serde_json::Value::Null
        } else {
            match raw.as_str() {
                Ok(text) => text_to_json(text, pg_type_mapping(col.type_info().name())),
                Err(_) => serde_json::Value::String("(binary data)".into()),
            }
        };
        map.insert(name.to_string(), val);
    }
    serde_json::Value::Object(map)
}

fn pg_type_mapping(type_name: &str) -> JsonMapping {
    match type_name {
        "INT2" | "INT4" | "INT8" => JsonMapping::Integer,
        "FLOAT4" | "FLOAT8" => JsonMapping::Float,
        "BOOL" => JsonMapping::Bool,
        "JSON" | "JSONB" => JsonMapping::Json,
        "BYTEA" => JsonMapping::Binary,
        _ => JsonMapping::Text,
    }
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
            let json = mysql_row_to_json_text(&row);
            total_bytes += serde_json::to_string(&json).unwrap_or_default().len();
            rows.push(json);
            if rows.len() >= DEFAULT_MAX_RESULT_ROWS {
                truncated = true;
                truncation_reason = Some(format!("row limit reached ({DEFAULT_MAX_RESULT_ROWS})"));
                break;
            }
            if total_bytes >= DEFAULT_MAX_RESULT_BYTES {
                truncated = true;
                truncation_reason = Some(format!(
                    "size limit reached ({} MB)",
                    DEFAULT_MAX_RESULT_BYTES / 1024 / 1024
                ));
                break;
            }
        }
        Ok(QueryOutput {
            rows,
            truncated,
            truncation_reason,
        })
    }

    async fn execute(&self, sql: &str) -> Result<u64, Error> {
        // MySQL: wrap multi-statement in explicit transaction for atomicity
        // (MySQL has no implicit transaction block for multi-statement batches)
        if !crate::query::is_multi_statement_mysql(sql) {
            let result = sqlx::raw_sql(sql)
                .execute(&self.pool)
                .await
                .map_err(|e| Error::Database(e.to_string()))?;
            return Ok(result.rows_affected());
        }
        let stmts = crate::query::split_statements_mysql(sql);
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Error::Database(e.to_string()))?;
        let mut total_affected = 0u64;
        for stmt in &stmts {
            let r = sqlx::query(stmt)
                .execute(&mut *tx)
                .await
                .map_err(|e| Error::Database(e.to_string()))?;
            total_affected += r.rows_affected();
        }
        tx.commit()
            .await
            .map_err(|e| Error::Database(e.to_string()))?;
        Ok(total_affected)
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

fn mysql_row_to_json_text(row: &sqlx::mysql::MySqlRow) -> serde_json::Value {
    use sqlx::{Column, Row, TypeInfo};
    let mut map = serde_json::Map::new();
    for col in row.columns() {
        let name = col.name();
        let mapping = mysql_type_mapping(col.type_info().name());
        let val: serde_json::Value = match mapping {
            JsonMapping::Integer => row
                .try_get::<i64, _>(name)
                .map(Into::into)
                .unwrap_or(serde_json::Value::Null),
            JsonMapping::Float => row
                .try_get::<f64, _>(name)
                .map(|v| {
                    serde_json::Number::from_f64(v)
                        .map(serde_json::Value::Number)
                        .unwrap_or(serde_json::Value::String(v.to_string()))
                })
                .unwrap_or(serde_json::Value::Null),
            JsonMapping::Bool => row
                .try_get::<bool, _>(name)
                .map(Into::into)
                .unwrap_or(serde_json::Value::Null),
            JsonMapping::Json => row
                .try_get::<String, _>(name)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or(serde_json::Value::Null),
            JsonMapping::Binary => serde_json::Value::String("(binary data)".into()),
            JsonMapping::Text => row
                .try_get::<Option<String>, _>(name)
                .map(|opt| opt.map(Into::into).unwrap_or(serde_json::Value::Null))
                .unwrap_or_else(|_| serde_json::Value::String("(binary data)".into())),
        };
        map.insert(name.to_string(), val);
    }
    serde_json::Value::Object(map)
}

fn mysql_type_mapping(type_name: &str) -> JsonMapping {
    match type_name {
        "TINYINT" | "TINYINT UNSIGNED" | "SMALLINT" | "SMALLINT UNSIGNED" | "INT"
        | "INT UNSIGNED" | "MEDIUMINT" | "MEDIUMINT UNSIGNED" | "BIGINT"
        | "BIGINT UNSIGNED" => JsonMapping::Integer,
        "FLOAT" | "DOUBLE" => JsonMapping::Float,
        "BOOLEAN" => JsonMapping::Bool,
        "JSON" => JsonMapping::Json,
        "BLOB" | "BINARY" | "VARBINARY" | "LONGBLOB" | "MEDIUMBLOB" | "TINYBLOB" => {
            JsonMapping::Binary
        }
        _ => JsonMapping::Text,
    }
}
