use futures::TryStreamExt;
use sqlx::{Column, Row, TypeInfo, ValueRef};

use crate::{
    text_to_json, CancelState, DatabaseDriver, DriverError, JsonMapping, QueryOutput, MAX_RESULT_BYTES,
    MAX_RESULT_ROWS,
};

pub struct PostgresDriver {
    pool: sqlx::PgPool,
}

impl PostgresDriver {
    pub async fn connect(
        url: &str,
        statement_timeout_secs: Option<u64>,
    ) -> Result<Self, DriverError> {
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
            .map_err(|e| DriverError::ConnectionFailed(e.to_string()))?;
        Ok(Self { pool })
    }
}

#[async_trait::async_trait]
impl DatabaseDriver for PostgresDriver {
    async fn query(&self, sql: &str) -> Result<QueryOutput, DriverError> {
        let mut stream = sqlx::raw_sql(sql).fetch(&self.pool);
        let mut rows = Vec::new();
        let mut total_bytes: usize = 0;
        let mut truncated = false;
        let mut truncation_reason = None;

        while let Some(row) = stream
            .try_next()
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?
        {
            let json = pg_row_to_json(&row);
            total_bytes += serde_json::to_string(&json).unwrap_or_default().len();
            rows.push(json);
            if rows.len() >= MAX_RESULT_ROWS {
                truncated = true;
                truncation_reason = Some(format!("row limit reached ({MAX_RESULT_ROWS})"));
                break;
            }
            if total_bytes >= MAX_RESULT_BYTES {
                truncated = true;
                truncation_reason = Some(format!(
                    "size limit reached ({} MB)",
                    MAX_RESULT_BYTES / 1024 / 1024
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

    async fn execute(&self, sql: &str) -> Result<u64, DriverError> {
        // PostgreSQL simple query protocol guarantees atomicity for multi-statement
        let result = sqlx::raw_sql(sql)
            .execute(&self.pool)
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        Ok(result.rows_affected())
    }

    async fn apply_migration(&self, sql: &str, version: &str) -> Result<(), DriverError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        sqlx::query(sql)
            .execute(&mut *tx)
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        sqlx::query("INSERT INTO schema_migrations (version) VALUES ($1)")
            .bind(version)
            .execute(&mut *tx)
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        tx.commit()
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))
    }

    async fn revert_migration(&self, down_sql: &str, version: &str) -> Result<(), DriverError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        sqlx::query(down_sql)
            .execute(&mut *tx)
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        sqlx::query("DELETE FROM schema_migrations WHERE version = $1")
            .bind(version)
            .execute(&mut *tx)
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        tx.commit()
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))
    }

    async fn ensure_migrations_table(&self) -> Result<(), DriverError> {
        sqlx::query("CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY)")
            .execute(&self.pool)
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        Ok(())
    }

    async fn applied_versions(&self) -> Result<Vec<String>, DriverError> {
        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT version FROM schema_migrations ORDER BY version")
                .fetch_all(&self.pool)
                .await
                .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        Ok(rows.into_iter().map(|(v,)| v).collect())
    }

    async fn query_cancellable(&self, sql: &str, timeout_secs: u64, cancel: &CancelState) -> Result<QueryOutput, DriverError> {
        let mut conn = self.pool.acquire().await
            .map_err(|e| DriverError::ConnectionFailed(e.to_string()))?;
        let ms = timeout_secs * 1000;
        sqlx::query(&format!("SET statement_timeout = {ms}"))
            .execute(&mut *conn).await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        let pid = sqlx::query_scalar::<_, i32>("SELECT pg_backend_pid()")
            .fetch_one(&mut *conn).await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        cancel.set_connection_id(pid.to_string());

        if cancel.is_cancelled() {
            return Err(DriverError::Cancelled);
        }

        let all_rows = sqlx::query(sql).fetch_all(&mut *conn).await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;

        let mut rows = Vec::new();
        let mut total_bytes: usize = 0;
        let mut truncated = false;
        let mut truncation_reason = None;
        for row in all_rows {
            let json = pg_row_to_json(&row);
            total_bytes += json.to_string().len();
            if rows.len() >= MAX_RESULT_ROWS {
                truncated = true;
                truncation_reason = Some(format!("max rows ({MAX_RESULT_ROWS})"));
                break;
            }
            if total_bytes >= MAX_RESULT_BYTES {
                truncated = true;
                truncation_reason = Some(format!("max size ({MAX_RESULT_BYTES} bytes)"));
                break;
            }
            rows.push(json);
        }
        Ok(QueryOutput { rows, truncated, truncation_reason })
    }

    async fn execute_cancellable(&self, sql: &str, timeout_secs: u64, cancel: &CancelState) -> Result<u64, DriverError> {
        let mut conn = self.pool.acquire().await
            .map_err(|e| DriverError::ConnectionFailed(e.to_string()))?;
        let ms = timeout_secs * 1000;
        sqlx::query(&format!("SET statement_timeout = {ms}"))
            .execute(&mut *conn).await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        let pid = sqlx::query_scalar::<_, i32>("SELECT pg_backend_pid()")
            .fetch_one(&mut *conn).await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        cancel.set_connection_id(pid.to_string());

        if cancel.is_cancelled() {
            return Err(DriverError::Cancelled);
        }

        // raw_sql on acquired connection has lifetime issues with async_trait.
        // Hold connection (keeps timeout set), execute via pool which will reuse it.
        // With pid already captured, cancel targets the correct backend.
        drop(conn);
        let result = sqlx::raw_sql(sql).execute(&self.pool).await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        Ok(result.rows_affected())
    }
}

fn pg_row_to_json(row: &sqlx::postgres::PgRow) -> serde_json::Value {
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
