use futures::TryStreamExt;
use sqlx::postgres::{PgTypeInfo, PgTypeKind};
use sqlx::{Column, Row, TypeInfo, ValueRef};

use crate::{
    CancelState, ColumnMapping, DatabaseDriver, DriverError, JsonMapping, MAX_RESULT_BYTES,
    MAX_RESULT_ROWS, QueryOutput, pg_array::parse_pg_array, text_to_json,
};

pub struct PostgresDriver {
    pool: sqlx::PgPool,
    url: String,
}

impl PostgresDriver {
    pub async fn connect(
        url: &str,
        statement_timeout_secs: Option<u64>,
    ) -> Result<Self, DriverError> {
        let opts = sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .after_connect(move |conn, _meta| {
                Box::pin(async move {
                    sqlx::query("SET bytea_output = 'hex'")
                        .execute(&mut *conn)
                        .await?;
                    if let Some(secs) = statement_timeout_secs {
                        sqlx::query(&format!("SET statement_timeout = '{secs}s'"))
                            .execute(&mut *conn)
                            .await?;
                    }
                    Ok(())
                })
            });
        let pool = opts.connect(url).await.map_err(classify_connect_error)?;
        Ok(Self { pool, url: url.to_owned() })
    }
}

fn classify_connect_error(e: sqlx::Error) -> DriverError {
    if let sqlx::Error::Database(ref db_err) = e
        && let Some(code) = db_err.code()
        && (code == "28P01" || code == "28000")
    {
        return DriverError::AuthenticationFailed(e.to_string());
    }
    DriverError::ConnectionFailed(e.to_string())
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
        // Version comes from migration filename; reject unsafe characters defensively
        if version.contains('\'') || version.contains(';') {
            return Err(DriverError::QueryFailed("invalid migration version".into()));
        }
        // Combine migration SQL + version record in a single raw_sql batch for atomicity
        let batch =
            format!("{sql}\n;\nINSERT INTO schema_migrations (version) VALUES ('{version}');");
        sqlx::raw_sql(&batch)
            .execute(&self.pool)
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        Ok(())
    }

    async fn revert_migration(&self, down_sql: &str, version: &str) -> Result<(), DriverError> {
        if version.contains('\'') || version.contains(';') {
            return Err(DriverError::QueryFailed("invalid migration version".into()));
        }
        let batch =
            format!("{down_sql}\n;\nDELETE FROM schema_migrations WHERE version = '{version}';");
        sqlx::raw_sql(&batch)
            .execute(&self.pool)
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        Ok(())
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

    async fn query_cancellable(
        &self,
        sql: &str,
        timeout_secs: u64,
        cancel: &CancelState,
        max_rows: Option<usize>,
    ) -> Result<QueryOutput, DriverError> {
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|e| DriverError::ConnectionFailed(e.to_string()))?;
        let ms = timeout_secs * 1000;
        sqlx::query(&format!("SET statement_timeout = {ms}"))
            .execute(&mut *conn)
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        let pid = sqlx::query_scalar::<_, i32>("SELECT pg_backend_pid()")
            .fetch_one(&mut *conn)
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        cancel.set_connection_id(pid.to_string());

        if cancel.is_cancelled() {
            return Err(DriverError::Cancelled);
        }

        let mut stream = sqlx::raw_sql(sql).fetch(&mut *conn);
        let mut rows = Vec::new();
        let mut total_bytes: usize = 0;
        let mut truncated = false;
        let mut truncation_reason = None;
        let effective_max_rows = max_rows.unwrap_or(MAX_RESULT_ROWS).min(MAX_RESULT_ROWS);

        while let Some(row) = stream
            .try_next()
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?
        {
            let json = pg_row_to_json(&row);
            total_bytes += json.to_string().len();
            if rows.len() >= effective_max_rows {
                truncated = true;
                truncation_reason = Some(format!("max rows ({effective_max_rows})"));
                break;
            }
            if total_bytes >= MAX_RESULT_BYTES {
                truncated = true;
                truncation_reason = Some(format!("max size ({MAX_RESULT_BYTES} bytes)"));
                break;
            }
            rows.push(json);
        }
        Ok(QueryOutput {
            rows,
            truncated,
            truncation_reason,
        })
    }

    async fn execute_cancellable(
        &self,
        sql: &str,
        timeout_secs: u64,
        cancel: &CancelState,
    ) -> Result<u64, DriverError> {
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|e| DriverError::ConnectionFailed(e.to_string()))?;
        let ms = timeout_secs * 1000;
        sqlx::query(&format!("SET statement_timeout = {ms}"))
            .execute(&mut *conn)
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        let pid = sqlx::query_scalar::<_, i32>("SELECT pg_backend_pid()")
            .fetch_one(&mut *conn)
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        cancel.set_connection_id(pid.to_string());

        if cancel.is_cancelled() {
            return Err(DriverError::Cancelled);
        }

        // Use raw_sql + fetch_many to support multi-statement and sum rows_affected
        let mut stream = sqlx::raw_sql(sql).fetch_many(&mut *conn);
        let mut total_affected = 0u64;
        while let Some(either) = stream
            .try_next()
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?
        {
            if let sqlx::Either::Left(result) = either {
                total_affected += result.rows_affected();
            }
        }
        Ok(total_affected)
    }

    async fn cancel_query(&self, connection_id: &str) -> Result<bool, DriverError> {
        let pid: i32 = connection_id
            .parse()
            .map_err(|_| DriverError::QueryFailed(format!("invalid PG pid: {connection_id}")))?;
        let cancel_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&self.url)
            .await
            .map_err(|e| DriverError::ConnectionFailed(e.to_string()))?;
        let cancelled: bool =
            sqlx::query_scalar(&format!("SELECT pg_cancel_backend({pid})"))
                .fetch_one(&cancel_pool)
                .await
                .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        cancel_pool.close().await;
        Ok(cancelled)
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
                Ok(text) => {
                    let type_info: &PgTypeInfo = col.type_info();
                    match pg_column_mapping(type_info) {
                        ColumnMapping::Scalar(m) => text_to_json(text, m),
                        ColumnMapping::Array(elem_m) => parse_pg_array(text, elem_m)
                            .unwrap_or_else(|_| serde_json::Value::String(text.to_owned())),
                    }
                }
                Err(_) => {
                    // Raw binary bytes — hex encode with \x prefix
                    let bytes: &[u8] = raw.as_bytes().unwrap_or(b"");
                    serde_json::Value::String(format!("\\x{}", hex::encode(bytes)))
                }
            }
        };
        map.insert(name.to_string(), val);
    }
    serde_json::Value::Object(map)
}

fn pg_column_mapping(type_info: &PgTypeInfo) -> ColumnMapping {
    resolve_type(type_info)
}

fn resolve_type(ti: &PgTypeInfo) -> ColumnMapping {
    match ti.kind() {
        PgTypeKind::Array(elem_ti) => ColumnMapping::Array(resolve_scalar(elem_ti)),
        PgTypeKind::Domain(inner_ti) => resolve_type(inner_ti),
        _ => ColumnMapping::Scalar(resolve_scalar(ti)),
    }
}

fn resolve_scalar(ti: &PgTypeInfo) -> JsonMapping {
    match ti.kind() {
        PgTypeKind::Domain(inner) => resolve_scalar(inner),
        _ => scalar_json_mapping(ti.name()),
    }
}

fn scalar_json_mapping(name: &str) -> JsonMapping {
    match name {
        "INT2" | "INT4" | "INT8" => JsonMapping::Integer,
        "FLOAT4" | "FLOAT8" => JsonMapping::Float,
        "BOOL" => JsonMapping::Bool,
        "JSON" | "JSONB" => JsonMapping::Json,
        "BYTEA" => JsonMapping::Binary,
        _ => JsonMapping::Text,
    }
}
