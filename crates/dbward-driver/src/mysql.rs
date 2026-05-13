use futures::TryStreamExt;
use sqlx::{Column, Row, TypeInfo, ValueRef};

use crate::{
    CancelState, DatabaseDriver, DriverError, JsonMapping, MAX_RESULT_BYTES, MAX_RESULT_ROWS,
    QueryOutput, text_to_json,
};

pub struct MysqlDriver {
    pool: sqlx::MySqlPool,
}

impl MysqlDriver {
    pub async fn connect(
        url: &str,
        statement_timeout_secs: Option<u64>,
    ) -> Result<Self, DriverError> {
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
            .map_err(|e| DriverError::ConnectionFailed(e.to_string()))?;
        Ok(Self { pool })
    }
}

#[async_trait::async_trait]
impl DatabaseDriver for MysqlDriver {
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
            let json = mysql_row_to_json(&row);
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
        if !is_multi_statement(sql) {
            let result = sqlx::raw_sql(sql)
                .execute(&self.pool)
                .await
                .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
            return Ok(result.rows_affected());
        }

        // MySQL: wrap multi-statement in explicit transaction for atomicity
        let stmts = split_statements(sql);
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        let mut total_affected = 0u64;
        for stmt in &stmts {
            let r = sqlx::query(stmt)
                .execute(&mut *tx)
                .await
                .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
            total_affected += r.rows_affected();
        }
        tx.commit()
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        Ok(total_affected)
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
        sqlx::query("INSERT INTO schema_migrations (version) VALUES (?)")
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
        sqlx::query("DELETE FROM schema_migrations WHERE version = ?")
            .bind(version)
            .execute(&mut *tx)
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        tx.commit()
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))
    }

    async fn ensure_migrations_table(&self) -> Result<(), DriverError> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version VARCHAR(255) PRIMARY KEY)",
        )
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
    ) -> Result<QueryOutput, DriverError> {
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|e| DriverError::ConnectionFailed(e.to_string()))?;
        let ms = timeout_secs * 1000;
        sqlx::query(&format!("SET SESSION max_execution_time = {ms}"))
            .execute(&mut *conn)
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        let id = sqlx::query_scalar::<_, u64>("SELECT CONNECTION_ID()")
            .fetch_one(&mut *conn)
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        cancel.set_connection_id(id.to_string());

        if cancel.is_cancelled() {
            return Err(DriverError::Cancelled);
        }

        // Execute on same connection
        let mut stream = sqlx::raw_sql(sql).fetch(&mut *conn);
        let mut rows = Vec::new();
        let mut total_bytes: usize = 0;
        let mut truncated = false;
        let mut truncation_reason = None;

        while let Some(row) = stream
            .try_next()
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?
        {
            let json = mysql_row_to_json(&row);
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
        sqlx::query(&format!("SET SESSION max_execution_time = {ms}"))
            .execute(&mut *conn)
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        let id = sqlx::query_scalar::<_, u64>("SELECT CONNECTION_ID()")
            .fetch_one(&mut *conn)
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        cancel.set_connection_id(id.to_string());

        if cancel.is_cancelled() {
            return Err(DriverError::Cancelled);
        }

        let result = sqlx::query(sql)
            .execute(&mut *conn)
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        Ok(result.rows_affected())
    }
}

use sqlparser::dialect::MySqlDialect;
use sqlparser::parser::Parser;

fn is_multi_statement(sql: &str) -> bool {
    match Parser::parse_sql(&MySqlDialect {}, sql.trim()) {
        Ok(stmts) => stmts.len() > 1,
        Err(_) => false,
    }
}

fn split_statements(sql: &str) -> Vec<String> {
    match Parser::parse_sql(&MySqlDialect {}, sql.trim()) {
        Ok(stmts) if stmts.len() > 1 => stmts.iter().map(|s| s.to_string()).collect(),
        _ => vec![sql.to_string()],
    }
}

fn mysql_row_to_json(row: &sqlx::mysql::MySqlRow) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for col in row.columns() {
        let name = col.name();
        let raw = row
            .try_get_raw(col.ordinal())
            .expect("column ordinal from row.columns() must be valid");
        let val = if raw.is_null() {
            serde_json::Value::Null
        } else {
            match row.try_get::<Vec<u8>, _>(col.ordinal()) {
                Ok(bytes) => match std::str::from_utf8(&bytes) {
                    Ok(text) => text_to_json(text, mysql_type_mapping(col.type_info().name())),
                    Err(_) => serde_json::Value::String("(binary data)".into()),
                },
                Err(_) => serde_json::Value::String("(binary data)".into()),
            }
        };
        map.insert(name.to_string(), val);
    }
    serde_json::Value::Object(map)
}

fn mysql_type_mapping(type_name: &str) -> JsonMapping {
    match type_name {
        "TINYINT" | "TINYINT UNSIGNED" | "SMALLINT" | "SMALLINT UNSIGNED" | "INT"
        | "INT UNSIGNED" | "MEDIUMINT" | "MEDIUMINT UNSIGNED" | "BIGINT" | "BIGINT UNSIGNED" => {
            JsonMapping::Integer
        }
        "FLOAT" | "DOUBLE" => JsonMapping::Float,
        "BOOLEAN" => JsonMapping::Bool,
        "JSON" => JsonMapping::Json,
        "BLOB" | "BINARY" | "VARBINARY" | "LONGBLOB" | "MEDIUMBLOB" | "TINYBLOB" => {
            JsonMapping::Binary
        }
        _ => JsonMapping::Text,
    }
}
