use futures::TryStreamExt;
use sqlx::{Column, TypeInfo, ValueRef};
use std::time::Duration;

use crate::{
    CancelState, DatabaseDriver, DriverError, JsonMapping, MAX_RESULT_BYTES, MAX_RESULT_ROWS,
    QueryOutput, text_to_json,
};

pub struct MysqlDriver {
    pool: sqlx::MySqlPool,
    url: String,
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
            .map_err(classify_mysql_connect_error)?;
        Ok(Self {
            pool,
            url: url.to_owned(),
        })
    }
}

fn classify_mysql_connect_error(e: sqlx::Error) -> DriverError {
    if let sqlx::Error::Database(ref db_err) = e
        && let Some(code) = db_err.code()
        && code == "1045"
    {
        return DriverError::AuthenticationFailed(e.to_string());
    }
    DriverError::ConnectionFailed(e.to_string())
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
        let stmts = split_statements(sql);
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        for stmt in &stmts {
            sqlx::query(stmt)
                .execute(&mut *tx)
                .await
                .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        }
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
        let stmts = split_statements(down_sql);
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        for stmt in &stmts {
            sqlx::query(stmt)
                .execute(&mut *tx)
                .await
                .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        }
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
        max_rows: Option<usize>,
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

        // Execute on same connection with external timeout fallback
        let conn_id = id;
        let pool = self.pool.clone();
        let deadline = Duration::from_secs(timeout_secs + 5);

        let exec_result = tokio::time::timeout(deadline, async {
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
                let json = mysql_row_to_json(&row);
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
            Ok::<_, DriverError>(QueryOutput {
                rows,
                truncated,
                truncation_reason,
            })
        })
        .await;

        match exec_result {
            Ok(r) => r,
            Err(_) => {
                tokio::spawn(async move {
                    if let Ok(mut k) = pool.acquire().await {
                        let _ = sqlx::query(&format!("KILL {conn_id}"))
                            .execute(&mut *k)
                            .await;
                    }
                });
                Err(DriverError::QueryFailed(format!(
                    "query timed out after {timeout_secs}s"
                )))
            }
        }
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

        let conn_id = id;
        let pool = self.pool.clone();
        let deadline = Duration::from_secs(timeout_secs + 5);
        let is_multi = is_multi_statement(sql);
        let stmts = split_statements(sql);

        let exec_result = tokio::time::timeout(deadline, async move {
            if !is_multi {
                // Single statement or parse-failed: execute directly
                let r = sqlx::query(&stmts[0])
                    .execute(&mut *conn)
                    .await
                    .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
                return Ok::<_, DriverError>(r.rows_affected());
            }
            // Multi-statement: wrap in transaction for atomicity, sum rows_affected
            sqlx::query("BEGIN")
                .execute(&mut *conn)
                .await
                .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
            let mut total = 0u64;
            for stmt in &stmts {
                let r = match sqlx::query(stmt).execute(&mut *conn).await {
                    Ok(r) => r,
                    Err(e) => {
                        // Rollback on error to avoid leaking open transaction
                        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                        return Err(DriverError::QueryFailed(e.to_string()));
                    }
                };
                total += r.rows_affected();
            }
            sqlx::query("COMMIT")
                .execute(&mut *conn)
                .await
                .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
            Ok(total)
        })
        .await;

        match exec_result {
            Ok(r) => r,
            Err(_) => {
                tokio::spawn(async move {
                    if let Ok(mut k) = pool.acquire().await {
                        let _ = sqlx::query(&format!("KILL {conn_id}"))
                            .execute(&mut *k)
                            .await;
                    }
                });
                Err(DriverError::QueryFailed(format!(
                    "query timed out after {timeout_secs}s"
                )))
            }
        }
    }

    async fn cancel_query(&self, connection_id: &str) -> Result<bool, DriverError> {
        let conn_id: u64 = connection_id.parse().map_err(|_| {
            DriverError::QueryFailed(format!("invalid MySQL connection_id: {connection_id}"))
        })?;
        let cancel_pool = sqlx::mysql::MySqlPoolOptions::new()
            .max_connections(1)
            .connect(&self.url)
            .await
            .map_err(|e| DriverError::ConnectionFailed(e.to_string()))?;
        sqlx::query(&format!("KILL QUERY {conn_id}"))
            .execute(&cancel_pool)
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        cancel_pool.close().await;
        Ok(true)
    }

    async fn collect_schema(&self) -> Result<crate::SchemaSnapshot, DriverError> {
        use crate::schema::*;
        use sqlx::Row;

        let table_rows = sqlx::query(
            "SELECT table_name, table_rows FROM information_schema.tables \
             WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE'"
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| DriverError::QueryFailed(e.to_string()))?;

        let mut tables = Vec::new();
        for row in &table_rows {
            let name: String = row.get("table_name");
            let estimated_rows: i64 = row.get::<Option<i64>, _>("table_rows").unwrap_or(0);

            let col_rows = sqlx::query(
                "SELECT column_name, data_type, is_nullable, column_default, column_key \
                 FROM information_schema.columns \
                 WHERE table_schema = DATABASE() AND table_name = ? \
                 ORDER BY ordinal_position"
            )
            .bind(&name)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;

            let columns: Vec<ColumnInfo> = col_rows.iter().map(|r| {
                let key: String = r.get::<Option<String>, _>("column_key").unwrap_or_default();
                ColumnInfo {
                    name: r.get("column_name"),
                    data_type: r.get("data_type"),
                    nullable: r.get::<String, _>("is_nullable") == "YES",
                    default_value: r.get("column_default"),
                    is_primary_key: key == "PRI",
                }
            }).collect();

            let fk_rows = sqlx::query(
                "SELECT kcu.constraint_name, kcu.column_name, \
                        kcu.referenced_table_name, kcu.referenced_column_name, \
                        rc.delete_rule \
                 FROM information_schema.key_column_usage kcu \
                 JOIN information_schema.referential_constraints rc \
                   ON kcu.constraint_name = rc.constraint_name AND kcu.constraint_schema = rc.constraint_schema \
                 WHERE kcu.table_schema = DATABASE() AND kcu.table_name = ? \
                   AND kcu.referenced_table_name IS NOT NULL"
            )
            .bind(&name)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;

            let mut constraints: Vec<ConstraintInfo> = Vec::new();
            for r in &fk_rows {
                let cname: String = r.get("constraint_name");
                let col: String = r.get("column_name");
                let ref_table: Option<String> = r.get("referenced_table_name");
                let ref_col: Option<String> = r.get("referenced_column_name");
                let delete_rule: Option<String> = r.get("delete_rule");

                if let Some(existing) = constraints.iter_mut().find(|c| c.name == cname) {
                    if !existing.columns.contains(&col) { existing.columns.push(col); }
                } else {
                    constraints.push(ConstraintInfo {
                        name: cname,
                        constraint_type: ConstraintType::ForeignKey,
                        columns: vec![col],
                        referenced_table: ref_table,
                        referenced_columns: ref_col.map(|c| vec![c]),
                        on_delete: delete_rule.and_then(|r| match r.as_str() {
                            "CASCADE" => Some(FkAction::Cascade),
                            "SET NULL" => Some(FkAction::SetNull),
                            "RESTRICT" => Some(FkAction::Restrict),
                            _ => Some(FkAction::NoAction),
                        }),
                    });
                }
            }

            tables.push(TableInfo {
                name,
                schema_name: String::new(),
                estimated_rows,
                columns,
                constraints,
                indexes: vec![],
            });
        }

        Ok(SchemaSnapshot { tables })
    }

    async fn explain(&self, sql: &str, timeout_secs: u64) -> Result<serde_json::Value, DriverError> {
        use sqlx::{Connection, Row};
        // Use dedicated connection to avoid session pollution
        let mut conn = sqlx::MySqlConnection::connect(&self.url).await
            .map_err(|e| DriverError::ConnectionFailed(e.to_string()))?;
        let ms = timeout_secs * 1000;
        sqlx::query(&format!("SET max_execution_time = {ms}"))
            .execute(&mut conn)
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        let explain_sql = format!("EXPLAIN FORMAT=JSON {sql}");
        let row = sqlx::query(&explain_sql)
            .fetch_one(&mut conn)
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        let plan: String = row.try_get(0)
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        serde_json::from_str(&plan)
            .map_err(|e| DriverError::QueryFailed(format!("invalid EXPLAIN JSON: {e}")))
    }

    fn dialect(&self) -> &'static str {
        "mysql"
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
    use sqlx::Row;
    let mut map = serde_json::Map::new();
    for col in row.columns() {
        let name = col.name();
        let raw = row
            .try_get_raw(col.ordinal())
            .expect("column ordinal from row.columns() must be valid");
        let val = if raw.is_null() {
            serde_json::Value::Null
        } else {
            // try_get_unchecked bypasses sqlx's type compatibility check.
            // MySQL text protocol (COM_QUERY via raw_sql) sends all values as UTF-8
            // strings regardless of column type. sqlx's checked Decode<String> rejects
            // non-TEXT types, so we bypass the check to access the raw string value.
            let text: Result<String, _> = row.try_get_unchecked(col.ordinal());
            match text {
                Ok(s) => text_to_json(&s, mysql_type_mapping(col.type_info().name())),
                Err(_) => {
                    // Raw binary bytes — hex encode with \x prefix
                    let bytes: Vec<u8> = row
                        .try_get_unchecked::<Vec<u8>, _>(col.ordinal())
                        .unwrap_or_default();
                    serde_json::Value::String(format!("\\x{}", hex::encode(&bytes)))
                }
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
