use futures::TryStreamExt;
use sqlx::{Column, TypeInfo, ValueRef};
use std::time::Duration;

use crate::{MigrationDriver, QueryDriver, SchemaDriver};

use crate::common::{conn_err, query_err};
use crate::{
    CancelState, DatabaseDriver, DriverError, JsonMapping, MAX_RESULT_ROWS, QueryOutput,
    text_to_json,
};

fn contains_ddl(stmts: &[String]) -> bool {
    stmts.iter().any(|s| {
        let upper = s.trim_start().to_uppercase();
        upper.starts_with("CREATE ")
            || upper.starts_with("ALTER ")
            || upper.starts_with("DROP ")
            || upper.starts_with("TRUNCATE ")
            || upper.starts_with("RENAME ")
    })
}

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

    /// Best-effort KILL via a fresh connection (avoids pool saturation).
    /// Uses KILL (not KILL QUERY) to fully terminate the connection for migrations.
    async fn kill_connection(&self, conn_id: u64) {
        let kill_result = async {
            let kill_pool = sqlx::mysql::MySqlPoolOptions::new()
                .max_connections(1)
                .connect(&self.url)
                .await
                .map_err(|e| e.to_string())?;
            sqlx::query(&format!("KILL {conn_id}"))
                .execute(&kill_pool)
                .await
                .map_err(|e| e.to_string())?;
            kill_pool.close().await;
            Ok::<(), String>(())
        };
        match tokio::time::timeout(Duration::from_secs(5), kill_result).await {
            Ok(Ok(())) => {
                tracing::warn!(conn_id, "migration timed out, connection killed");
            }
            Ok(Err(e)) => {
                tracing::error!(
                    conn_id, error = %e,
                    "migration timed out but KILL failed; connection may still be running"
                );
            }
            Err(_) => {
                tracing::error!(
                    conn_id,
                    "migration timed out and KILL itself timed out; connection may still be running"
                );
            }
        }
    }

    /// Shared implementation for apply/revert migration with timeout + KILL.
    async fn run_migration_tx(
        &self,
        stmts: &[String],
        version_sql: &str,
        version: &str,
        timeout_secs: u64,
    ) -> Result<(), DriverError> {
        if contains_ddl(stmts) {
            tracing::warn!(
                version,
                "migration contains DDL; MySQL implicit commit means \
                 transaction atomicity is not guaranteed for this migration"
            );
        }

        let mut tx = self.pool.begin().await.map_err(query_err)?;
        let conn_id: u64 = sqlx::query_scalar("SELECT CONNECTION_ID()")
            .fetch_one(&mut *tx)
            .await
            .map_err(query_err)?;

        let exec = async {
            for stmt in stmts {
                sqlx::query(stmt)
                    .execute(&mut *tx)
                    .await
                    .map_err(query_err)?;
            }
            sqlx::query(version_sql)
                .bind(version)
                .execute(&mut *tx)
                .await
                .map_err(query_err)?;
            tx.commit().await.map_err(query_err)?;
            Ok::<(), DriverError>(())
        };

        if timeout_secs == 0 {
            return exec.await;
        }

        match tokio::time::timeout(Duration::from_secs(timeout_secs), exec).await {
            Ok(result) => result,
            Err(_) => {
                self.kill_connection(conn_id).await;
                Err(DriverError::MigrationTimeout {
                    version: version.to_owned(),
                    message: format!(
                        "migration timed out after {timeout_secs}s. Schema state is unknown. \
                         Manual inspection required before running further migrations."
                    ),
                })
            }
        }
    }
}

fn classify_mysql_connect_error(e: sqlx::Error) -> DriverError {
    crate::common::classify_connect_error(e, &["1045"])
}

#[async_trait::async_trait]
impl QueryDriver for MysqlDriver {
    async fn query_cancellable(
        &self,
        sql: &str,
        timeout_secs: u64,
        cancel: &CancelState,
        max_rows: Option<usize>,
    ) -> Result<QueryOutput, DriverError> {
        let conn = self.pool.acquire().await.map_err(conn_err)?;
        let mut guard = crate::guard::CancellationGuard::new(conn);

        let id = sqlx::query_scalar::<_, u64>("SELECT CONNECTION_ID()")
            .fetch_one(&mut **guard.conn_mut())
            .await
            .map_err(query_err)?;
        cancel.set_connection_id(id.to_string());

        if cancel.is_cancelled() {
            guard.release();
            return Err(DriverError::Cancelled);
        }

        let ms = timeout_secs * 1000;
        sqlx::query(&format!("SET SESSION max_execution_time = {ms}"))
            .execute(&mut **guard.conn_mut())
            .await
            .map_err(query_err)?;

        // MySQL prepared protocol does not support BEGIN/START TRANSACTION
        // Use SET TRANSACTION READ ONLY + SET autocommit=0 instead
        sqlx::query("SET TRANSACTION READ ONLY")
            .execute(&mut **guard.conn_mut())
            .await
            .map_err(query_err)?;
        sqlx::query("SET autocommit = 0")
            .execute(&mut **guard.conn_mut())
            .await
            .map_err(query_err)?;

        let conn_id = id;
        let url = self.url.clone();
        let deadline = Duration::from_secs(timeout_secs + 5);

        let exec_result = tokio::time::timeout(deadline, async {
            let mut stream = sqlx::raw_sql(sql).fetch(&mut **guard.conn_mut());
            let effective_max_rows = max_rows.unwrap_or(MAX_RESULT_ROWS).min(MAX_RESULT_ROWS);
            let mut collector = crate::common::RowCollector::new(Some(effective_max_rows));

            while let Some(row) = stream.try_next().await.map_err(query_err)? {
                if collector.push(mysql_row_to_json(&row)) {
                    break;
                }
            }
            Ok::<_, DriverError>(collector.finish())
        })
        .await;

        match exec_result {
            Ok(result) => {
                let cleanup_ok = sqlx::query("ROLLBACK")
                    .execute(&mut **guard.conn_mut())
                    .await
                    .is_ok()
                    && sqlx::query("SET autocommit = 1")
                        .execute(&mut **guard.conn_mut())
                        .await
                        .is_ok()
                    && sqlx::query("SET SESSION max_execution_time = 0")
                        .execute(&mut **guard.conn_mut())
                        .await
                        .is_ok();
                if cleanup_ok {
                    guard.release();
                }
                // else: guard drops → detach (connection destroyed)
                result
            }
            Err(_) => {
                // Timeout: guard drops → conn detached. KILL via dedicated connection.
                drop(guard);
                tokio::spawn(async move {
                    let kill_result = async {
                        let kill_pool = sqlx::mysql::MySqlPoolOptions::new()
                            .max_connections(1)
                            .connect(&url)
                            .await?;
                        sqlx::query(&format!("KILL {conn_id}"))
                            .execute(&kill_pool)
                            .await?;
                        kill_pool.close().await;
                        Ok::<(), sqlx::Error>(())
                    };
                    let _ = tokio::time::timeout(Duration::from_secs(5), kill_result).await;
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
        let conn = self.pool.acquire().await.map_err(conn_err)?;
        let mut guard = crate::guard::CancellationGuard::new(conn);

        let id = sqlx::query_scalar::<_, u64>("SELECT CONNECTION_ID()")
            .fetch_one(&mut **guard.conn_mut())
            .await
            .map_err(query_err)?;
        cancel.set_connection_id(id.to_string());

        if cancel.is_cancelled() {
            guard.release();
            return Err(DriverError::Cancelled);
        }

        let ms = timeout_secs * 1000;
        sqlx::query(&format!("SET SESSION max_execution_time = {ms}"))
            .execute(&mut **guard.conn_mut())
            .await
            .map_err(query_err)?;

        let conn_id = id;
        let url = self.url.clone();
        let deadline = Duration::from_secs(timeout_secs + 5);
        let is_multi = is_multi_statement(sql);
        let stmts = split_statements(sql);

        let exec_result = tokio::time::timeout(deadline, async {
            if !is_multi {
                let r = sqlx::query(&stmts[0])
                    .execute(&mut **guard.conn_mut())
                    .await
                    .map_err(query_err)?;
                return Ok::<_, DriverError>(r.rows_affected());
            }
            sqlx::query("SET autocommit = 0")
                .execute(&mut **guard.conn_mut())
                .await
                .map_err(query_err)?;
            let mut total = 0u64;
            for stmt in &stmts {
                let r = match sqlx::query(stmt).execute(&mut **guard.conn_mut()).await {
                    Ok(r) => r,
                    Err(e) => {
                        if let Err(re) = sqlx::query("ROLLBACK")
                            .execute(&mut **guard.conn_mut())
                            .await
                        {
                            tracing::debug!(error = %re, "ROLLBACK failed after migration error");
                        }
                        return Err(query_err(e));
                    }
                };
                total += r.rows_affected();
            }
            sqlx::query("COMMIT")
                .execute(&mut **guard.conn_mut())
                .await
                .map_err(query_err)?;
            Ok(total)
        })
        .await;

        match exec_result {
            Ok(result) => {
                let cleanup_ok = sqlx::query("ROLLBACK")
                    .execute(&mut **guard.conn_mut())
                    .await
                    .is_ok()
                    && sqlx::query("SET autocommit = 1")
                        .execute(&mut **guard.conn_mut())
                        .await
                        .is_ok()
                    && sqlx::query("SET SESSION max_execution_time = 0")
                        .execute(&mut **guard.conn_mut())
                        .await
                        .is_ok();
                if cleanup_ok {
                    guard.release();
                }
                result
            }
            Err(_) => {
                // Timeout: guard drops → conn detached. KILL via dedicated connection.
                drop(guard);
                tokio::spawn(async move {
                    let kill_result = async {
                        let kill_pool = sqlx::mysql::MySqlPoolOptions::new()
                            .max_connections(1)
                            .connect(&url)
                            .await?;
                        sqlx::query(&format!("KILL {conn_id}"))
                            .execute(&kill_pool)
                            .await?;
                        kill_pool.close().await;
                        Ok::<(), sqlx::Error>(())
                    };
                    let _ = tokio::time::timeout(Duration::from_secs(5), kill_result).await;
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
            .map_err(conn_err)?;
        sqlx::query(&format!("KILL QUERY {conn_id}"))
            .execute(&cancel_pool)
            .await
            .map_err(query_err)?;
        cancel_pool.close().await;
        Ok(true)
    }

    fn dialect(&self) -> &'static str {
        "mysql"
    }
}

#[async_trait::async_trait]
impl MigrationDriver for MysqlDriver {
    async fn apply_migration(
        &self,
        sql: &str,
        version: &str,
        timeout_secs: u64,
    ) -> Result<(), DriverError> {
        let stmts = split_statements(sql);
        self.run_migration_tx(
            &stmts,
            "INSERT INTO schema_migrations (version) VALUES (?)",
            version,
            timeout_secs,
        )
        .await
    }

    async fn revert_migration(
        &self,
        down_sql: &str,
        version: &str,
        timeout_secs: u64,
    ) -> Result<(), DriverError> {
        let stmts = split_statements(down_sql);
        self.run_migration_tx(
            &stmts,
            "DELETE FROM schema_migrations WHERE version = ?",
            version,
            timeout_secs,
        )
        .await
    }

    async fn apply_migration_no_tx(
        &self,
        _sql: &str,
        _version: &str,
        _timeout_secs: u64,
    ) -> Result<(), DriverError> {
        Err(DriverError::QueryFailed(
            "non-transactional migrations are not supported for MySQL".into(),
        ))
    }

    async fn revert_migration_no_tx(
        &self,
        _down_sql: &str,
        _version: &str,
        _timeout_secs: u64,
    ) -> Result<(), DriverError> {
        Err(DriverError::QueryFailed(
            "non-transactional migrations are not supported for MySQL".into(),
        ))
    }

    async fn ensure_migrations_table(&self) -> Result<(), DriverError> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version VARCHAR(255) PRIMARY KEY)",
        )
        .execute(&self.pool)
        .await
        .map_err(query_err)?;
        Ok(())
    }

    async fn applied_versions(&self) -> Result<Vec<String>, DriverError> {
        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT version FROM schema_migrations ORDER BY version")
                .fetch_all(&self.pool)
                .await
                .map_err(query_err)?;
        Ok(rows.into_iter().map(|(v,)| v).collect())
    }

    async fn mark_applied(&self, version: &str) -> Result<(), DriverError> {
        sqlx::query("INSERT IGNORE INTO schema_migrations (version) VALUES (?)")
            .bind(version)
            .execute(&self.pool)
            .await
            .map_err(query_err)?;
        Ok(())
    }

    async fn remove_version(&self, version: &str) -> Result<(), DriverError> {
        sqlx::query("DELETE FROM schema_migrations WHERE version = ?")
            .bind(version)
            .execute(&self.pool)
            .await
            .map_err(query_err)?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl SchemaDriver for MysqlDriver {
    async fn collect_schema(&self) -> Result<crate::SchemaSnapshot, DriverError> {
        use crate::schema::*;
        use sqlx::Row;

        // MySQL 8.0 information_schema may return VARBINARY for string columns
        fn get_str(row: &sqlx::mysql::MySqlRow, idx: usize) -> String {
            row.try_get::<String, _>(idx)
                .or_else(|_| {
                    row.try_get::<Vec<u8>, _>(idx)
                        .map(|v| String::from_utf8_lossy(&v).into_owned())
                })
                .unwrap_or_else(|e| {
                    tracing::warn!(column_idx = idx, error = %e, "MySQL column decode fallback to empty");
                    String::new()
                })
        }
        fn get_opt_str(row: &sqlx::mysql::MySqlRow, idx: usize) -> Option<String> {
            row.try_get::<Option<String>, _>(idx)
                .ok()
                .flatten()
                .or_else(|| {
                    row.try_get::<Option<Vec<u8>>, _>(idx)
                        .ok()
                        .flatten()
                        .map(|v| String::from_utf8_lossy(&v).into_owned())
                })
        }

        let table_rows = sqlx::query(
            "SELECT table_name, table_rows FROM information_schema.tables \
             WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE'",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(query_err)?;

        let mut tables = Vec::new();
        for row in &table_rows {
            let name: String = get_str(row, 0);
            let estimated_rows: i64 = row
                .try_get::<Option<i64>, _>(1)
                .unwrap_or(None)
                .unwrap_or(0);

            let col_rows = sqlx::query(
                "SELECT column_name, data_type, is_nullable, column_default, column_key \
                 FROM information_schema.columns \
                 WHERE table_schema = DATABASE() AND table_name = ? \
                 ORDER BY ordinal_position",
            )
            .bind(&name)
            .fetch_all(&self.pool)
            .await
            .map_err(query_err)?;

            let columns: Vec<ColumnInfo> = col_rows
                .iter()
                .map(|r| {
                    let key = get_str(r, 4);
                    ColumnInfo {
                        name: get_str(r, 0),
                        data_type: get_str(r, 1),
                        nullable: get_str(r, 2) == "YES",
                        default_value: get_opt_str(r, 3),
                        is_primary_key: key == "PRI",
                    }
                })
                .collect();

            let fk_rows = sqlx::query(
                "SELECT kcu.constraint_name, kcu.column_name, \
                        kcu.referenced_table_name, kcu.referenced_column_name, \
                        rc.delete_rule \
                 FROM information_schema.key_column_usage kcu \
                 JOIN information_schema.referential_constraints rc \
                   ON kcu.constraint_name = rc.constraint_name AND kcu.constraint_schema = rc.constraint_schema \
                 WHERE kcu.table_schema = DATABASE() AND kcu.table_name = ? \
                   AND kcu.referenced_table_name IS NOT NULL \
                 ORDER BY kcu.constraint_name, kcu.ordinal_position"
            )
            .bind(&name)
            .fetch_all(&self.pool)
            .await
            .map_err(query_err)?;

            let mut constraints: Vec<ConstraintInfo> = Vec::new();
            for r in &fk_rows {
                let cname = get_str(r, 0);
                let col = get_str(r, 1);
                let ref_table = get_opt_str(r, 2);
                let ref_col = get_opt_str(r, 3);
                let delete_rule = get_opt_str(r, 4);

                if let Some(existing) = constraints.iter_mut().find(|c| c.name == cname) {
                    if !existing.columns.contains(&col) {
                        existing.columns.push(col);
                    }
                    if let Some(rc) = ref_col
                        && let Some(ref mut refs) = existing.referenced_columns
                        && !refs.contains(&rc)
                    {
                        refs.push(rc);
                    }
                } else {
                    constraints.push(ConstraintInfo {
                        name: cname,
                        constraint_type: ConstraintType::ForeignKey,
                        columns: vec![col],
                        referenced_table: ref_table,
                        referenced_columns: ref_col.map(|c| vec![c]),
                        on_delete: delete_rule.map(|r| match r.as_str() {
                            "CASCADE" => FkAction::Cascade,
                            "SET NULL" => FkAction::SetNull,
                            "RESTRICT" => FkAction::Restrict,
                            _ => FkAction::NoAction,
                        }),
                    });
                }
            }

            // Indexes
            let idx_rows = sqlx::query(
                "SELECT INDEX_NAME, COLUMN_NAME, NON_UNIQUE FROM information_schema.STATISTICS \
                 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? ORDER BY INDEX_NAME, SEQ_IN_INDEX"
            )
            .bind(&name)
            .fetch_all(&self.pool)
            .await
            .unwrap_or_default();

            let mut indexes: Vec<IndexInfo> = Vec::new();
            for r in &idx_rows {
                let idx_name = get_str(r, 0);
                let col = get_str(r, 1);
                let non_unique: i32 = r.try_get(2).unwrap_or(1);
                if let Some(existing) = indexes.iter_mut().find(|i| i.name == idx_name) {
                    existing.columns.push(col);
                } else {
                    indexes.push(IndexInfo {
                        name: idx_name,
                        columns: vec![col],
                        is_unique: non_unique == 0,
                        index_type: "btree".into(),
                    });
                }
            }

            tables.push(TableInfo {
                name,
                schema_name: String::new(),
                estimated_rows,
                columns,
                constraints,
                indexes,
            });
        }

        Ok(SchemaSnapshot { tables })
    }

    async fn explain(
        &self,
        sql: &str,
        timeout_secs: u64,
    ) -> Result<serde_json::Value, DriverError> {
        use sqlx::{Connection, Row};
        // Use dedicated connection to avoid session pollution
        let mut conn = sqlx::MySqlConnection::connect(&self.url)
            .await
            .map_err(conn_err)?;
        let ms = timeout_secs * 1000;
        sqlx::query(&format!("SET max_execution_time = {ms}"))
            .execute(&mut conn)
            .await
            .map_err(query_err)?;
        // MySQL prepared protocol does not support START TRANSACTION — split into two stmts
        sqlx::query("SET TRANSACTION READ ONLY")
            .execute(&mut conn)
            .await
            .map_err(query_err)?;
        sqlx::query("SET autocommit = 0")
            .execute(&mut conn)
            .await
            .map_err(query_err)?;
        let explain_sql = format!("EXPLAIN FORMAT=JSON {sql}");
        let result = sqlx::query(&explain_sql)
            .fetch_one(&mut conn)
            .await
            .map_err(query_err);
        if let Err(e) = sqlx::query("ROLLBACK").execute(&mut conn).await {
            tracing::debug!(error = %e, "ROLLBACK failed after EXPLAIN, dropping connection");
            drop(conn);
        }
        let row = result?;
        let plan: String = row.try_get(0).map_err(query_err)?;
        serde_json::from_str(&plan)
            .map_err(|e| DriverError::QueryFailed(format!("invalid EXPLAIN JSON: {e}")))
    }
}

#[async_trait::async_trait]
impl DatabaseDriver for MysqlDriver {}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contains_ddl_detects_create() {
        assert!(contains_ddl(&["CREATE TABLE foo (id INT)".into()]));
    }

    #[test]
    fn contains_ddl_detects_alter() {
        assert!(contains_ddl(&["ALTER TABLE foo ADD COLUMN bar INT".into()]));
    }

    #[test]
    fn contains_ddl_detects_drop() {
        assert!(contains_ddl(&["DROP TABLE foo".into()]));
    }

    #[test]
    fn contains_ddl_detects_truncate() {
        assert!(contains_ddl(&["TRUNCATE TABLE foo".into()]));
    }

    #[test]
    fn contains_ddl_detects_rename() {
        assert!(contains_ddl(&["RENAME TABLE foo TO bar".into()]));
    }

    #[test]
    fn contains_ddl_ignores_dml() {
        assert!(!contains_ddl(&["INSERT INTO foo VALUES (1)".into()]));
        assert!(!contains_ddl(&["UPDATE foo SET bar = 1".into()]));
        assert!(!contains_ddl(&["SELECT 1".into()]));
    }

    #[test]
    fn contains_ddl_case_insensitive() {
        assert!(contains_ddl(&["create table foo (id int)".into()]));
        assert!(contains_ddl(&["  ALTER TABLE foo DROP COLUMN bar".into()]));
    }
}
