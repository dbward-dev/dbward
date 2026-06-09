use futures::TryStreamExt;
use sqlx::postgres::{PgTypeInfo, PgTypeKind};
use sqlx::{Column, Row, TypeInfo, ValueRef};

use crate::{
    CancelState, ColumnMapping, DatabaseDriver, DriverError, JsonMapping, MAX_RESULT_BYTES,
    MAX_RESULT_ROWS, QueryOutput, pg_array::parse_pg_array, text_to_json,
};

/// Reject migration version strings containing characters that could escape
/// the SQL string literal used in `format!("...VALUES ('{version}')...")`.
/// Specific to PostgreSQL's raw_sql batch approach.
use crate::common::validate_migration_version;
use crate::common::{conn_err, query_err};

/// Check if SQL contains multiple statements (semicolon followed by non-whitespace).
fn has_multiple_statements(sql: &str) -> bool {
    let mut found_semi = false;
    for ch in sql.trim().chars() {
        if ch == ';' {
            found_semi = true;
        } else if found_semi && !ch.is_whitespace() {
            return true;
        }
    }
    false
}

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
        Ok(Self {
            pool,
            url: url.to_owned(),
        })
    }

    /// Shared logic for non-transactional migration (apply or revert).
    /// Acquires a connection, sets timeout, executes SQL, records version, restores timeout.
    async fn run_no_tx_migration(
        &self,
        sql: &str,
        version_sql: &str,
        version: &str,
        partial_error_prefix: &str,
        repair_action: &str,
        timeout_secs: u64,
    ) -> Result<(), DriverError> {
        let mut conn = self.pool.acquire().await.map_err(conn_err)?;
        let original_timeout = if timeout_secs > 0 {
            let row: (String,) = sqlx::query_as("SHOW statement_timeout")
                .fetch_one(&mut *conn)
                .await
                .map_err(query_err)?;
            let ms = timeout_secs * 1000;
            sqlx::query(&format!("SET statement_timeout = {ms}"))
                .execute(&mut *conn)
                .await
                .map_err(query_err)?;
            Some(row.0)
        } else {
            None
        };
        let migration_result = sqlx::query(sql).execute(&mut *conn).await.map_err(|e| {
            let msg = e.to_string();
            if msg.contains("statement timeout") {
                DriverError::MigrationTimeout {
                    version: version.to_owned(),
                    message: "migration timed out (statement_timeout). Schema state may be \
                             partially applied. Manual inspection required before running \
                             further migrations."
                        .to_string(),
                }
            } else {
                DriverError::QueryFailed(msg)
            }
        });
        let result = match migration_result {
            Ok(_) => sqlx::query(version_sql)
                .execute(&mut *conn)
                .await
                .map_err(|e| DriverError::PartialMigration {
                    version: version.to_owned(),
                    message: format!(
                        "{partial_error_prefix}: {e}. \
                         Run `dbward migrate repair --emergency --action {repair_action} --version {version} --reason <reason>` to fix \
                         (metadata only — does not modify actual schema)."
                    ),
                })
                .map(|_| ()),
            Err(e) => Err(e),
        };
        if let Some(ref orig) = original_timeout {
            let _ = sqlx::query(&format!("SET statement_timeout = '{orig}'"))
                .execute(&mut *conn)
                .await;
        }
        result
    }
}

fn classify_connect_error(e: sqlx::Error) -> DriverError {
    crate::common::classify_connect_error(e, &["28P01", "28000"])
}

#[async_trait::async_trait]
impl DatabaseDriver for PostgresDriver {
    async fn query(&self, sql: &str) -> Result<QueryOutput, DriverError> {
        let mut stream = sqlx::raw_sql(sql).fetch(&self.pool);
        let mut rows = Vec::new();
        let mut total_bytes: usize = 0;
        let mut truncated = false;
        let mut truncation_reason = None;

        while let Some(row) = stream.try_next().await.map_err(query_err)? {
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
            .map_err(query_err)?;
        Ok(result.rows_affected())
    }

    async fn apply_migration(
        &self,
        sql: &str,
        version: &str,
        timeout_secs: u64,
    ) -> Result<(), DriverError> {
        validate_migration_version(version)?;
        // SET LOCAL is effective within the implicit transaction of PG simple query protocol.
        // statement_timeout applies per-statement, not cumulatively across the batch.
        let timeout_stmt = if timeout_secs > 0 {
            format!("SET LOCAL statement_timeout = '{}s';\n", timeout_secs)
        } else {
            String::new()
        };
        let batch = format!(
            "{timeout_stmt}{sql}\n;\nINSERT INTO schema_migrations (version) VALUES ('{version}');"
        );
        sqlx::raw_sql(&batch)
            .execute(&self.pool)
            .await
            .map_err(query_err)?;
        Ok(())
    }

    async fn revert_migration(
        &self,
        down_sql: &str,
        version: &str,
        timeout_secs: u64,
    ) -> Result<(), DriverError> {
        validate_migration_version(version)?;
        let timeout_stmt = if timeout_secs > 0 {
            format!("SET LOCAL statement_timeout = '{}s';\n", timeout_secs)
        } else {
            String::new()
        };
        let batch = format!(
            "{timeout_stmt}{down_sql}\n;\nDELETE FROM schema_migrations WHERE version = '{version}';"
        );
        sqlx::raw_sql(&batch)
            .execute(&self.pool)
            .await
            .map_err(query_err)?;
        Ok(())
    }

    async fn apply_migration_no_tx(
        &self,
        sql: &str,
        version: &str,
        timeout_secs: u64,
    ) -> Result<(), DriverError> {
        validate_migration_version(version)?;
        if has_multiple_statements(sql) {
            return Err(DriverError::QueryFailed(
                "transactional=false migrations must contain a single SQL statement".into(),
            ));
        }
        self.run_no_tx_migration(
            sql,
            &format!("INSERT INTO schema_migrations (version) VALUES ('{version}')"),
            version,
            "migration SQL applied successfully but version record failed",
            "mark-applied",
            timeout_secs,
        )
        .await
    }

    async fn revert_migration_no_tx(
        &self,
        down_sql: &str,
        version: &str,
        timeout_secs: u64,
    ) -> Result<(), DriverError> {
        validate_migration_version(version)?;
        if has_multiple_statements(down_sql) {
            return Err(DriverError::QueryFailed(
                "transactional=false migrations must contain a single SQL statement".into(),
            ));
        }
        self.run_no_tx_migration(
            down_sql,
            &format!("DELETE FROM schema_migrations WHERE version = '{version}'"),
            version,
            "revert SQL applied successfully but version removal failed",
            "remove",
            timeout_secs,
        )
        .await
    }

    async fn ensure_migrations_table(&self) -> Result<(), DriverError> {
        sqlx::query("CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY)")
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
        sqlx::query("INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT DO NOTHING")
            .bind(version)
            .execute(&self.pool)
            .await
            .map_err(query_err)?;
        Ok(())
    }

    async fn remove_version(&self, version: &str) -> Result<(), DriverError> {
        sqlx::query("DELETE FROM schema_migrations WHERE version = $1")
            .bind(version)
            .execute(&self.pool)
            .await
            .map_err(query_err)?;
        Ok(())
    }

    async fn query_cancellable(
        &self,
        sql: &str,
        timeout_secs: u64,
        cancel: &CancelState,
        max_rows: Option<usize>,
    ) -> Result<QueryOutput, DriverError> {
        let conn = self.pool.acquire().await.map_err(conn_err)?;
        let mut guard = crate::guard::CancellationGuard::new(conn);

        let pid = sqlx::query_scalar::<_, i32>("SELECT pg_backend_pid()")
            .fetch_one(&mut **guard.conn_mut())
            .await
            .map_err(query_err)?;
        cancel.set_connection_id(pid.to_string());

        if cancel.is_cancelled() {
            guard.release();
            return Err(DriverError::Cancelled);
        }

        // SAFE-1: read-only transaction prevents any writes regardless of SQL content
        sqlx::query("BEGIN READ ONLY")
            .execute(&mut **guard.conn_mut())
            .await
            .map_err(query_err)?;

        let ms = timeout_secs * 1000;
        sqlx::query(&format!("SET LOCAL statement_timeout = '{ms}ms'"))
            .execute(&mut **guard.conn_mut())
            .await
            .map_err(query_err)?;

        let result = async {
            let mut stream = sqlx::raw_sql(sql).fetch(&mut **guard.conn_mut());
            let mut rows = Vec::new();
            let mut total_bytes: usize = 0;
            let mut truncated = false;
            let mut truncation_reason = None;
            let effective_max_rows = max_rows.unwrap_or(MAX_RESULT_ROWS).min(MAX_RESULT_ROWS);

            while let Some(row) = stream.try_next().await.map_err(query_err)? {
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
            Ok::<_, DriverError>(QueryOutput {
                rows,
                truncated,
                truncation_reason,
            })
        }
        .await;

        let cleanup_ok = sqlx::query("ROLLBACK")
            .execute(&mut **guard.conn_mut())
            .await
            .is_ok();
        if cleanup_ok {
            guard.release();
        }
        result
    }

    async fn execute_cancellable(
        &self,
        sql: &str,
        timeout_secs: u64,
        cancel: &CancelState,
    ) -> Result<u64, DriverError> {
        let conn = self.pool.acquire().await.map_err(conn_err)?;
        let mut guard = crate::guard::CancellationGuard::new(conn);

        let pid = sqlx::query_scalar::<_, i32>("SELECT pg_backend_pid()")
            .fetch_one(&mut **guard.conn_mut())
            .await
            .map_err(query_err)?;
        cancel.set_connection_id(pid.to_string());

        if cancel.is_cancelled() {
            guard.release();
            return Err(DriverError::Cancelled);
        }

        let ms = timeout_secs * 1000;
        sqlx::query(&format!("SET statement_timeout = {ms}"))
            .execute(&mut **guard.conn_mut())
            .await
            .map_err(query_err)?;

        let result = async {
            let mut stream = sqlx::raw_sql(sql).fetch_many(&mut **guard.conn_mut());
            let mut total_affected = 0u64;
            while let Some(either) = stream.try_next().await.map_err(query_err)? {
                if let sqlx::Either::Left(result) = either {
                    total_affected += result.rows_affected();
                }
            }
            Ok::<_, DriverError>(total_affected)
        }
        .await;
        let cleanup_ok = sqlx::query("ROLLBACK")
            .execute(&mut **guard.conn_mut())
            .await
            .is_ok()
            && sqlx::query("RESET statement_timeout")
                .execute(&mut **guard.conn_mut())
                .await
                .is_ok();
        if cleanup_ok {
            guard.release();
        }
        result
    }

    async fn cancel_query(&self, connection_id: &str) -> Result<bool, DriverError> {
        let pid: i32 = connection_id
            .parse()
            .map_err(|_| DriverError::QueryFailed(format!("invalid PG pid: {connection_id}")))?;
        let cancel_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&self.url)
            .await
            .map_err(conn_err)?;
        let cancelled: bool = sqlx::query_scalar(&format!("SELECT pg_cancel_backend({pid})"))
            .fetch_one(&cancel_pool)
            .await
            .map_err(query_err)?;
        cancel_pool.close().await;
        Ok(cancelled)
    }

    async fn collect_schema(&self) -> Result<crate::SchemaSnapshot, DriverError> {
        use crate::schema::*;
        use sqlx::Row;

        // 1. Tables + estimated rows
        let table_rows = sqlx::query(
            "SELECT c.relname, n.nspname, c.reltuples::bigint \
             FROM pg_class c JOIN pg_namespace n ON c.relnamespace = n.oid \
             WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast') \
             AND c.relkind = 'r'",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(query_err)?;

        let mut tables = Vec::new();
        for row in &table_rows {
            let name: String = row.get("relname");
            let schema_name: String = row.get("nspname");
            let estimated_rows: i64 = row.get::<i64, _>(2);

            // 2. Columns
            let col_rows = sqlx::query(
                "SELECT column_name, data_type, is_nullable, column_default \
                 FROM information_schema.columns \
                 WHERE table_schema = $1 AND table_name = $2 \
                 ORDER BY ordinal_position",
            )
            .bind(&schema_name)
            .bind(&name)
            .fetch_all(&self.pool)
            .await
            .map_err(query_err)?;

            let columns: Vec<ColumnInfo> = col_rows
                .iter()
                .map(|r| {
                    ColumnInfo {
                        name: r.get("column_name"),
                        data_type: r.get("data_type"),
                        nullable: r.get::<String, _>("is_nullable") == "YES",
                        default_value: r.get("column_default"),
                        is_primary_key: false, // filled below
                    }
                })
                .collect();

            // 3. Constraints
            let constraint_rows = sqlx::query(
                "SELECT tc.constraint_name, tc.constraint_type, \
                        kcu.column_name, \
                        ccu.table_name AS ref_table, ccu.column_name AS ref_column, \
                        rc.delete_rule \
                 FROM information_schema.table_constraints tc \
                 JOIN information_schema.key_column_usage kcu \
                   ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema \
                 LEFT JOIN information_schema.constraint_column_usage ccu \
                   ON tc.constraint_name = ccu.constraint_name AND tc.table_schema = ccu.table_schema \
                 LEFT JOIN information_schema.referential_constraints rc \
                   ON tc.constraint_name = rc.constraint_name AND tc.constraint_schema = rc.constraint_schema \
                 WHERE tc.table_schema = $1 AND tc.table_name = $2"
            )
            .bind(&schema_name)
            .bind(&name)
            .fetch_all(&self.pool)
            .await
            .map_err(query_err)?;

            let mut constraints: Vec<ConstraintInfo> = Vec::new();
            for cr in &constraint_rows {
                let cname: String = cr.get("constraint_name");
                let ctype: String = cr.get("constraint_type");
                let col: String = cr.get("column_name");
                let ref_table: Option<String> = cr.get("ref_table");
                let ref_col: Option<String> = cr.get("ref_column");
                let delete_rule: Option<String> = cr.get("delete_rule");

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
                        constraint_type: match ctype.as_str() {
                            "PRIMARY KEY" => ConstraintType::PrimaryKey,
                            "FOREIGN KEY" => ConstraintType::ForeignKey,
                            "UNIQUE" => ConstraintType::Unique,
                            _ => ConstraintType::Check,
                        },
                        columns: vec![col],
                        referenced_table: ref_table,
                        referenced_columns: ref_col.map(|c| vec![c]),
                        on_delete: delete_rule.map(|r| match r.as_str() {
                            "CASCADE" => FkAction::Cascade,
                            "SET NULL" => FkAction::SetNull,
                            "RESTRICT" => FkAction::Restrict,
                            "SET DEFAULT" => FkAction::SetDefault,
                            _ => FkAction::NoAction,
                        }),
                    });
                }
            }

            // 4. Indexes
            let idx_rows = sqlx::query(
                "SELECT indexname, indexdef FROM pg_indexes \
                 WHERE schemaname = $1 AND tablename = $2",
            )
            .bind(&schema_name)
            .bind(&name)
            .fetch_all(&self.pool)
            .await
            .map_err(query_err)?;

            let indexes: Vec<IndexInfo> = idx_rows
                .iter()
                .map(|r| {
                    let indexdef: String = r.get("indexdef");
                    let is_unique = indexdef.contains("UNIQUE");
                    IndexInfo {
                        name: r.get("indexname"),
                        columns: vec![], // simplified: full parsing of indexdef not needed for v0.1.3
                        is_unique,
                        index_type: "btree".into(),
                    }
                })
                .collect();

            // Mark PK columns
            let mut columns = columns;
            let pk_cols: Vec<&str> = constraints
                .iter()
                .filter(|c| c.constraint_type == ConstraintType::PrimaryKey)
                .flat_map(|c| c.columns.iter().map(|s| s.as_str()))
                .collect();
            for col in &mut columns {
                if pk_cols.contains(&col.name.as_str()) {
                    col.is_primary_key = true;
                }
            }

            tables.push(TableInfo {
                name,
                schema_name,
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
        use sqlx::Row;
        let mut conn = self.pool.acquire().await.map_err(conn_err)?;
        // BEGIN READ ONLY so SET LOCAL is scoped correctly and no writes possible
        sqlx::query("BEGIN READ ONLY")
            .execute(&mut *conn)
            .await
            .map_err(query_err)?;
        sqlx::query(&format!("SET LOCAL statement_timeout = '{timeout_secs}s'"))
            .execute(&mut *conn)
            .await
            .map_err(query_err)?;
        let explain_sql = format!("EXPLAIN (FORMAT JSON) {sql}");
        let result = sqlx::query(&explain_sql)
            .fetch_one(&mut *conn)
            .await
            .map_err(query_err);
        // Always rollback (read-only, no side effects)
        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
        let row = result?;
        // PG EXPLAIN (FORMAT JSON) returns a json column, decode directly
        let plan: serde_json::Value = row.try_get(0).map_err(query_err)?;
        Ok(plan)
    }

    fn dialect(&self) -> &'static str {
        "postgresql"
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_version_accepted() {
        assert!(validate_migration_version("20260501120000_create_users").is_ok());
    }

    #[test]
    fn numeric_version_accepted() {
        assert!(validate_migration_version("001").is_ok());
    }

    #[test]
    fn single_quote_rejected() {
        assert!(validate_migration_version("v1'; DROP TABLE x --").is_err());
    }

    #[test]
    fn semicolon_rejected() {
        assert!(validate_migration_version("v1; DROP TABLE x").is_err());
    }

    #[test]
    fn backslash_rejected() {
        assert!(validate_migration_version("v1\\' OR 1=1").is_err());
    }

    #[test]
    fn newline_rejected() {
        assert!(validate_migration_version("v1\n'; DROP TABLE x --").is_err());
    }

    #[test]
    fn carriage_return_rejected() {
        assert!(validate_migration_version("v1\r\n").is_err());
    }

    #[test]
    fn null_byte_rejected() {
        assert!(validate_migration_version("v1\0").is_err());
    }

    #[test]
    fn unicode_version_accepted() {
        // Migration filenames could contain unicode (though unusual)
        assert!(validate_migration_version("20260501_テスト").is_ok());
    }

    #[test]
    fn empty_version_accepted() {
        // Empty is structurally valid (migrate crate validates non-empty separately)
        assert!(validate_migration_version("").is_ok());
    }

    #[test]
    fn double_quote_accepted() {
        // Double quotes don't escape single-quoted SQL string literals
        assert!(validate_migration_version("v1\"test").is_ok());
    }

    #[test]
    fn dash_dash_accepted() {
        // SQL comment chars in version are safe inside single quotes
        assert!(validate_migration_version("v1--comment").is_ok());
    }
}
