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
        Ok(Self {
            pool,
            url: url.to_owned(),
        })
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
        let cancelled: bool = sqlx::query_scalar(&format!("SELECT pg_cancel_backend({pid})"))
            .fetch_one(&cancel_pool)
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
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
             AND c.relkind = 'r'"
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| DriverError::QueryFailed(e.to_string()))?;

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
                 ORDER BY ordinal_position"
            )
            .bind(&schema_name)
            .bind(&name)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;

            let columns: Vec<ColumnInfo> = col_rows.iter().map(|r| {
                ColumnInfo {
                    name: r.get("column_name"),
                    data_type: r.get("data_type"),
                    nullable: r.get::<String, _>("is_nullable") == "YES",
                    default_value: r.get("column_default"),
                    is_primary_key: false, // filled below
                }
            }).collect();

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
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;

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
                        on_delete: delete_rule.and_then(|r| match r.as_str() {
                            "CASCADE" => Some(FkAction::Cascade),
                            "SET NULL" => Some(FkAction::SetNull),
                            "RESTRICT" => Some(FkAction::Restrict),
                            "SET DEFAULT" => Some(FkAction::SetDefault),
                            _ => Some(FkAction::NoAction),
                        }),
                    });
                }
            }

            // 4. Indexes
            let idx_rows = sqlx::query(
                "SELECT indexname, indexdef FROM pg_indexes \
                 WHERE schemaname = $1 AND tablename = $2"
            )
            .bind(&schema_name)
            .bind(&name)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;

            let indexes: Vec<IndexInfo> = idx_rows.iter().map(|r| {
                let indexdef: String = r.get("indexdef");
                let is_unique = indexdef.contains("UNIQUE");
                IndexInfo {
                    name: r.get("indexname"),
                    columns: vec![], // simplified: full parsing of indexdef not needed for v0.1.3
                    is_unique,
                    index_type: "btree".into(),
                }
            }).collect();

            // Mark PK columns
            let mut columns = columns;
            let pk_cols: Vec<&str> = constraints.iter()
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

    async fn explain(&self, sql: &str, timeout_secs: u64) -> Result<serde_json::Value, DriverError> {
        use sqlx::Row;
        let mut conn = self.pool.acquire().await
            .map_err(|e| DriverError::ConnectionFailed(e.to_string()))?;
        sqlx::query(&format!("SET LOCAL statement_timeout = '{timeout_secs}s'"))
            .execute(&mut *conn)
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        let explain_sql = format!("EXPLAIN (FORMAT JSON) {sql}");
        let row = sqlx::query(&explain_sql)
            .fetch_one(&mut *conn)
            .await
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        let plan: String = row.try_get(0)
            .map_err(|e| DriverError::QueryFailed(e.to_string()))?;
        serde_json::from_str(&plan)
            .map_err(|e| DriverError::QueryFailed(format!("invalid EXPLAIN JSON: {e}")))
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
