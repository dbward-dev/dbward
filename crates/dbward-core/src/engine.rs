use sqlx::postgres::PgRow;
use sqlx::{PgPool, Row};

use crate::query::{QueryResult, QueryType, classify_query};
use crate::{AuditEntry, AuditLogger, Config, Error, Operation, Role, check_permission};

pub struct Engine {
    pool: PgPool,
    config: Config,
    audit: AuditLogger,
}

impl Engine {
    pub async fn new(config: Config) -> Result<Self, Error> {
        let pool = PgPool::connect(&config.database.url)
            .await
            .map_err(|e| Error::Database(e.to_string()))?;
        Ok(Self {
            pool,
            config,
            audit: AuditLogger::stdout(),
        })
    }

    pub fn from_pool(pool: PgPool, config: Config) -> Self {
        Self {
            pool,
            config,
            audit: AuditLogger::stdout(),
        }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn set_audit_logger(&mut self, logger: AuditLogger) {
        self.audit = logger;
    }
    pub async fn execute_query(
        &mut self,
        user: &str,
        role: Role,
        sql: &str,
    ) -> Result<QueryResult, Error> {
        check_permission(&role, &Operation::ExecuteQuery)?;
        let query_type = classify_query(sql)?;

        // Readonly can only SELECT
        if role == Role::Readonly && !matches!(query_type, QueryType::Select) {
            return Err(Error::PermissionDenied {
                role,
                operation: Operation::ExecuteQuery,
            });
        }

        let result = match query_type {
            QueryType::Select => {
                let rows: Vec<PgRow> = sqlx::query(sql)
                    .fetch_all(&self.pool)
                    .await
                    .map_err(|e| Error::Database(e.to_string()))?;

                let json_rows: Vec<serde_json::Value> = rows
                    .iter()
                    .map(|row| row_to_json(row))
                    .collect();

                QueryResult {
                    query_type: QueryType::Select,
                    rows: json_rows,
                    rows_affected: 0,
                }
            }
            _ => {
                let result = sqlx::query(sql)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| Error::Database(e.to_string()))?;

                QueryResult {
                    query_type,
                    rows: vec![],
                    rows_affected: result.rows_affected(),
                }
            }
        };

        let mut entry = AuditEntry::new(
            user,
            role,
            Operation::ExecuteQuery,
            self.config.environment.clone(),
            sql,
        );
        entry.success = true;
        let _ = self.audit.log(&entry);

        Ok(result)
    }
}

/// Convert a PgRow to a JSON object using column metadata.
fn row_to_json(row: &PgRow) -> serde_json::Value {
    use sqlx::Column;
    use sqlx::TypeInfo;

    let mut map = serde_json::Map::new();
    for col in row.columns() {
        let name = col.name();
        let type_name = col.type_info().name();
        let value: serde_json::Value = match type_name {
            "BOOL" => row
                .try_get::<bool, _>(name)
                .map(serde_json::Value::from)
                .unwrap_or(serde_json::Value::Null),
            "INT2" => row
                .try_get::<i16, _>(name)
                .map(|v| serde_json::Value::from(v))
                .unwrap_or(serde_json::Value::Null),
            "INT4" => row
                .try_get::<i32, _>(name)
                .map(serde_json::Value::from)
                .unwrap_or(serde_json::Value::Null),
            "INT8" => row
                .try_get::<i64, _>(name)
                .map(serde_json::Value::from)
                .unwrap_or(serde_json::Value::Null),
            "FLOAT4" => row
                .try_get::<f32, _>(name)
                .map(|v| serde_json::Value::from(v))
                .unwrap_or(serde_json::Value::Null),
            "FLOAT8" => row
                .try_get::<f64, _>(name)
                .map(serde_json::Value::from)
                .unwrap_or(serde_json::Value::Null),
            _ => row
                .try_get::<String, _>(name)
                .map(serde_json::Value::from)
                .unwrap_or(serde_json::Value::Null),
        };
        map.insert(name.to_string(), value);
    }
    serde_json::Value::Object(map)
}
