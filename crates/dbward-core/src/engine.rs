use std::sync::Arc;

use crate::config::ResolvedDatabaseConfig;
use crate::driver::DatabaseDriver;
use crate::query::{QueryResult, QueryType, classify_query};
use crate::{AuditEntry, AuditLogger, Error, Environment, Operation, check_permission};

pub struct Engine {
    driver: Arc<dyn DatabaseDriver>,
    database_name: String,
    environment: Environment,
    audit: AuditLogger,
}

impl Engine {
    pub async fn new(resolved: &ResolvedDatabaseConfig, environment: Environment) -> Result<Self, Error> {
        let driver = crate::driver::connect(&resolved.url).await?;
        Ok(Self {
            driver,
            database_name: resolved.name.clone(),
            environment,
            audit: AuditLogger::stdout(),
        })
    }

    pub fn from_driver(driver: Arc<dyn DatabaseDriver>, database_name: &str, environment: Environment) -> Self {
        Self {
            driver,
            database_name: database_name.to_string(),
            environment,
            audit: AuditLogger::stdout(),
        }
    }

    pub fn driver(&self) -> &Arc<dyn DatabaseDriver> {
        &self.driver
    }

    pub fn database_name(&self) -> &str {
        &self.database_name
    }

    pub fn set_audit_logger(&mut self, logger: AuditLogger) {
        self.audit = logger;
    }

    pub async fn execute_query(
        &mut self,
        user: &str,
        role: &str,
        sql: &str,
    ) -> Result<QueryResult, Error> {
        check_permission(role, &Operation::ExecuteQuery)?;
        let query_type = classify_query(sql)?;

        if role == "readonly" && !matches!(query_type, QueryType::Select) {
            return Err(Error::PermissionDenied {
                role: role.to_string(),
                operation: Operation::ExecuteQuery,
            });
        }

        let result = match query_type {
            QueryType::Select => {
                let rows = self.driver.query(sql).await?;
                QueryResult {
                    query_type: QueryType::Select,
                    rows,
                    rows_affected: 0,
                }
            }
            _ => {
                let affected = self.driver.execute(sql).await?;
                QueryResult {
                    query_type,
                    rows: vec![],
                    rows_affected: affected,
                }
            }
        };

        let mut entry = AuditEntry::new(
            user,
            role,
            Operation::ExecuteQuery,
            self.environment.clone(),
            sql,
        );
        entry.success = true;
        let _ = self.audit.log(&entry);

        Ok(result)
    }
}
