use std::sync::Arc;

use crate::driver::DatabaseDriver;
use crate::query::{QueryResult, QueryType, classify_query};
use crate::{AuditEntry, AuditLogger, Config, Error, Operation, Role, check_permission};

pub struct Engine {
    driver: Arc<dyn DatabaseDriver>,
    config: Config,
    audit: AuditLogger,
}

impl Engine {
    pub async fn new(config: Config) -> Result<Self, Error> {
        let driver = crate::driver::connect(&config.database.url).await?;
        Ok(Self {
            driver,
            config,
            audit: AuditLogger::stdout(),
        })
    }

    pub fn from_driver(driver: Arc<dyn DatabaseDriver>, config: Config) -> Self {
        Self {
            driver,
            config,
            audit: AuditLogger::stdout(),
        }
    }

    pub fn driver(&self) -> &Arc<dyn DatabaseDriver> {
        &self.driver
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

        if role == Role::Readonly && !matches!(query_type, QueryType::Select) {
            return Err(Error::PermissionDenied {
                role,
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
            self.config.environment.clone(),
            sql,
        );
        entry.success = true;
        let _ = self.audit.log(&entry);

        Ok(result)
    }
}
