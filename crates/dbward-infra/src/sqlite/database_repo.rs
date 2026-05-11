use crate::sqlite::DbConn;
use dbward_app::error::AppError;
use dbward_app::ports::DatabaseRegistry;
use dbward_domain::values::{DatabaseName, Environment};

pub struct SqliteDatabaseRegistry {
    conn: DbConn,
}

impl SqliteDatabaseRegistry {
    pub fn new(conn: DbConn) -> Self {
        Self { conn }
    }
}

impl DatabaseRegistry for SqliteDatabaseRegistry {
    fn exists(&self, db: &DatabaseName, env: &Environment) -> Result<bool, AppError> {
        let conn = self.conn.blocking_lock();
        let id = format!("{}:{}", db, env);
        let result: Result<String, _> = conn.query_row(
            "SELECT id FROM databases WHERE id = ?1",
            rusqlite::params![id],
            |row| row.get(0),
        );
        match result {
            Ok(_) => Ok(true),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
            Err(e) => Err(AppError::Internal(e.to_string())),
        }
    }

    fn list(&self) -> Result<Vec<(DatabaseName, Environment)>, AppError> {
        let conn = self.conn.blocking_lock();
        let mut stmt = conn.prepare("SELECT name, environment FROM databases")
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        }).map_err(|e| AppError::Internal(e.to_string()))?;

        let mut results = Vec::new();
        for row in rows {
            let (name, env) = row.map_err(|e| AppError::Internal(e.to_string()))?;
            let db = DatabaseName::new(name).map_err(|e| AppError::Internal(e.to_string()))?;
            let environment = Environment::new(env).map_err(|e| AppError::Internal(e.to_string()))?;
            results.push((db, environment));
        }
        Ok(results)
    }
}
