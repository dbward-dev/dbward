use crate::sqlite::DbConn;
use crate::sqlite::error::db_err;
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
    fn register(&self, db: &DatabaseName, env: &Environment) -> Result<(), AppError> {
        let conn = self.conn.lock();
        let id = format!("{}:{}", db, env);
        conn.execute(
            "INSERT INTO databases (id, name, environment, source, created_at) VALUES (?1, ?2, ?3, 'config', ?4) ON CONFLICT(id) DO UPDATE SET source='config'",
            rusqlite::params![id, db.to_string(), env.to_string(), chrono::Utc::now().to_rfc3339()],
        )
        .map_err(db_err("database: register"))?;
        Ok(())
    }

    fn exists(&self, db: &DatabaseName, env: &Environment) -> Result<bool, AppError> {
        let conn = self.conn.lock();
        let id = format!("{}:{}", db, env);
        let result: Result<String, _> = conn.query_row(
            "SELECT id FROM databases WHERE id = ?1",
            rusqlite::params![id],
            |row| row.get(0),
        );
        match result {
            Ok(_) => Ok(true),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
            Err(e) => Err(db_err("database: exists")(e)),
        }
    }

    fn list(&self) -> Result<Vec<(DatabaseName, Environment)>, AppError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT name, environment FROM databases")
            .map_err(db_err("database: list"))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(db_err("database: list"))?;

        let mut results = Vec::new();
        for row in rows {
            let (name, env) = row.map_err(db_err("database: list"))?;
            let db = DatabaseName::new(name).map_err(|e| AppError::Internal(e.to_string()))?;
            let environment =
                Environment::new(env).map_err(|e| AppError::Internal(e.to_string()))?;
            results.push((db, environment));
        }
        Ok(results)
    }

    fn delete_by_source(&self, source: &str) -> Result<u64, AppError> {
        let conn = self.conn.lock();
        let n = conn
            .execute("DELETE FROM databases WHERE source = ?1", [source])
            .map_err(db_err("database: delete_by_source"))?;
        Ok(n as u64)
    }
}
