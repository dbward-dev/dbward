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
            "INSERT INTO databases (id, name, environment, source, lifecycle_state, created_at) \
             VALUES (?1, ?2, ?3, 'config', 'active', ?4) \
             ON CONFLICT(id) DO UPDATE SET source='config', lifecycle_state='active'",
            rusqlite::params![
                id,
                db.to_string(),
                env.to_string(),
                chrono::Utc::now().to_rfc3339()
            ],
        )
        .map_err(db_err("database: register"))?;
        Ok(())
    }

    fn exists_active(&self, db: &DatabaseName, env: &Environment) -> Result<bool, AppError> {
        let conn = self.conn.lock();
        let id = format!("{}:{}", db, env);
        let result: Result<String, _> = conn.query_row(
            "SELECT id FROM databases WHERE id = ?1 AND lifecycle_state = 'active'",
            rusqlite::params![id],
            |row| row.get(0),
        );
        match result {
            Ok(_) => Ok(true),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
            Err(e) => Err(db_err("database: exists_active")(e)),
        }
    }

    fn list_active(&self) -> Result<Vec<(DatabaseName, Environment)>, AppError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare("SELECT name, environment FROM databases WHERE lifecycle_state = 'active'")
            .map_err(db_err("database: list_active"))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(db_err("database: list_active"))?;

        let mut results = Vec::new();
        for row in rows {
            let (name, env) = row.map_err(db_err("database: list_active"))?;
            let db = DatabaseName::new(name).map_err(|e| AppError::Internal(e.to_string()))?;
            let environment =
                Environment::new(env).map_err(|e| AppError::Internal(e.to_string()))?;
            results.push((db, environment));
        }
        Ok(results)
    }

    fn get_by_id(&self, id: &str) -> Result<bool, AppError> {
        let conn = self.conn.lock();
        let result: Result<String, _> = conn.query_row(
            "SELECT id FROM databases WHERE id = ?1",
            rusqlite::params![id],
            |row| row.get(0),
        );
        match result {
            Ok(_) => Ok(true),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
            Err(e) => Err(db_err("database: get_by_id")(e)),
        }
    }

    fn delete_by_source(&self, source: &str) -> Result<u64, AppError> {
        let conn = self.conn.lock();
        let n = conn
            .execute("DELETE FROM databases WHERE source = ?1", [source])
            .map_err(db_err("database: delete_by_source"))?;
        Ok(n as u64)
    }

    fn reconcile_stale(&self, active_ids: &[String]) -> Result<(u64, u64), AppError> {
        let conn = self.conn.lock();
        if active_ids.is_empty() {
            // Orphan those with FK refs, delete the rest
            let orphaned = conn.execute(
                "UPDATE databases SET lifecycle_state = 'orphan' WHERE source = 'config' AND lifecycle_state = 'active' AND EXISTS (SELECT 1 FROM requests WHERE requests.database_id = databases.id)",
                [],
            ).map_err(db_err("database: reconcile_stale orphan"))? as u64;
            let deleted = conn.execute(
                "DELETE FROM databases WHERE source = 'config' AND lifecycle_state = 'active' AND NOT EXISTS (SELECT 1 FROM requests WHERE requests.database_id = databases.id)",
                [],
            ).map_err(db_err("database: reconcile_stale delete"))? as u64;
            return Ok((orphaned, deleted));
        }
        let placeholders: String = (1..=active_ids.len())
            .map(|i| format!("?{i}"))
            .collect::<Vec<_>>()
            .join(",");
        // Orphan stale with FK refs
        let sql_orphan = format!(
            "UPDATE databases SET lifecycle_state = 'orphan' WHERE source = 'config' AND lifecycle_state = 'active' AND id NOT IN ({placeholders}) AND EXISTS (SELECT 1 FROM requests WHERE requests.database_id = databases.id)"
        );
        let params: Vec<&dyn rusqlite::types::ToSql> = active_ids
            .iter()
            .map(|s| s as &dyn rusqlite::types::ToSql)
            .collect();
        let orphaned = conn
            .execute(&sql_orphan, params.as_slice())
            .map_err(db_err("database: reconcile_stale orphan"))? as u64;
        // Delete stale without FK refs
        let sql_delete = format!(
            "DELETE FROM databases WHERE source = 'config' AND lifecycle_state = 'active' AND id NOT IN ({placeholders}) AND NOT EXISTS (SELECT 1 FROM requests WHERE requests.database_id = databases.id)"
        );
        let deleted = conn
            .execute(&sql_delete, params.as_slice())
            .map_err(db_err("database: reconcile_stale delete"))? as u64;
        Ok((orphaned, deleted))
    }
}
