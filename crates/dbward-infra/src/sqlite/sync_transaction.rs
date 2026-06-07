use crate::sqlite::DbConn;
use dbward_app::error::AppError;
use dbward_app::use_cases::sync_config::SyncTransaction;

/// SQLite transaction wrapper for config sync.
/// Uses IMMEDIATE mode to acquire a write lock at BEGIN.
///
/// INVARIANT: All repos sharing this DbConn operate on the same underlying
/// SQLite connection. SQLite transaction state is per-connection, so BEGIN
/// here applies to all subsequent operations regardless of Mutex lock/unlock
/// cycles between repo calls. This breaks if a second connection is introduced.
pub struct SqliteSyncTransaction {
    conn: DbConn,
}

impl SqliteSyncTransaction {
    pub fn new(conn: DbConn) -> Self {
        Self { conn }
    }
}

impl SyncTransaction for SqliteSyncTransaction {
    fn begin(&self) -> Result<(), AppError> {
        let conn = self.conn.lock();
        conn.execute_batch("BEGIN IMMEDIATE")
            .map_err(|e| AppError::Internal(format!("begin transaction: {e}")))?;
        Ok(())
    }

    fn commit(&self) -> Result<(), AppError> {
        let conn = self.conn.lock();
        conn.execute_batch("COMMIT")
            .map_err(|e| AppError::Internal(format!("commit transaction: {e}")))?;
        Ok(())
    }

    fn rollback(&self) -> Result<(), AppError> {
        let conn = self.conn.lock();
        conn.execute_batch("ROLLBACK")
            .map_err(|e| AppError::Internal(format!("rollback transaction: {e}")))?;
        Ok(())
    }
}
