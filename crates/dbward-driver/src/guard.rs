use sqlx::pool::PoolConnection;

/// RAII guard ensuring a pooled connection is never returned dirty on cancel/drop.
///
/// Normal path: call `release()` after cleanup (ROLLBACK etc.) → conn returns to pool.
/// Cancel/drop path: `Drop` calls `conn.detach()` → conn is closed, not reused.
pub(crate) struct CancellationGuard<DB: sqlx::Database> {
    conn: Option<PoolConnection<DB>>,
}

impl<DB: sqlx::Database> CancellationGuard<DB> {
    pub fn new(conn: PoolConnection<DB>) -> Self {
        Self { conn: Some(conn) }
    }

    pub fn conn_mut(&mut self) -> &mut PoolConnection<DB> {
        self.conn.as_mut().expect("guard already released")
    }

    /// Return connection to pool (normal completion path).
    pub fn release(mut self) {
        drop(self.conn.take());
    }
}

impl<DB: sqlx::Database> Drop for CancellationGuard<DB> {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            conn.detach();
        }
    }
}
