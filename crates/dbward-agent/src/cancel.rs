use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

#[derive(Clone)]
pub struct CancelToken {
    cancelled: Arc<AtomicBool>,
    killed: Arc<Notify>,
    connection_id: Arc<Mutex<Option<String>>>,
    db_url: Option<String>,
    is_migration: bool,
}

impl CancelToken {
    pub fn new(db_url: Option<String>, is_migration: bool) -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            killed: Arc::new(Notify::new()),
            connection_id: Arc::new(Mutex::new(None)),
            db_url,
            is_migration,
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub fn set_connection_id(&self, id: String) {
        *self.connection_id.lock().unwrap() = Some(id);
    }

    /// Waits until kill_query is triggered (after grace period).
    pub async fn wait_for_kill(&self) {
        self.killed.notified().await;
    }

    pub async fn kill_query(&self) -> Result<(), crate::AgentError> {
        // ADR-003: never kill during migration
        if self.is_migration {
            tracing::info!("migration in progress, skipping kill_query (statement_timeout only)");
            self.killed.notify_waiters();
            return Ok(());
        }

        let pid = self.connection_id.lock().unwrap().clone();
        let Some(pid) = pid else {
            self.killed.notify_waiters();
            return Ok(());
        };
        let Some(url) = &self.db_url else {
            tracing::warn!("no db_url configured for cancel; cannot kill query");
            self.killed.notify_waiters();
            return Ok(());
        };

        if url.starts_with("postgres://") || url.starts_with("postgresql://") {
            let pid_int: i32 = pid.parse().map_err(|_| {
                crate::AgentError::Config(format!("invalid pid: {pid}"))
            })?;
            let driver = dbward_driver::connect(url, Some(5)).await?;
            driver
                .execute(&format!("SELECT pg_cancel_backend({pid_int})"))
                .await?;
        } else {
            tracing::warn!("kill_query not implemented for MySQL; query will time out");
        }

        self.killed.notify_waiters();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_token_basic() {
        let token = CancelToken::new(None, false);
        assert!(!token.is_cancelled());
        token.cancel();
        assert!(token.is_cancelled());
    }

    #[tokio::test]
    async fn kill_notifies_waiters() {
        let token = CancelToken::new(None, false);
        let t2 = token.clone();
        let handle = tokio::spawn(async move {
            t2.wait_for_kill().await;
            true
        });
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        token.kill_query().await.unwrap();
        assert!(handle.await.unwrap());
    }

    #[tokio::test]
    async fn migration_skips_kill() {
        let token = CancelToken::new(Some("postgres://localhost/db".into()), true);
        token.set_connection_id("12345".into());
        // Should not attempt DB connection, just notify
        token.kill_query().await.unwrap();
    }
}
