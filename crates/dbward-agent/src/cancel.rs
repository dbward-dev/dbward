use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use dbward_driver::CancelState;

/// Agent-side cancel orchestrator. Wraps CancelState with kill logic.
#[derive(Clone)]
pub struct CancelToken {
    cancelled: Arc<AtomicBool>,
    cancel_state: CancelState,
    db_url: Option<String>,
    is_migration: bool,
}

impl CancelToken {
    pub fn new(db_url: Option<String>, is_migration: bool, cancel_state: CancelState) -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            cancel_state,
            db_url,
            is_migration,
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    /// Called by heartbeat when server says cancelled.
    /// Marks cancelled → 2s grace → kill_query → notify.
    pub async fn trigger_cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.cancel_state.mark_cancelled();

        // 2s grace period for short queries to finish naturally
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        // ADR-003: never kill during migration
        if self.is_migration {
            tracing::info!("migration in progress, skipping kill (statement_timeout only)");
            self.cancel_state.notify_killed();
            return;
        }

        if let Err(e) = self.kill_query().await {
            tracing::error!("kill_query failed: {e}");
        }
        self.cancel_state.notify_killed();
    }

    async fn kill_query(&self) -> Result<(), crate::AgentError> {
        if self.is_migration {
            return Ok(());
        }
        let Some(pid) = self.cancel_state.connection_id() else {
            return Ok(());
        };
        let Some(url) = &self.db_url else {
            tracing::warn!("no db_url for cancel");
            return Ok(());
        };

        if url.starts_with("postgres://") || url.starts_with("postgresql://") {
            let pid_int: i32 = pid.parse().map_err(|_| {
                crate::AgentError::Config(format!("invalid pid: {pid}"))
            })?;
            let driver = dbward_driver::connect(url, Some(5)).await?;
            driver.execute(&format!("SELECT pg_cancel_backend({pid_int})")).await?;
        } else {
            // MySQL: KILL QUERY not implemented yet (v0.1.1)
            // Do NOT notify_killed — let statement timeout handle it
            tracing::warn!("kill_query not implemented for MySQL; relying on statement_timeout");
            return Ok(());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_token_basic() {
        let state = CancelState::new();
        let token = CancelToken::new(None, false, state);
        assert!(!token.is_cancelled());
        token.cancelled.store(true, Ordering::Release);
        assert!(token.is_cancelled());
    }

    #[tokio::test]
    async fn migration_skips_kill() {
        let state = CancelState::new();
        state.set_connection_id("12345".into());
        let token = CancelToken::new(Some("postgres://localhost/db".into()), true, state.clone());
        // Directly test kill_query skips for migration
        assert!(token.kill_query().await.is_ok());
    }
}
