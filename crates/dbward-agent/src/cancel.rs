use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use dbward_driver::{CancelState, DatabaseDriver};

/// Agent-side cancel orchestrator. Wraps CancelState with kill logic.
#[derive(Clone)]
pub struct CancelToken {
    cancelled: Arc<AtomicBool>,
    cancel_state: CancelState,
    driver: Option<Arc<dyn DatabaseDriver>>,
    is_migration: bool,
}

impl CancelToken {
    pub fn new(
        driver: Option<Arc<dyn DatabaseDriver>>,
        is_migration: bool,
        cancel_state: CancelState,
    ) -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            cancel_state,
            driver,
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

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        // ADR-003: never kill during migration
        if self.is_migration {
            tracing::info!("migration in progress, skipping kill (statement_timeout only)");
            return;
        }

        let killed = self.kill_query().await;
        if killed {
            self.cancel_state.notify_killed();
        }
    }

    async fn kill_query(&self) -> bool {
        let Some(pid) = self.cancel_state.connection_id() else {
            return false;
        };
        let Some(driver) = &self.driver else {
            tracing::warn!("no driver for cancel");
            return false;
        };

        // Ok(_) → always notify: if the cancel SQL was delivered successfully,
        // wake the executor for fail-fast. The biased select! ensures that a
        // query result arriving first takes priority over the kill notification.
        match driver.cancel_query(&pid).await {
            Ok(_) => true,
            Err(e) => {
                tracing::error!("cancel_query failed: {e}");
                false
            }
        }
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
    async fn no_kill_without_driver() {
        let state = CancelState::new();
        state.set_connection_id("12345".into());
        let token = CancelToken::new(None, false, state);
        assert!(!token.kill_query().await);
    }

    #[tokio::test]
    async fn no_kill_without_connection_id() {
        let state = CancelState::new();
        // No driver needed — connection_id check comes first
        let token = CancelToken::new(None, false, state);
        assert!(!token.kill_query().await);
    }
}
