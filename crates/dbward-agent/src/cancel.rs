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
            // Don't notify — let query finish naturally or timeout
            return;
        }

        let killed = self.kill_query().await;
        if killed {
            self.cancel_state.notify_killed();
        }
        // If not killed (MySQL, no pid, etc.), don't notify — query runs to timeout
    }

    /// Returns true if kill was actually performed (PG only for now).
    async fn kill_query(&self) -> bool {
        let Some(pid) = self.cancel_state.connection_id() else {
            return false;
        };
        let Some(url) = &self.db_url else {
            tracing::warn!("no db_url for cancel");
            return false;
        };

        if url.starts_with("postgres://") || url.starts_with("postgresql://") {
            let pid_int: i32 = match pid.parse() {
                Ok(v) => v,
                Err(_) => return false,
            };
            match dbward_driver::connect(url, Some(5)).await {
                Ok(driver) => {
                    if let Err(e) = driver.execute(&format!("SELECT pg_cancel_backend({pid_int})")).await {
                        tracing::error!("pg_cancel_backend failed: {e}");
                        return false;
                    }
                    true
                }
                Err(e) => {
                    tracing::error!("cancel connection failed: {e}");
                    false
                }
            }
        } else if url.starts_with("mysql://") {
            let conn_id: u64 = match pid.parse() {
                Ok(v) => v,
                Err(_) => return false,
            };
            match dbward_driver::connect(url, Some(5)).await {
                Ok(driver) => {
                    if let Err(e) = driver.execute(&format!("KILL QUERY {conn_id}")).await {
                        tracing::error!("KILL QUERY failed: {e}");
                        return false;
                    }
                    true
                }
                Err(e) => {
                    tracing::error!("cancel connection failed: {e}");
                    false
                }
            }
        } else {
            tracing::warn!("kill_query not supported for this DB scheme");
            false
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
    async fn no_kill_without_url() {
        let state = CancelState::new();
        state.set_connection_id("12345".into());
        let token = CancelToken::new(None, false, state.clone());
        assert!(!token.kill_query().await);
    }

    #[tokio::test]
    async fn no_kill_without_connection_id() {
        let state = CancelState::new();
        let token = CancelToken::new(Some("postgres://localhost/db".into()), false, state);
        // No connection_id set → returns false
        assert!(!token.kill_query().await);
    }

    #[tokio::test]
    async fn pg_kill_fails_gracefully_on_bad_connection() {
        let state = CancelState::new();
        state.set_connection_id("999".into());
        let token = CancelToken::new(Some("postgres://invalid:1/x".into()), false, state);
        // Connection fails → returns false (no panic)
        assert!(!token.kill_query().await);
    }

    #[tokio::test]
    async fn mysql_kill_fails_gracefully_on_bad_connection() {
        let state = CancelState::new();
        state.set_connection_id("999".into());
        let token = CancelToken::new(Some("mysql://invalid:1/x".into()), false, state);
        // Connection fails → returns false (no panic)
        assert!(!token.kill_query().await);
    }
}
