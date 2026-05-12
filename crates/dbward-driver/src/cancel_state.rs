//! Thin shared state for cancellable execution.
//! Lives in driver crate so Driver impls can set connection_id before executing.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

/// Shared cancel state between heartbeat task and driver execution.
/// Driver sets connection_id; heartbeat task reads it for kill.
#[derive(Clone)]
pub struct CancelState {
    inner: Arc<Inner>,
}

struct Inner {
    cancelled: AtomicBool,
    connection_id: Mutex<Option<String>>,
    kill_notify: Notify,
}

impl CancelState {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                cancelled: AtomicBool::new(false),
                connection_id: Mutex::new(None),
                kill_notify: Notify::new(),
            }),
        }
    }

    /// Called by heartbeat when server says cancelled.
    pub fn mark_cancelled(&self) {
        self.inner.cancelled.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire)
    }

    /// Called by driver impl after acquiring connection and getting pid.
    pub fn set_connection_id(&self, id: String) {
        *self.inner.connection_id.lock().unwrap() = Some(id);
    }

    /// Read connection_id for kill. Returns None if not yet set.
    pub fn connection_id(&self) -> Option<String> {
        self.inner.connection_id.lock().unwrap().clone()
    }

    /// Notify that kill has been attempted (or skipped). Wakes select! in driver.
    pub fn notify_killed(&self) {
        self.inner.kill_notify.notify_waiters();
    }

    /// Wait for kill signal. Used in tokio::select! to abort execution.
    pub async fn wait_for_kill(&self) {
        self.inner.kill_notify.notified().await;
    }
}

impl Default for CancelState {
    fn default() -> Self {
        Self::new()
    }
}
