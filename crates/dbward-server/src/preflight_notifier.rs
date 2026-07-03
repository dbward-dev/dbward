use dashmap::DashMap;
use tokio::sync::watch;

/// Manages per-job watch channels for preflight EXPLAIN completion notification.
///
/// The HTTP handler registers a waiter before the job becomes visible to agents,
/// then waits on the receiver. When the agent submits the result, the server calls
/// `notify()` to wake the handler. `NotifierGuard` ensures cleanup on all exit paths.
pub struct PreflightNotifier {
    waiters: DashMap<String, watch::Sender<bool>>,
}

impl PreflightNotifier {
    pub fn new() -> Self {
        Self {
            waiters: DashMap::new(),
        }
    }

    /// Register a waiter for a job. Must be called BEFORE the job is inserted into DB.
    /// Returns a receiver that fires when `notify()` is called for this job_id.
    pub fn register(&self, job_id: &str) -> watch::Receiver<bool> {
        let (tx, rx) = watch::channel(false);
        self.waiters.insert(job_id.to_string(), tx);
        rx
    }

    /// Notify the waiter that the job is complete. No-op if no waiter registered.
    pub fn notify(&self, job_id: &str) {
        if let Some(tx) = self.waiters.get(job_id) {
            let _ = tx.send(true);
        }
    }

    /// Remove waiter entry. Called by `NotifierGuard::drop()`.
    pub fn remove(&self, job_id: &str) {
        self.waiters.remove(job_id);
    }
}

impl Default for PreflightNotifier {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII guard that removes the notifier entry on drop.
/// Ensures cleanup on success, timeout, and client disconnect.
pub struct NotifierGuard<'a> {
    notifier: &'a PreflightNotifier,
    job_id: String,
}

impl<'a> NotifierGuard<'a> {
    pub fn new(notifier: &'a PreflightNotifier, job_id: String) -> Self {
        Self { notifier, job_id }
    }
}

impl Drop for NotifierGuard<'_> {
    fn drop(&mut self) {
        self.notifier.remove(&self.job_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn notify_wakes_receiver() {
        let notifier = PreflightNotifier::new();
        let mut rx = notifier.register("job-1");
        notifier.notify("job-1");
        rx.changed().await.unwrap();
        assert!(*rx.borrow());
    }

    #[tokio::test]
    async fn guard_removes_on_drop() {
        let notifier = PreflightNotifier::new();
        let _rx = notifier.register("job-2");
        {
            let _guard = NotifierGuard::new(&notifier, "job-2".to_string());
        }
        // After guard dropped, entry is removed
        assert!(!notifier.waiters.contains_key("job-2"));
    }

    #[test]
    fn notify_without_waiter_is_noop() {
        let notifier = PreflightNotifier::new();
        notifier.notify("nonexistent"); // should not panic
    }
}
