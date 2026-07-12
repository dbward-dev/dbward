use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Instant;

use async_trait::async_trait;
use tokio::sync::{Mutex, Notify};

use dbward_app::error::AppError;
use dbward_app::ports::ResultChannel;
use dbward_domain::values::ResultSummary;

struct ResultSlot {
    data: Mutex<Option<ResultSummary>>,
    notify: Notify,
    created_at: Instant,
}

pub struct InMemoryResultChannel {
    slots: Arc<StdMutex<HashMap<String, Arc<ResultSlot>>>>,
    max_slots: usize,
    slot_ttl_secs: u64,
    evictions_total: Arc<AtomicU64>,
}

impl Default for InMemoryResultChannel {
    fn default() -> Self {
        Self::new(10_000, 600)
    }
}

impl InMemoryResultChannel {
    pub fn new(max_slots: usize, slot_ttl_secs: u64) -> Self {
        Self {
            slots: Arc::new(StdMutex::new(HashMap::new())),
            max_slots,
            slot_ttl_secs,
            evictions_total: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn evictions_total(&self) -> u64 {
        self.evictions_total.load(Ordering::Relaxed)
    }

    /// Get or create a slot, applying TTL cleanup and eviction if needed.
    fn ensure_slot(&self, request_id: &str) -> Arc<ResultSlot> {
        let mut slots = self.slots.lock().unwrap();
        let ttl = self.slot_ttl_secs;
        // Only expire slots that already have data (completed) and are past TTL.
        // Pending slots (no data) are kept to avoid breaking active subscribers.
        slots.retain(|_, s| {
            s.created_at.elapsed().as_secs() < ttl
                || s.data.try_lock().map_or(true, |d| d.is_none())
        });

        if let Some(slot) = slots.get(request_id) {
            return slot.clone();
        }

        // Evict oldest if at capacity
        while slots.len() >= self.max_slots {
            let oldest_key = slots
                .iter()
                .min_by_key(|(_, s)| s.created_at)
                .map(|(k, _)| k.clone());
            if let Some(key) = oldest_key {
                if let Some(evicted) = slots.remove(&key) {
                    evicted.notify.notify_waiters();
                }
                self.evictions_total.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(evicted_key = %key, "result channel slot evicted due to capacity limit");
            } else {
                break;
            }
        }

        let slot = Arc::new(ResultSlot {
            data: Mutex::new(None),
            notify: Notify::new(),
            created_at: Instant::now(),
        });
        slots.insert(request_id.to_string(), slot.clone());
        slot
    }
}

#[async_trait]
impl ResultChannel for InMemoryResultChannel {
    fn create_slot(&self, request_id: &str) {
        let slot = self.ensure_slot(request_id);
        // Reset data for retry case: if a previous execution already published,
        // clear it so the new execution's result is awaited.
        if let Ok(mut data) = slot.data.try_lock() {
            *data = None;
        }
    }

    async fn publish(&self, request_id: &str, summary: ResultSummary) {
        let slot = self.ensure_slot(request_id);
        *slot.data.lock().await = Some(summary);
        slot.notify.notify_waiters();
    }

    async fn subscribe(
        &self,
        request_id: &str,
        timeout_secs: u64,
    ) -> Result<Option<ResultSummary>, AppError> {
        let slot = self.ensure_slot(request_id);

        // Register notification interest BEFORE checking data to avoid race:
        // without this, publish() can fire between data check and notified()
        // registration, causing the notification to be lost (300s hang).
        let notified = slot.notify.notified();
        tokio::pin!(notified);
        // Defensive: enable() registers for notify_one(). For notify_waiters(),
        // Notified creation alone suffices, but enable() future-proofs against
        // a potential switch to notify_one().
        notified.as_mut().enable();

        // Check if already available
        if let Some(ref summary) = *slot.data.lock().await {
            return Ok(Some(summary.clone()));
        }

        // Wait — if publish() fired after Notified creation, resolves immediately
        let timeout =
            tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), notified).await;

        if timeout.is_ok() {
            // notify_all (shutdown/eviction) can wake without data → returns None
            Ok(slot.data.lock().await.clone())
        } else {
            Ok(None)
        }
    }

    async fn notify_all(&self) {
        let slots = self.slots.lock().unwrap();
        for slot in slots.values() {
            slot.notify.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evicts_oldest_when_at_capacity() {
        let ch = InMemoryResultChannel::new(3, 600);
        ch.create_slot("a");
        ch.create_slot("b");
        ch.create_slot("c");
        // At capacity, next insert should evict "a"
        ch.create_slot("d");

        let slots = ch.slots.lock().unwrap();
        assert!(!slots.contains_key("a"));
        assert!(slots.contains_key("d"));
        assert_eq!(slots.len(), 3);
        drop(slots);
        assert_eq!(ch.evictions_total(), 1);
    }

    #[test]
    fn create_slot_is_idempotent() {
        let ch = InMemoryResultChannel::new(10, 600);
        ch.create_slot("x");
        ch.create_slot("x");
        let slots = ch.slots.lock().unwrap();
        assert_eq!(slots.len(), 1);
    }

    #[test]
    fn ttl_cleanup_removes_expired() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let ch = InMemoryResultChannel::new(100, 0); // 0 second TTL
        ch.create_slot("old");
        // Publish data so the slot is "completed" and eligible for TTL cleanup
        rt.block_on(async {
            ch.publish(
                "old",
                ResultSummary {
                    execution_id: "e".into(),
                    success: true,
                    rows_affected: None,
                    truncated: false,
                    error_message: None,
                    result_data: None,
                },
            )
            .await;
        });
        std::thread::sleep(std::time::Duration::from_millis(10));
        // Next ensure_slot should clean up "old" (completed + past TTL)
        ch.create_slot("new");
        let slots = ch.slots.lock().unwrap();
        assert!(!slots.contains_key("old"));
        assert!(slots.contains_key("new"));
    }

    fn test_summary(success: bool) -> ResultSummary {
        ResultSummary {
            execution_id: "exec-1".into(),
            success,
            rows_affected: Some(1),
            truncated: false,
            error_message: None,
            result_data: None,
        }
    }

    #[tokio::test]
    async fn publish_then_subscribe_returns_immediately() {
        let ch = InMemoryResultChannel::default();
        ch.create_slot("req-1");
        ch.publish("req-1", test_summary(true)).await;

        let result = ch.subscribe("req-1", 5).await.unwrap();
        assert!(result.is_some());
        assert!(result.unwrap().success);
    }

    #[tokio::test]
    async fn subscribe_before_publish_waits_and_receives() {
        let ch = Arc::new(InMemoryResultChannel::default());
        ch.create_slot("req-2");

        let ch2 = ch.clone();
        let handle = tokio::spawn(async move { ch2.subscribe("req-2", 5).await });

        // Small delay to ensure subscriber is waiting
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        ch.publish("req-2", test_summary(true)).await;

        let result = handle.await.unwrap().unwrap();
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn subscribe_timeout_returns_none() {
        let ch = InMemoryResultChannel::default();
        ch.create_slot("req-3");

        let result = ch.subscribe("req-3", 1).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn notify_all_unblocks_subscribers() {
        let ch = Arc::new(InMemoryResultChannel::default());
        ch.create_slot("req-4");

        let ch2 = ch.clone();
        let handle = tokio::spawn(async move { ch2.subscribe("req-4", 10).await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let start = std::time::Instant::now();
        ch.notify_all().await;

        let result = handle.await.unwrap().unwrap();
        let elapsed = start.elapsed();
        // notify_all unblocks but no data was published → None
        assert!(result.is_none());
        // Should return quickly, not wait for the 10s timeout
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "took too long: {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn subscribe_returns_data_published_before_call() {
        let ch = Arc::new(InMemoryResultChannel::new(100, 600));
        ch.create_slot("pre-pub");
        ch.publish("pre-pub", test_summary(true)).await;

        // subscribe finds data via the check after enable — returns immediately
        let result = ch.subscribe("pre-pub", 2).await.unwrap();
        assert!(result.is_some());
        assert!(result.unwrap().success);
    }

    #[tokio::test]
    async fn subscribe_receives_concurrent_publish() {
        let ch = Arc::new(InMemoryResultChannel::new(100, 600));
        ch.create_slot("concurrent");

        let ch2 = ch.clone();
        let sub = tokio::spawn(async move { ch2.subscribe("concurrent", 5).await });

        // Yield multiple times to increase chance of subscribe reaching await
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        ch.publish("concurrent", test_summary(true)).await;

        let result = sub.await.unwrap().unwrap();
        assert!(result.is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn subscribe_never_misses_publish_under_contention() {
        // Probabilistic stress test: spawns 50 concurrent subscribe+publish pairs.
        // With multi_thread runtime, publish can truly race against subscribe.
        let ch = Arc::new(InMemoryResultChannel::new(10_000, 600));
        let mut handles = vec![];

        for i in 0..50 {
            let id = format!("stress-{i}");
            ch.create_slot(&id);

            let ch_sub = ch.clone();
            let ch_pub = ch.clone();
            let id_sub = id.clone();
            let id_pub = id.clone();

            let sub_handle = tokio::spawn(async move { ch_sub.subscribe(&id_sub, 2).await });
            let _pub_handle = tokio::spawn(async move {
                ch_pub.publish(&id_pub, test_summary(true)).await;
            });

            handles.push(sub_handle);
        }

        for h in handles {
            let result = h.await.unwrap().unwrap();
            assert!(
                result.is_some(),
                "subscribe must not miss publish under contention"
            );
        }
    }

    #[tokio::test]
    async fn notify_all_without_data_returns_none_not_panic() {
        let ch = Arc::new(InMemoryResultChannel::new(100, 600));
        ch.create_slot("spurious");

        let ch2 = ch.clone();
        let sub = tokio::spawn(async move { ch2.subscribe("spurious", 5).await });

        tokio::task::yield_now().await;
        ch.notify_all().await;

        let result = sub.await.unwrap().unwrap();
        // Woken without data → None (spurious wakeup treated as timeout-like)
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn subscribe_without_create_slot_still_receives_publish() {
        // Simulates the Conflict path where resume is skipped (no create_slot)
        let ch = Arc::new(InMemoryResultChannel::new(100, 600));

        let ch2 = ch.clone();
        let sub = tokio::spawn(async move { ch2.subscribe("no-slot", 5).await });

        tokio::task::yield_now().await;
        ch.publish("no-slot", test_summary(true)).await;

        let result = sub.await.unwrap().unwrap();
        assert!(result.is_some());
    }
}
