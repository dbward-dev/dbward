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

        // Check if already available
        if let Some(ref summary) = *slot.data.lock().await {
            return Ok(Some(summary.clone()));
        }

        // Wait with timeout
        let timeout = tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            slot.notify.notified(),
        )
        .await;

        if timeout.is_ok() {
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
}
