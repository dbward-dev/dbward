use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use tokio::sync::{Mutex, Notify};

use dbward_app::error::AppError;
use dbward_app::ports::ResultChannel;

struct ResultSlot {
    data: Mutex<Option<Vec<u8>>>,
    notify: Notify,
    created_at: Instant,
}

pub struct InMemoryResultChannel {
    slots: Arc<Mutex<HashMap<String, Arc<ResultSlot>>>>,
}

impl InMemoryResultChannel {
    pub fn new() -> Self {
        Self { slots: Arc::new(Mutex::new(HashMap::new())) }
    }

    /// Create a slot for a request (called when dispatching).
    pub async fn create_slot(&self, request_id: &str) {
        let mut slots = self.slots.lock().await;
        // Clean expired slots (10 min TTL)
        slots.retain(|_, s| s.created_at.elapsed().as_secs() < 600);
        slots.insert(request_id.to_string(), Arc::new(ResultSlot {
            data: Mutex::new(None),
            notify: Notify::new(),
            created_at: Instant::now(),
        }));
    }

    /// Write result data to a slot (called by agent submit).
    pub async fn publish(&self, request_id: &str, data: Vec<u8>) {
        let slots = self.slots.lock().await;
        if let Some(slot) = slots.get(request_id) {
            *slot.data.lock().await = Some(data);
            slot.notify.notify_waiters();
        }
    }
}

#[async_trait]
impl ResultChannel for InMemoryResultChannel {
    async fn subscribe(&self, request_id: &str, timeout_secs: u64) -> Result<Option<Vec<u8>>, AppError> {
        let slot = {
            let slots = self.slots.lock().await;
            slots.get(request_id).cloned()
        };

        let Some(slot) = slot else {
            return Ok(None);
        };

        // Check if already available
        if let Some(data) = slot.data.lock().await.take() {
            return Ok(Some(data));
        }

        // Wait with timeout
        let timeout = tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            slot.notify.notified(),
        ).await;

        if timeout.is_ok() {
            Ok(slot.data.lock().await.take())
        } else {
            Ok(None)
        }
    }
}
