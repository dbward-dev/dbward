use std::collections::HashMap;
use std::sync::Arc;
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
    slots: Arc<Mutex<HashMap<String, Arc<ResultSlot>>>>,
}

impl InMemoryResultChannel {
    pub fn new() -> Self {
        Self { slots: Arc::new(Mutex::new(HashMap::new())) }
    }
}

#[async_trait]
impl ResultChannel for InMemoryResultChannel {
    async fn create_slot(&self, request_id: &str) {
        let mut slots = self.slots.lock().await;
        slots.retain(|_, s| s.created_at.elapsed().as_secs() < 600);
        slots.insert(request_id.to_string(), Arc::new(ResultSlot {
            data: Mutex::new(None),
            notify: Notify::new(),
            created_at: Instant::now(),
        }));
    }

    async fn publish(&self, request_id: &str, summary: ResultSummary) {
        let mut slots = self.slots.lock().await;
        let slot = slots.entry(request_id.to_string()).or_insert_with(|| {
            Arc::new(ResultSlot {
                data: Mutex::new(None),
                notify: Notify::new(),
                created_at: Instant::now(),
            })
        });
        *slot.data.lock().await = Some(summary);
        slot.notify.notify_waiters();
    }

    async fn subscribe(&self, request_id: &str, timeout_secs: u64) -> Result<Option<ResultSummary>, AppError> {
        let slot = {
            let mut slots = self.slots.lock().await;
            slots.entry(request_id.to_string()).or_insert_with(|| {
                Arc::new(ResultSlot {
                    data: tokio::sync::Mutex::new(None),
                    notify: Notify::new(),
                    created_at: Instant::now(),
                })
            }).clone()
        };

        // Check if already available
        if let Some(ref summary) = *slot.data.lock().await {
            return Ok(Some(summary.clone()));
        }

        // Wait with timeout
        let timeout = tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            slot.notify.notified(),
        ).await;

        if timeout.is_ok() {
            Ok(slot.data.lock().await.clone())
        } else {
            Ok(None)
        }
    }
}
