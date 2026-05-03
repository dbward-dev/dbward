use rusqlite::Connection;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use dbward_core::Role;

use crate::oidc::OidcVerifier;
use crate::policy::PolicyConfig;
use crate::token::TokenSigner;
use crate::webhook::WebhookDispatcher;

/// Holds a pending result slot: agent writes, CLI reads.
pub struct ResultSlot {
    pub result: Mutex<Option<serde_json::Value>>,
    pub notify: tokio::sync::Notify,
    pub created_at: Instant,
}

/// In-memory channels for relaying query results from agent to CLI.
pub struct ResultChannels {
    pub slots: Mutex<HashMap<String, Arc<ResultSlot>>>,
}

impl ResultChannels {
    const SLOT_TTL: Duration = Duration::from_secs(600);

    pub fn new() -> Self {
        Self {
            slots: Mutex::new(HashMap::new()),
        }
    }

    pub async fn insert(&self, request_id: String, slot: Arc<ResultSlot>) {
        self.cleanup_expired().await;
        self.slots.lock().await.insert(request_id, slot);
    }

    pub async fn get(&self, request_id: &str) -> Option<Arc<ResultSlot>> {
        self.cleanup_expired().await;
        self.slots.lock().await.get(request_id).cloned()
    }

    pub async fn remove(&self, request_id: &str) -> Option<Arc<ResultSlot>> {
        self.slots.lock().await.remove(request_id)
    }

    async fn cleanup_expired(&self) {
        let now = Instant::now();
        self.slots
            .lock()
            .await
            .retain(|_, slot| now.duration_since(slot.created_at) < Self::SLOT_TTL);
    }
}

#[derive(Clone)]
pub struct AppState {
    pub sqlite: Arc<Mutex<Connection>>,
    pub token_signer: Arc<TokenSigner>,
    pub webhooks: Arc<WebhookDispatcher>,
    pub oidc: Option<Arc<OidcVerifier>>,
    pub auth_mode: String,
    pub policy: Arc<PolicyConfig>,
    pub result_channels: Arc<ResultChannels>,
}

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub token_id: String,
    pub user: String,
    pub role: Role,
}
