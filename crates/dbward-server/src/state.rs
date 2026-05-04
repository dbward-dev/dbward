use rusqlite::Connection;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use crate::oidc::OidcVerifier;
use crate::policy::PolicyConfig;
use crate::server_config::RetentionConfig;
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

impl Default for ResultChannels {
    fn default() -> Self {
        Self::new()
    }
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

/// Notifies long-polling GET /api/requests/{id}?wait= when status changes.
pub struct RequestNotifier {
    notifiers: Mutex<HashMap<String, Arc<tokio::sync::Notify>>>,
}

impl Default for RequestNotifier {
    fn default() -> Self {
        Self::new()
    }
}

impl RequestNotifier {
    pub fn new() -> Self {
        Self {
            notifiers: Mutex::new(HashMap::new()),
        }
    }

    pub async fn subscribe(&self, request_id: &str) -> Arc<tokio::sync::Notify> {
        self.notifiers
            .lock()
            .await
            .entry(request_id.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Notify::new()))
            .clone()
    }

    pub async fn notify(&self, request_id: &str) {
        if let Some(n) = self.notifiers.lock().await.get(request_id) {
            n.notify_waiters();
        }
    }

    pub async fn remove(&self, request_id: &str) {
        self.notifiers.lock().await.remove(request_id);
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
    pub retention: RetentionConfig,
    pub request_notifier: Arc<RequestNotifier>,
}

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub token_id: String,
    pub user: String,
    pub roles: Vec<String>,
    pub subject_type: String,
}

impl AuthUser {
    /// Returns the effective permission level:
    /// "admin" > "developer" > "readonly" > "approver" (custom roles can only approve).
    pub fn effective_permission(&self) -> &str {
        if self.roles.iter().any(|r| r == "admin") {
            return "admin";
        }
        if self.roles.iter().any(|r| r == "developer") {
            return "developer";
        }
        if self.roles.iter().any(|r| r == "readonly") {
            return "readonly";
        }
        "approver"
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }
}
