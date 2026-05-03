use rusqlite::Connection;
use std::collections::HashMap;
use std::sync::Arc;
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
}

/// In-memory channels for relaying query results from agent to CLI.
pub struct ResultChannels {
    pub slots: Mutex<HashMap<String, Arc<ResultSlot>>>,
}

impl ResultChannels {
    pub fn new() -> Self {
        Self {
            slots: Mutex::new(HashMap::new()),
        }
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
