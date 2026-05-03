use rusqlite::Connection;
use std::sync::Arc;
use tokio::sync::Mutex;

use dbward_core::Role;

use crate::oidc::OidcVerifier;
use crate::policy::PolicyConfig;
use crate::token::TokenSigner;
use crate::webhook::WebhookDispatcher;

#[derive(Clone)]
pub struct AppState {
    pub sqlite: Arc<Mutex<Connection>>,
    pub token_signer: Arc<TokenSigner>,
    pub webhooks: Arc<WebhookDispatcher>,
    pub oidc: Option<Arc<OidcVerifier>>,
    pub auth_mode: String,
    pub policy: Arc<PolicyConfig>,
}

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub token_id: String,
    pub user: String,
    pub role: Role,
}
