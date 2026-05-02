use rusqlite::Connection;
use std::sync::{Arc, Mutex};

use dbward_core::Role;

use crate::oidc::OidcVerifier;
use crate::token::TokenSigner;
use crate::webhook::WebhookDispatcher;

#[derive(Clone)]
pub struct AppState {
    pub sqlite: Arc<Mutex<Connection>>,
    pub token_signer: Arc<TokenSigner>,
    pub webhooks: Arc<WebhookDispatcher>,
    pub oidc: Option<Arc<OidcVerifier>>,
    pub auth_mode: String,
}

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub token_id: String,
    pub user: String,
    pub role: Role,
}
