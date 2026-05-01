use rusqlite::Connection;
use std::sync::{Arc, Mutex};

use dbward_core::Role;

/// Shared application state for axum handlers.
#[derive(Clone)]
pub struct AppState {
    pub sqlite: Arc<Mutex<Connection>>,
}

/// Authenticated user extracted from API token.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub token_id: String,
    pub user: String,
    pub role: Role,
}
