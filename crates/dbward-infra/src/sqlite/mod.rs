mod schema;

mod agent_repo;
mod audit_repo;
mod database_repo;
mod policy_repo;
mod request_repo;
mod token_repo;
mod user_repo;
mod webhook_delivery_repo;
mod webhook_repo;

pub use schema::initialize;

pub use agent_repo::SqliteAgentRepo;
pub use audit_repo::{SqliteAuditLogger, SqliteAuditRepo};
pub use database_repo::SqliteDatabaseRegistry;
pub use policy_repo::{SqlitePolicyEvaluator, SqlitePolicyRepo};
pub use request_repo::SqliteRequestRepo;
pub use token_repo::SqliteTokenRepo;
pub use user_repo::SqliteUserRepo;
pub use webhook_delivery_repo::SqliteWebhookDeliveryRepo;
pub use webhook_repo::SqliteWebhookRepo;

use rusqlite::Connection;
use std::sync::Arc;
use std::sync::Mutex;

/// Shared SQLite connection handle used by all repos.
pub type DbConn = Arc<Mutex<Connection>>;

/// Create a new DbConn from a file path.
pub fn open(path: &str) -> Result<DbConn, rusqlite::Error> {
    let conn = Connection::open(path)?;
    initialize(&conn)?;
    Ok(Arc::new(Mutex::new(conn)))
}

/// Create an in-memory DbConn (for testing).
pub fn open_memory() -> Result<DbConn, rusqlite::Error> {
    let conn = Connection::open_in_memory()?;
    initialize(&conn)?;
    Ok(Arc::new(Mutex::new(conn)))
}
