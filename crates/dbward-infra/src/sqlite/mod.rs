mod schema;

mod agent_repo;
mod audit_helper;
mod audit_repo;
mod context_repo;
mod database_repo;
mod dry_run_repo;
mod policy_repo;
mod request_repo;
mod schema_repo;
pub mod slack_message_repo;
mod token_repo;
mod user_repo;
mod webhook_delivery_repo;
mod webhook_repo;

pub use schema::initialize;

pub use agent_repo::SqliteAgentRepo;
pub use audit_repo::{SqliteAuditLogger, SqliteAuditRepo};
pub use context_repo::SqliteContextRepo;
pub use database_repo::SqliteDatabaseRegistry;
pub use dry_run_repo::SqliteDryRunRepo;
pub use policy_repo::{SqlitePolicyEvaluator, SqlitePolicyRepo};
pub use request_repo::SqliteRequestRepo;
pub use schema_repo::SqliteSchemaRepo;
pub use slack_message_repo::SqliteSlackMessageRepo;
pub use token_repo::SqliteTokenRepo;
pub use user_repo::SqliteUserRepo;
pub use webhook_delivery_repo::SqliteWebhookDeliveryRepo;
pub use webhook_repo::SqliteWebhookRepo;

use chrono::{DateTime, Utc};
use rusqlite::Connection;
use std::sync::Arc;
use std::sync::Mutex;

/// Parse an RFC3339 datetime string from the database without panicking.
pub(crate) fn parse_datetime(s: &str) -> Result<DateTime<Utc>, rusqlite::Error> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })
}

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
