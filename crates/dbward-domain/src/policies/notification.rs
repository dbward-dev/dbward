use serde::{Deserialize, Serialize};

use crate::values::{DatabaseName, Environment};

/// Controls which webhooks fire for a database+environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationPolicy {
    pub id: String,
    pub database: DatabaseName,
    pub environment: Environment,
    pub webhooks: Vec<String>,
    pub events: Vec<String>,
}
