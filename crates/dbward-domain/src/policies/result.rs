use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::values::{DatabaseName, Environment, Selector};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryMode {
    #[default]
    Both,
    StoreOnly,
    Stream,
}

/// Controls how results are stored and who can access them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultPolicy {
    pub id: String,
    pub database: DatabaseName,
    pub environment: Environment,
    pub retention_days: u32,
    pub delivery_mode: DeliveryMode,
    pub access: Vec<Selector>,
    #[serde(default)]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub updated_at: Option<DateTime<Utc>>,
}
