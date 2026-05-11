use serde::{Deserialize, Serialize};

use crate::values::{DatabaseName, Environment, Selector};

/// Controls how results are stored and who can access them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultPolicy {
    pub id: String,
    pub database: DatabaseName,
    pub environment: Environment,
    pub delivery_mode: String,
    pub access: Vec<Selector>,
}
