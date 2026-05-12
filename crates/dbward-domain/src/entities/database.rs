use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::values::{DatabaseName, Environment};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Database {
    pub name: DatabaseName,
    pub environments: Vec<Environment>,
    pub created_at: DateTime<Utc>,
}
