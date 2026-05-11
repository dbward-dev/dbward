use super::Permission;
use crate::values::{DatabaseName, Environment};
use serde::{Deserialize, Serialize};

/// A stored role definition (persisted in PolicyRepo).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleDefinition {
    pub name: String,
    pub permissions: Vec<Permission>,
    pub databases: Vec<DatabaseName>,
    pub environments: Vec<Environment>,
}
