use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::values::Role;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectType {
    User,
    Agent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub id: String,
    pub subject_type: SubjectType,
    pub subject_id: String,
    pub token_hash: String,
    pub token_prefix: String,
    pub role: Role,
    pub groups: Vec<String>,
    pub name: Option<String>,
    pub status: TokenStatus,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}
