use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultStatus {
    Stored,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectorType {
    Requester,
    Role,
    Group,
    User,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub id: String,
    pub request_id: String,
    pub execution_id: String,
    pub storage_backend: String,
    pub storage_key: String,
    pub content_length: u64,
    pub checksum_sha256: String,
    pub retention_days: u32,
    pub status: ResultStatus,
    pub truncated: bool,
    pub truncation_reason: Option<String>,
    pub stored_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultAccess {
    pub id: String,
    pub result_id: String,
    pub selector_type: SelectorType,
    pub selector_value: String,
}
