use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventCategory {
    Approval,
    Execution,
    Agent,
    Auth,
    Token,
    Identity,
    Policy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventOutcome {
    Success,
    Denied,
    Failure,
    Info,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    User,
    Agent,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub event_type: String,
    pub event_category: EventCategory,
    pub event_version: u32,
    pub outcome: EventOutcome,
    pub actor_id: String,
    pub actor_type: ActorType,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub peer_ip: Option<String>,
    pub client_ip: Option<String>,
    pub client_ip_source: Option<String>,
    pub request_id: Option<String>,
    pub operation: Option<String>,
    pub database_name: Option<String>,
    pub environment: Option<String>,
    pub detail_fingerprint: Option<String>,
    pub detail_raw: Option<String>,
    pub reason: Option<String>,
    pub metadata_json: String,
    pub prev_hash: Option<String>,
    pub event_hash: String,
    pub created_at: DateTime<Utc>,
}
