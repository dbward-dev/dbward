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

impl EventCategory {
    pub fn from_str(s: &str) -> Self {
        match s {
            "approval" => Self::Approval,
            "execution" => Self::Execution,
            "agent" => Self::Agent,
            "auth" => Self::Auth,
            "token" => Self::Token,
            "identity" => Self::Identity,
            _ => Self::Policy,
        }
    }
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

impl AuditEvent {
    /// Create a minimal audit event for management operations.
    /// Hash chain fields (prev_hash, event_hash) are filled by the infra layer.
    pub fn simple(event_type: &str, category: &str, actor_id: &str, resource_id: Option<&str>) -> Self {
        Self {
            id: String::new(), // filled by infra
            event_type: event_type.to_string(),
            event_category: EventCategory::from_str(category),
            event_version: 1,
            outcome: EventOutcome::Success,
            actor_id: actor_id.to_string(),
            actor_type: ActorType::User,
            resource_type: None,
            resource_id: resource_id.map(|s| s.to_string()),
            peer_ip: None,
            client_ip: None,
            client_ip_source: None,
            request_id: None,
            operation: None,
            database_name: None,
            environment: None,
            detail_fingerprint: None,
            detail_raw: None,
            reason: None,
            metadata_json: "{}".to_string(),
            prev_hash: None,
            event_hash: String::new(), // filled by infra
            created_at: Utc::now(),
        }
    }
}
