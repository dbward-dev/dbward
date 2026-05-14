use serde::{Deserialize, Serialize};

// --- ResultPolicy ---

#[derive(Debug, Deserialize)]
pub struct CreateResultPolicyRequest {
    pub database: String,
    pub environment: String,
    pub retention_days: u32,
    pub delivery_mode: String,
    #[serde(default)]
    pub access: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateResultPolicyRequest {
    pub retention_days: Option<u32>,
    pub delivery_mode: Option<String>,
    pub access: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct ResultPolicyResponse {
    pub id: String,
    pub database: String,
    pub environment: String,
    pub retention_days: u32,
    pub delivery_mode: String,
    pub access: Vec<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

// --- NotificationPolicy ---

#[derive(Debug, Deserialize)]
pub struct CreateNotificationPolicyRequest {
    pub database: String,
    pub environment: String,
    pub webhooks: Vec<String>,
    #[serde(default)]
    pub events: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateNotificationPolicyRequest {
    pub webhooks: Option<Vec<String>>,
    pub events: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct NotificationPolicyResponse {
    pub id: String,
    pub database: String,
    pub environment: String,
    pub webhooks: Vec<String>,
    pub events: Vec<String>,
}
