use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Plan {
    Free,
    Pro,
    Enterprise,
}

#[derive(Debug, Clone)]
pub struct PlanLimits {
    pub max_workflows: u32,
    pub max_databases: u32,
    pub max_webhooks: u32,
    pub max_tokens: u32,
    pub max_roles: u32,
}

impl PlanLimits {
    pub const FREE: Self = Self {
        max_workflows: 5,
        max_databases: 3,
        max_webhooks: 3,
        max_tokens: 10,
        max_roles: 8,
    };
}

/// License payload for key verification (serialized in license keys)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicensePayload {
    pub key_id: String,
    pub plan: Plan,
    pub issued_to: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct License {
    pub plan: Plan,
    pub issued_to: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl License {
    pub fn is_enterprise(&self) -> bool {
        self.plan == Plan::Enterprise
    }

    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|exp| now > exp)
    }
}

impl Default for License {
    fn default() -> Self {
        Self {
            plan: Plan::Free,
            issued_to: None,
            expires_at: None,
        }
    }
}

impl From<LicensePayload> for License {
    fn from(payload: LicensePayload) -> Self {
        Self {
            plan: payload.plan,
            issued_to: Some(payload.issued_to),
            expires_at: Some(payload.expires_at),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_check() {
        let past = Utc::now() - chrono::Duration::hours(1);
        let future = Utc::now() + chrono::Duration::hours(1);
        let lic = License {
            plan: Plan::Pro,
            issued_to: None,
            expires_at: Some(past),
        };
        assert!(lic.is_expired_at(Utc::now()));
        let lic2 = License {
            plan: Plan::Pro,
            issued_to: None,
            expires_at: Some(future),
        };
        assert!(!lic2.is_expired_at(Utc::now()));
    }

    #[test]
    fn no_expiry_means_not_expired() {
        let lic = License::default();
        assert!(!lic.is_expired_at(Utc::now()));
    }

    #[test]
    fn payload_serde_roundtrip() {
        let payload = LicensePayload {
            key_id: "key-roundtrip-99".into(),
            plan: Plan::Pro,
            issued_to: "acme-corp".into(),
            issued_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::days(90),
        };
        let json = serde_json::to_string(&payload).unwrap();
        let deserialized: LicensePayload = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.key_id, "key-roundtrip-99");
        assert_eq!(deserialized.plan, Plan::Pro);
        assert_eq!(deserialized.issued_to, "acme-corp");
        assert_eq!(deserialized.expires_at, payload.expires_at);
    }

    #[test]
    fn from_payload_to_license() {
        let expires = Utc::now() + chrono::Duration::days(30);
        let payload = LicensePayload {
            key_id: "key-convert-01".into(),
            plan: Plan::Enterprise,
            issued_to: "big-corp".into(),
            issued_at: Utc::now(),
            expires_at: expires,
        };
        let license = License::from(payload);
        assert_eq!(license.plan, Plan::Enterprise);
        assert_eq!(license.issued_to.as_deref(), Some("big-corp"));
        assert_eq!(license.expires_at, Some(expires));
    }
}
