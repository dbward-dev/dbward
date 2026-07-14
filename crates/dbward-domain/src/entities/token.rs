use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::auth::SubjectType;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenStatus {
    Active,
    Revoked,
}

/// Classification of how a token was provisioned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvisioningKind {
    /// Auto-issued when a user is added via `user add` or `reissue-initial-token`.
    Initial,
    /// Auto-issued during server bootstrap.
    Bootstrap,
}

impl ProvisioningKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Initial => "initial",
            Self::Bootstrap => "bootstrap",
        }
    }

    pub fn from_str_opt(s: Option<&str>) -> Option<Self> {
        match s {
            Some("initial") => Some(Self::Initial),
            Some("bootstrap") => Some(Self::Bootstrap),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeCeiling {
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub id: String,
    pub subject_type: SubjectType,
    pub subject_id: String,
    #[serde(skip_serializing)]
    pub token_hash: String,
    #[serde(skip_serializing)]
    pub token_prefix: String,
    pub scope_ceiling: Option<ScopeCeiling>,
    pub name: Option<String>,
    pub status: TokenStatus,
    pub provisioning_kind: Option<ProvisioningKind>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl Token {
    /// Extract the lookup prefix from a raw token string.
    /// Token format: "dbw_" + hex chars; prefix is chars 4..12 (first 8 hex chars).
    pub fn extract_prefix(raw_token: &str) -> String {
        raw_token
            .get(4..12)
            .map(str::to_string)
            .unwrap_or_else(|| raw_token.chars().take(8).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_prefix_normal_token() {
        // Standard token: "dbw_" + 8 hex chars prefix + rest
        let token = "dbw_abcdef0123456789";
        assert_eq!(Token::extract_prefix(token), "abcdef01");
    }

    #[test]
    fn extract_prefix_short_string() {
        // Too short to slice 4..12 — falls back to first 8 chars
        let token = "dbw_ab";
        assert_eq!(Token::extract_prefix(token), "dbw_ab");
    }

    #[test]
    fn extract_prefix_empty_string() {
        assert_eq!(Token::extract_prefix(""), "");
    }

    #[test]
    fn extract_prefix_non_ascii() {
        // Multi-byte chars: .get(4..12) returns None if boundary is invalid
        let token = "dbw_あいうえお";
        // "あ" is 3 bytes; byte range 4..12 crosses char boundaries → None
        // fallback: first 8 chars = "dbw_あいうえ"
        assert_eq!(Token::extract_prefix(token), "dbw_あいうえ");
    }

    #[test]
    fn extract_prefix_exactly_12_chars() {
        let token = "dbw_12345678";
        assert_eq!(Token::extract_prefix(token), "12345678");
    }
}
