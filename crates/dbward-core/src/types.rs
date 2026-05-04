use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    MigrateUp,
    MigrateDown,
    MigrateStatus,
    MigrateCreate,
    ExecuteQuery,
    AuditSearch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Environment {
    Production,
    Staging,
    Development,
    #[serde(untagged)]
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub user: String,
    pub role: String,
    pub operation: Operation,
    pub environment: Environment,
    /// Human-readable detail (e.g. SQL statement, migration name)
    pub detail: String,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

impl AuditEntry {
    pub fn new(
        user: impl Into<String>,
        role: impl Into<String>,
        operation: Operation,
        environment: Environment,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            user: user.into(),
            role: role.into(),
            operation,
            environment,
            detail: detail.into(),
            success: true,
            error_message: None,
        }
    }

    pub fn with_failure(mut self, message: impl Into<String>) -> Self {
        self.success = false;
        self.error_message = Some(message.into());
        self
    }
}

impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MigrateUp => write!(f, "migrate_up"),
            Self::MigrateDown => write!(f, "migrate_down"),
            Self::MigrateStatus => write!(f, "migrate_status"),
            Self::MigrateCreate => write!(f, "migrate_create"),
            Self::ExecuteQuery => write!(f, "execute_query"),
            Self::AuditSearch => write!(f, "audit_search"),
        }
    }
}

impl std::fmt::Display for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Production => write!(f, "production"),
            Self::Staging => write!(f, "staging"),
            Self::Development => write!(f, "development"),
            Self::Custom(name) => write!(f, "{name}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_entry_serializes_to_json() {
        let entry = AuditEntry::new(
            "alice",
            "developer",
            Operation::MigrateUp,
            Environment::Staging,
            "20260501_create_users.sql",
        );
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"operation\":\"migrate_up\""));
        assert!(json.contains("\"role\":\"developer\""));
        assert!(json.contains("\"success\":true"));
        // error_message should be omitted when None
        assert!(!json.contains("error_message"));
    }

    #[test]
    fn audit_entry_failure() {
        let entry = AuditEntry::new(
            "bob",
            "admin",
            Operation::ExecuteQuery,
            Environment::Production,
            "DELETE FROM users",
        )
        .with_failure("permission denied");

        assert!(!entry.success);
        assert_eq!(entry.error_message.as_deref(), Some("permission denied"));
    }

    #[test]
    fn environment_custom_variant() {
        let env = Environment::Custom("qa-1".into());
        assert_eq!(env.to_string(), "qa-1");
    }
}
