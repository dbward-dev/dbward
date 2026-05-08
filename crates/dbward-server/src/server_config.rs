use serde::Deserialize;

use crate::webhook::WebhookConfig;

/// Workflow definition from TOML config.
#[derive(Debug, Clone, Deserialize)]
pub struct WorkflowDef {
    pub database: String,
    pub environment: String,
    #[serde(default)]
    pub operations: Vec<String>,
    #[serde(default)]
    pub steps: Vec<WorkflowStep>,
    #[serde(default)]
    pub require_reason: bool,
    #[serde(default)]
    pub allow_same_approver_across_steps: bool,
    #[serde(default)]
    pub allow_self_approve: bool,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct WorkflowStep {
    #[serde(rename = "type")]
    pub step_type: String,
    #[serde(default = "default_step_mode")]
    pub mode: String,
    pub approvers: Vec<ApproverGroup>,
    #[serde(default = "default_true")]
    pub require_distinct_actors: bool,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct ApproverGroup {
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default = "default_one")]
    pub min: u32,
}

fn default_step_mode() -> String {
    "all".into()
}
fn default_one() -> u32 {
    1
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct RetentionConfig {
    #[serde(default = "default_request_ttl")]
    pub request_ttl_days: u32,
    #[serde(default = "default_audit_ttl")]
    pub audit_ttl_days: u32,
    #[serde(default = "default_result_ttl")]
    pub result_ttl_days: u32,
    #[serde(default = "default_approval_ttl")]
    pub approval_ttl_secs: u64,
}

fn default_request_ttl() -> u32 {
    90
}
fn default_audit_ttl() -> u32 {
    365
}
fn default_result_ttl() -> u32 {
    30
}
fn default_approval_ttl() -> u64 {
    86400
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            request_ttl_days: default_request_ttl(),
            audit_ttl_days: default_audit_ttl(),
            result_ttl_days: default_result_ttl(),
            approval_ttl_secs: default_approval_ttl(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ServerConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default = "default_data")]
    pub data: String,
    #[serde(default)]
    pub webhooks: Vec<WebhookConfig>,
    pub auth: Option<AuthConfig>,
    #[serde(default)]
    pub retention: RetentionConfig,
    #[serde(default)]
    pub workflows: Vec<WorkflowDef>,
    #[serde(default)]
    pub execution_policies: Vec<ExecutionPolicyDef>,
    #[serde(default)]
    pub result_policies: Vec<ResultPolicyDef>,
    #[serde(default)]
    pub notification_policies: Vec<NotificationPolicyDef>,
    #[serde(default)]
    pub access_policies: Vec<AccessPolicyDef>,
    #[serde(default)]
    pub result_storage: ResultStorageConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    #[serde(default)]
    pub logging: LoggingConfig,
    /// Enable periodic update check against GitHub Releases. Default: false (enable after public).
    #[serde(default)]
    pub update_check: bool,
}

/// Logging configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    /// "stderr" (default) or "file"
    #[serde(default = "default_log_output")]
    pub output: String,
    /// Log file path (only used when output = "file")
    #[serde(default)]
    pub file_path: Option<String>,
    /// Rotation: "daily" (default), "hourly", "never"
    #[serde(default = "default_rotation")]
    pub rotation: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            output: "stderr".into(),
            file_path: None,
            rotation: "daily".into(),
        }
    }
}

fn default_log_output() -> String {
    "stderr".into()
}
fn default_rotation() -> String {
    "daily".into()
}

/// Audit log configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct AuditConfig {
    #[serde(default = "default_redaction")]
    pub redaction: String,
    #[serde(default = "default_true")]
    pub record_ip: bool,
    #[serde(default = "default_audit_retention_days")]
    pub retention_days: u32,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            redaction: "literals".into(),
            record_ip: true,
            retention_days: 365,
        }
    }
}

fn default_redaction() -> String {
    "literals".into()
}
fn default_audit_retention_days() -> u32 {
    365
}

/// Result storage backend configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "backend", rename_all = "snake_case")]
pub enum ResultStorageConfig {
    Disabled,
    Local {
        root_dir: String,
    },
    S3 {
        bucket: String,
        region: String,
        endpoint: Option<String>,
    },
}

impl Default for ResultStorageConfig {
    fn default() -> Self {
        Self::Disabled
    }
}

/// Notification policy definition from TOML config.
#[derive(Debug, Clone, Deserialize)]
pub struct NotificationPolicyDef {
    pub database: String,
    pub environment: String,
    pub webhooks: Vec<crate::webhook::WebhookConfig>,
}

/// Execution policy definition from TOML config.
#[derive(Debug, Clone, Deserialize)]
pub struct ExecutionPolicyDef {
    pub database: String,
    pub environment: String,
    #[serde(default = "default_max_executions")]
    pub max_executions: u32,
    #[serde(default = "default_execution_window")]
    pub execution_window_secs: u64,
    #[serde(default)]
    pub retry_on_failure: bool,
}

fn default_max_executions() -> u32 {
    1
}
fn default_execution_window() -> u64 {
    86400
}

/// Access policy definition from TOML config.
#[derive(Debug, Clone, Deserialize)]
pub struct AccessPolicyDef {
    pub database: String,
    pub environment: String,
    #[serde(default)]
    pub allowed_roles: Vec<String>,
    #[serde(default)]
    pub allowed_groups: Vec<String>,
}

/// Result policy definition from TOML config.
#[derive(Debug, Clone, Deserialize)]
pub struct ResultPolicyDef {
    pub database: String,
    pub environment: String,
    #[serde(default = "default_delivery_mode")]
    pub delivery_mode: String,
    #[serde(default)]
    pub storage_config: Option<serde_json::Value>,
    #[serde(default = "default_access")]
    pub access: Vec<String>,
}

fn default_delivery_mode() -> String {
    "direct".into()
}
fn default_access() -> Vec<String> {
    vec!["requester".into(), "admin".into()]
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    #[serde(default = "default_auth_mode")]
    pub mode: String,
    pub oidc: Option<OidcConfig>,
    #[serde(default = "default_break_glass_roles")]
    pub break_glass_roles: Vec<String>,
}

pub const DEFAULT_BREAK_GLASS_ROLES: &[&str] = &["admin", "developer"];

pub fn default_break_glass_roles() -> Vec<String> {
    DEFAULT_BREAK_GLASS_ROLES
        .iter()
        .map(|role| (*role).to_string())
        .collect()
}

#[derive(Debug, Clone, Deserialize)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret_env: Option<String>,
    /// Override JWKS URI (for Docker environments where issuer URL is not reachable from server)
    pub jwks_uri: Option<String>,
    #[serde(default = "default_role")]
    pub default_role: String,
    #[serde(default)]
    pub role_mappings: Vec<RoleMapping>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RoleMapping {
    pub subject: Option<String>,
    pub claim: Option<String>,
    pub value: Option<String>,
    pub role: String,
}

fn default_listen() -> String {
    "127.0.0.1:3000".into()
}

fn default_data() -> String {
    "dbward.db".into()
}

fn default_auth_mode() -> String {
    "token".into()
}

fn default_role() -> String {
    "readonly".into()
}

impl ServerConfig {
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let mut value: toml::Value =
            toml::from_str(&content).map_err(|e| format!("{path:?}: {e}"))?;
        dbward_core::env_expand::expand_env_vars(&mut value)
            .map_err(|e| format!("{path:?}: {e}"))?;
        let config: Self = value.try_into().map_err(|e| format!("{path:?}: {e}"))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), String> {
        for (i, wh) in self.webhooks.iter().enumerate() {
            if let Some(ref secret) = wh.secret {
                if secret.trim().is_empty() {
                    return Err(format!(
                        "webhooks[{i}].secret must not be empty (remove the field to disable HMAC signing)"
                    ));
                }
            }
        }
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn load_returns_default_when_file_missing() {
        let config = ServerConfig::load(std::path::Path::new("/nonexistent/path.toml")).unwrap();
        // Default trait gives empty strings; serde defaults only apply during deserialization
        assert!(config.webhooks.is_empty());
        assert!(config.workflows.is_empty());
    }

    #[test]
    fn load_parses_minimal_toml() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, r#"listen = "0.0.0.0:9000""#).unwrap();
        let config = ServerConfig::load(f.path()).unwrap();
        assert_eq!(config.listen, "0.0.0.0:9000");
        assert_eq!(config.data, "dbward.db"); // default preserved
    }

    #[test]
    fn load_rejects_invalid_toml() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "not valid toml {{{{").unwrap();
        assert!(ServerConfig::load(f.path()).is_err());
    }

    #[test]
    fn validate_rejects_empty_webhook_secret() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(
            f,
            r#"
[[webhooks]]
url = "https://example.com/hook"
events = ["request_created"]
secret = "   "
"#
        )
        .unwrap();
        let err = ServerConfig::load(f.path()).unwrap_err();
        assert!(err.contains("secret must not be empty"));
    }

    #[test]
    fn validate_allows_webhook_without_secret() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(
            f,
            r#"
[[webhooks]]
url = "https://example.com/hook"
events = ["request_created"]
"#
        )
        .unwrap();
        assert!(ServerConfig::load(f.path()).is_ok());
    }

    #[test]
    fn retention_defaults() {
        let r = RetentionConfig::default();
        assert_eq!(r.request_ttl_days, 90);
        assert_eq!(r.audit_ttl_days, 365);
        assert_eq!(r.approval_ttl_secs, 86400);
    }

    #[test]
    fn load_parses_workflow() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(
            f,
            r#"
[[workflows]]
database = "app"
environment = "production"
operations = ["execute_query"]

[[workflows.steps]]
type = "approval"

[[workflows.steps.approvers]]
role = "admin"
min = 2
"#
        )
        .unwrap();
        let config = ServerConfig::load(f.path()).unwrap();
        assert_eq!(config.workflows.len(), 1);
        assert_eq!(config.workflows[0].steps[0].approvers[0].min, 2);
        assert_eq!(
            config.workflows[0].steps[0].approvers[0].role,
            Some("admin".into())
        );
    }

    #[test]
    fn workflow_step_defaults() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(
            f,
            r#"
[[workflows]]
database = "*"
environment = "*"

[[workflows.steps]]
type = "approval"

[[workflows.steps.approvers]]
role = "admin"
"#
        )
        .unwrap();
        let config = ServerConfig::load(f.path()).unwrap();
        let step = &config.workflows[0].steps[0];
        assert_eq!(step.mode, "all"); // default
        assert!(step.require_distinct_actors); // default true
        assert_eq!(step.approvers[0].min, 1); // default
    }
}
