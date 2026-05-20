use serde::Deserialize;
use std::path::Path;

/// Server configuration loaded from TOML.
#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default)]
    pub result_storage: ResultStorageConfig,
    #[serde(default)]
    pub result_channel: ResultChannelConfig,
    #[serde(default)]
    pub databases: Vec<DatabaseDef>,
    #[serde(default)]
    pub workflows: Vec<WorkflowDef>,
    #[serde(default)]
    pub webhooks: Vec<WebhookDef>,
    #[serde(default)]
    pub retention: RetentionConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    #[serde(default)]
    pub sql_review: SqlReviewConfig,
    #[serde(default)]
    pub auto_approve: AutoApproveServerConfig,
}

#[derive(Debug, Deserialize)]
pub struct RetentionConfig {
    #[serde(default = "default_request_ttl")]
    pub request_ttl_days: u64,
    #[serde(default = "default_audit_ttl")]
    pub audit_ttl_days: u64,
    #[serde(default = "default_result_ttl")]
    pub result_ttl_days: u64,
    #[serde(default = "default_approval_ttl")]
    pub approval_ttl_secs: u64,
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

fn default_request_ttl() -> u64 {
    90
}
fn default_audit_ttl() -> u64 {
    365
}
fn default_result_ttl() -> u64 {
    30
}
fn default_approval_ttl() -> u64 {
    86400
}

#[derive(Debug, Deserialize, Default)]
pub struct AuthConfig {
    #[serde(default = "default_auth_mode")]
    pub mode: String,
    #[serde(default)]
    pub oidc: Option<OidcConfig>,
    #[serde(default)]
    pub role_bindings: Vec<RoleBinding>,
    pub default_role: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RoleBinding {
    pub role: String,
    #[serde(default)]
    pub subjects: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct OidcConfig {
    #[serde(alias = "issuer")]
    pub issuer_url: String,
    #[serde(default)]
    pub audience: String,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub role_mappings: Vec<OidcRoleMapping>,
    pub default_role: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OidcRoleMapping {
    pub claim: String,
    pub value: String,
    pub role: String,
}

fn default_auth_mode() -> String {
    "both".into()
}

#[derive(Debug, Deserialize, Default)]
pub struct AuditConfig {
    #[serde(default = "default_redaction")]
    pub redaction: String,
}

fn default_redaction() -> String {
    "literals".into()
}

#[derive(Debug, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub format: LogFormat,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            format: LogFormat::Text,
        }
    }
}

fn default_log_level() -> String {
    "info".into()
}

#[derive(Debug, Deserialize, Default, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

#[derive(Debug, Deserialize, Default)]
pub struct ResultStorageConfig {
    #[serde(default = "default_backend")]
    pub backend: String,
    #[serde(default = "default_root_dir")]
    pub root_dir: String,
    pub bucket: Option<String>,
    pub region: Option<String>,
    pub endpoint: Option<String>,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    #[serde(default)]
    pub path_style: bool,
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default = "default_max_persist_bytes")]
    pub max_persist_bytes: usize,
}

fn default_backend() -> String {
    "local".into()
}
fn default_root_dir() -> String {
    "./data/results".into()
}
fn default_max_persist_bytes() -> usize {
    10 * 1024 * 1024
}

#[derive(Debug, Deserialize)]
pub struct ResultChannelConfig {
    #[serde(default = "default_max_slots")]
    pub max_slots: usize,
    #[serde(default = "default_slot_ttl_secs")]
    pub slot_ttl_secs: u64,
}

impl Default for ResultChannelConfig {
    fn default() -> Self {
        Self {
            max_slots: default_max_slots(),
            slot_ttl_secs: default_slot_ttl_secs(),
        }
    }
}

fn default_max_slots() -> usize {
    10_000
}
fn default_slot_ttl_secs() -> u64 {
    600
}

#[derive(Debug, Deserialize)]
pub struct DatabaseDef {
    pub name: String,
    #[serde(default)]
    pub environments: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct WorkflowDef {
    #[serde(default = "star")]
    pub database: String,
    #[serde(default = "star")]
    pub environment: String,
    #[serde(default)]
    pub operations: Vec<String>,
    #[serde(default)]
    pub steps: Vec<serde_json::Value>,
    #[serde(default)]
    pub require_reason: bool,
    #[serde(default)]
    pub skip_approval_for: Vec<String>,
    #[serde(default)]
    pub allow_self_approve: bool,
    #[serde(default = "default_true")]
    pub allow_same_approver_across_steps: bool,
    #[serde(default)]
    pub require_approval: bool,
    #[serde(default)]
    pub pending_ttl_secs: Option<u64>,
    #[serde(default)]
    pub statement_timeout_secs: Option<u64>,
}

fn default_true() -> bool {
    true
}

fn star() -> String {
    "*".into()
}

#[derive(Debug, Deserialize)]
pub struct WebhookDef {
    pub url: String,
    #[serde(default)]
    pub events: Vec<String>,
    #[serde(default = "default_webhook_format")]
    pub format: String,
    pub secret: Option<String>,
}

fn default_webhook_format() -> String {
    "generic".into()
}

impl ServerConfig {
    pub fn load(path: &Path) -> Result<Self, String> {
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let expanded = expand_env_vars(&content)?;
        let cfg: Self =
            toml::from_str(&expanded).map_err(|e| format!("{}: {e}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), String> {
        if self.retention.approval_ttl_secs == 0 {
            return Err(
                "retention.approval_ttl_secs must be > 0 (immediate expiry makes approval impossible)".into(),
            );
        }
        Ok(())
    }
}

fn expand_env_vars(input: &str) -> Result<String, String> {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' && chars.peek() == Some(&'{') {
            chars.next();
            let mut var_name = String::new();
            for ch in chars.by_ref() {
                if ch == '}' {
                    break;
                }
                var_name.push(ch);
            }
            let val = std::env::var(&var_name)
                .map_err(|_| format!("undefined environment variable: ${{{var_name}}}"))?;
            result.push_str(&val);
        } else {
            result.push(c);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_config_default_has_correct_values() {
        let cfg = RetentionConfig::default();
        assert_eq!(cfg.request_ttl_days, 90);
        assert_eq!(cfg.audit_ttl_days, 365);
        assert_eq!(cfg.result_ttl_days, 30);
        assert_eq!(cfg.approval_ttl_secs, 86400);
    }

    #[test]
    fn server_config_without_retention_section_uses_defaults() {
        let toml = r#"
[[databases]]
name = "app"
environments = ["development"]

[[workflows]]
database = "*"
environment = "*"
"#;
        let cfg: ServerConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.retention.approval_ttl_secs, 86400);
    }

    #[test]
    fn validate_rejects_zero_approval_ttl() {
        let toml = r#"
[retention]
approval_ttl_secs = 0
"#;
        let cfg: ServerConfig = toml::from_str(toml).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("approval_ttl_secs must be > 0"));
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct SqlReviewConfig {
    #[serde(default = "default_warn")]
    pub no_where_delete: String,
    #[serde(default = "default_warn")]
    pub no_where_update: String,
    #[serde(default = "default_warn")]
    pub drop_table: String,
    #[serde(default = "default_warn")]
    pub drop_column: String,
    #[serde(default = "default_warn")]
    pub not_null_without_default: String,
    #[serde(default = "default_warn")]
    pub create_index_not_concurrently: String,
    #[serde(default = "default_warn")]
    pub alter_column_type: String,
    #[serde(default = "default_warn")]
    pub truncate: String,
    #[serde(default = "default_warn")]
    pub mixed_ddl_dml: String,
    #[serde(default = "default_warn")]
    pub large_in_list: String,
}

fn default_warn() -> String {
    "warn".into()
}

impl SqlReviewConfig {
    pub fn to_review_rules(&self) -> dbward_domain::services::sql_reviewer::ReviewRules {
        use dbward_domain::services::sql_reviewer::{ReviewRules, RuleAction};
        fn parse_action(s: &str) -> RuleAction {
            match s {
                "block" => RuleAction::Block,
                "off" => RuleAction::Off,
                _ => RuleAction::Warn,
            }
        }
        ReviewRules {
            no_where_delete: parse_action(&self.no_where_delete),
            no_where_update: parse_action(&self.no_where_update),
            drop_table: parse_action(&self.drop_table),
            drop_column: parse_action(&self.drop_column),
            not_null_without_default: parse_action(&self.not_null_without_default),
            create_index_not_concurrently: parse_action(&self.create_index_not_concurrently),
            alter_column_type: parse_action(&self.alter_column_type),
            truncate: parse_action(&self.truncate),
            mixed_ddl_dml: parse_action(&self.mixed_ddl_dml),
            large_in_list: parse_action(&self.large_in_list),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct AutoApproveServerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_max_risk")]
    pub max_risk_level: String,
    #[serde(default = "default_allow_read_only")]
    pub allow_read_only: bool,
    #[serde(default = "default_allow_safe_ddl")]
    pub allow_safe_ddl: bool,
    #[serde(default = "default_max_estimated_rows")]
    pub max_estimated_rows: u64,
}

fn default_max_risk() -> String {
    "low".into()
}

fn default_allow_read_only() -> bool {
    true
}

fn default_allow_safe_ddl() -> bool {
    true
}

fn default_max_estimated_rows() -> u64 {
    1000
}

impl Default for AutoApproveServerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_risk_level: default_max_risk(),
            allow_read_only: default_allow_read_only(),
            allow_safe_ddl: default_allow_safe_ddl(),
            max_estimated_rows: default_max_estimated_rows(),
        }
    }
}

impl AutoApproveServerConfig {
    pub fn to_auto_approve_config(
        &self,
    ) -> dbward_domain::services::workflow_matcher::AutoApproveConfig {
        use dbward_domain::services::risk_scorer::RiskLevel;
        use dbward_domain::services::workflow_matcher::AutoApproveConfig;
        let max = match self.max_risk_level.as_str() {
            "medium" => RiskLevel::Medium,
            "high" => RiskLevel::High,
            _ => RiskLevel::Low,
        };
        AutoApproveConfig {
            enabled: self.enabled,
            max_risk_level: max,
            allow_safe_ddl: self.allow_safe_ddl,
        }
    }
}
