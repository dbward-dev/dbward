use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde::Deserialize;

use crate::ConfigError;
use crate::expand::expand_env_vars;

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
    pub execution_policies: Vec<ExecutionPolicyDef>,
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
    pub auto_approve: Vec<AutoApproveConfig>,
    #[serde(default)]
    pub slack: Option<SlackConfig>,
}

impl ServerConfig {
    /// Load, expand env vars, parse, and validate in one step.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        Self::from_str(&content, &path.display().to_string())
    }

    /// Parse from TOML string. Expands env vars and validates.
    pub fn from_str(input: &str, source: &str) -> Result<Self, ConfigError> {
        let expanded = expand_env_vars(input)?;
        let cfg: Self = toml::from_str(&expanded).map_err(|e| ConfigError::Parse {
            path: source.to_string(),
            message: e.to_string(),
        })?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.retention.approval_ttl_secs == 0 {
            return Err(ConfigError::Validation(
                "retention.approval_ttl_secs must be > 0 (immediate expiry makes approval impossible)".into(),
            ));
        }

        // Workflow operations overlap within same (db, env) scope
        type ScopeEntries = Vec<(usize, Vec<String>)>;
        let mut scope_ops: HashMap<(&str, &str), ScopeEntries> = HashMap::new();
        for (i, wf) in self.workflows.iter().enumerate() {
            scope_ops
                .entry((wf.database.as_str(), wf.environment.as_str()))
                .or_default()
                .push((i, wf.operations.clone()));
        }
        for ((db, env), entries) in &scope_ops {
            let has_catchall = entries.iter().any(|(_, ops)| ops.is_empty());
            if has_catchall && entries.len() > 1 {
                return Err(ConfigError::Validation(format!(
                    "workflow validation: database={db}, environment={env} has both catchall (operations omitted) and specific operations workflows — ambiguous"
                )));
            }
            let mut seen: HashSet<&str> = HashSet::new();
            for (idx, ops) in entries {
                for op in ops {
                    if !seen.insert(op.as_str()) {
                        return Err(ConfigError::Validation(format!(
                            "workflow validation: operation '{op}' appears in multiple workflows for database={db}, environment={env} (workflow index {idx})"
                        )));
                    }
                }
            }
        }

        // Auto-approve scope uniqueness
        let mut aa_scopes: HashSet<(&str, &str)> = HashSet::new();
        for a in &self.auto_approve {
            if !aa_scopes.insert((a.database.as_str(), a.environment.as_str())) {
                return Err(ConfigError::Validation(format!(
                    "auto_approve validation: duplicate scope (database={}, environment={})",
                    a.database, a.environment
                )));
            }
        }

        // Execution policy timeout consistency
        for (i, ep) in self.execution_policies.iter().enumerate() {
            if let (Some(st), Some(max_st)) =
                (ep.statement_timeout_secs, ep.max_statement_timeout_secs)
                && st > max_st
            {
                return Err(ConfigError::Validation(format!(
                    "execution_policies[{i}]: statement_timeout_secs must not exceed max_statement_timeout_secs"
                )));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Sub-types
// ---------------------------------------------------------------------------

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
#[serde(deny_unknown_fields)]
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
    pub allow_self_approve: bool,
    #[serde(default = "default_true")]
    pub allow_same_approver_across_steps: bool,
    #[serde(default = "default_true")]
    pub explain: bool,
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

#[derive(Debug, Deserialize)]
pub struct ExecutionPolicyDef {
    #[serde(default = "star")]
    pub database: String,
    #[serde(default = "star")]
    pub environment: String,
    #[serde(default)]
    pub max_executions: Option<u32>,
    #[serde(default)]
    pub execution_window_secs: Option<u64>,
    #[serde(default)]
    pub retry_on_failure: Option<bool>,
    #[serde(default)]
    pub statement_timeout_secs: Option<u32>,
    #[serde(default)]
    pub max_statement_timeout_secs: Option<u32>,
    #[serde(default)]
    pub max_rows: Option<u32>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutoApproveConfig {
    #[serde(default = "star")]
    pub database: String,
    #[serde(default = "star")]
    pub environment: String,
    #[serde(default = "default_risk_none")]
    pub risk: String,
    #[serde(default = "default_allow_read_only")]
    pub allow_read_only: bool,
    #[serde(default = "default_allow_safe_ddl")]
    pub allow_safe_ddl: bool,
    #[serde(default = "default_max_estimated_rows")]
    pub max_estimated_rows: u64,
}

fn default_risk_none() -> String {
    "none".into()
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

#[derive(Debug, Deserialize)]
pub struct SlackConfig {
    pub bot_token: String,
    pub signing_secret: String,
    #[serde(default = "default_slack_channel")]
    pub channel: String,
    #[serde(default)]
    pub channels: HashMap<String, String>,
}

fn default_slack_channel() -> String {
    "#db-approvals".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_valid_config() {
        let toml = r#"
[[databases]]
name = "app"
environments = ["dev"]

[[workflows]]
database = "*"
environment = "*"
"#;
        let cfg = ServerConfig::from_str(toml, "test").unwrap();
        assert_eq!(cfg.databases.len(), 1);
        assert_eq!(cfg.retention.approval_ttl_secs, 86400);
    }

    #[test]
    fn rejects_zero_approval_ttl() {
        let toml = r#"
[retention]
approval_ttl_secs = 0
"#;
        let err = ServerConfig::from_str(toml, "test").unwrap_err();
        assert!(err.to_string().contains("approval_ttl_secs"));
    }

    #[test]
    fn rejects_timeout_exceeding_max() {
        let toml = r#"
[[execution_policies]]
statement_timeout_secs = 500
max_statement_timeout_secs = 300
"#;
        let err = ServerConfig::from_str(toml, "test").unwrap_err();
        assert!(err.to_string().contains("must not exceed"));
    }

    #[test]
    fn rejects_duplicate_auto_approve_scope() {
        let toml = r#"
[[auto_approve]]
database = "app"
environment = "dev"

[[auto_approve]]
database = "app"
environment = "dev"
"#;
        let err = ServerConfig::from_str(toml, "test").unwrap_err();
        assert!(err.to_string().contains("duplicate scope"));
    }
}
