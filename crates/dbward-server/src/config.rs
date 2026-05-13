use serde::Deserialize;
use std::path::Path;

/// Server configuration loaded from TOML.
#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default)]
    pub result_storage: ResultStorageConfig,
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
}

#[derive(Debug, Deserialize, Default)]
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

#[derive(Debug, Deserialize, Default)]
pub struct ResultStorageConfig {
    #[serde(default = "default_backend")]
    pub backend: String,
    #[serde(default = "default_root_dir")]
    pub root_dir: String,
    pub bucket: Option<String>,
    pub region: Option<String>,
    pub endpoint: Option<String>,
}

fn default_backend() -> String {
    "local".into()
}
fn default_root_dir() -> String {
    "./data/results".into()
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
        toml::from_str(&expanded).map_err(|e| format!("{}: {e}", path.display()))
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
