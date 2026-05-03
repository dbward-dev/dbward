use serde::Deserialize;

use crate::policy::PolicyConfig;
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
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct WorkflowStep {
    #[serde(rename = "type")]
    pub step_type: String,
    #[serde(default = "default_min_approvals")]
    pub min_approvals: u32,
    #[serde(default)]
    pub allowed_roles: Vec<String>,
    #[serde(default = "default_true")]
    pub require_distinct_actors: bool,
}

fn default_min_approvals() -> u32 { 1 }
fn default_true() -> bool { true }

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
    pub policy: PolicyConfig,
    #[serde(default)]
    pub workflows: Vec<WorkflowDef>,
    #[serde(default)]
    pub execution_policies: Vec<ExecutionPolicyDef>,
    #[serde(default)]
    pub result_policies: Vec<ResultPolicyDef>,
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

fn default_max_executions() -> u32 { 1 }
fn default_execution_window() -> u64 { 86400 }

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

fn default_delivery_mode() -> String { "direct".into() }
fn default_access() -> Vec<String> { vec!["requester".into(), "admin".into()] }

#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    #[serde(default = "default_auth_mode")]
    pub mode: String,
    pub oidc: Option<OidcConfig>,
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
        toml::from_str(&content).map_err(|e| format!("{path:?}: {e}"))
    }
}
