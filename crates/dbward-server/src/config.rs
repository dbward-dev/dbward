use std::path::Path;
use serde::Deserialize;

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

fn default_backend() -> String { "local".into() }
fn default_root_dir() -> String { "./data/results".into() }

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
}

fn star() -> String { "*".into() }

#[derive(Debug, Deserialize)]
pub struct WebhookDef {
    pub url: String,
    #[serde(default)]
    pub events: Vec<String>,
    pub secret: Option<String>,
}

impl ServerConfig {
    pub fn load(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        toml::from_str(&content)
            .map_err(|e| format!("{}: {e}", path.display()))
    }
}
