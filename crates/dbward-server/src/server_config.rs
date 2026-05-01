use serde::Deserialize;

use crate::webhook::WebhookConfig;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ServerConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default = "default_data")]
    pub data: String,
    #[serde(default)]
    pub webhooks: Vec<WebhookConfig>,
}

fn default_listen() -> String {
    "127.0.0.1:3000".into()
}

fn default_data() -> String {
    "dbward.db".into()
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
