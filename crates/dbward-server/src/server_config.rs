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
    pub auth: Option<AuthConfig>,
}

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
