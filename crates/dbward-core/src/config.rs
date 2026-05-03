use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::Error;

// ---------------------------------------------------------------------------
// Client config (dbward.toml) — no DB credentials
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub default_database: Option<String>,
    #[serde(default = "default_migrations_dir")]
    pub migrations_dir: PathBuf,
    pub server: ServerConfig,
    #[serde(default)]
    pub databases: BTreeMap<String, ClientDatabaseConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientDatabaseConfig {
    pub migrations_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub url: String,
    pub token: Option<String>,
    pub oidc: Option<ClientOidcConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientOidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub discovery_url: Option<String>,
}

impl ClientConfig {
    /// Resolve which database name to use (no URL — client doesn't have it).
    pub fn resolve_database_name(&self, selected: Option<&str>) -> Result<String, Error> {
        if let Some(sel) = selected {
            if self.databases.contains_key(sel) || self.databases.is_empty() {
                return Ok(sel.to_string());
            }
            if !self.databases.contains_key(sel) {
                return Err(Error::Config(format!("database '{sel}' not found in config")));
            }
        }
        if let Some(ref def) = self.default_database {
            return Ok(def.clone());
        }
        if self.databases.len() == 1 {
            return Ok(self.databases.keys().next().unwrap().clone());
        }
        if self.databases.is_empty() {
            return Ok("default".to_string());
        }
        Err(Error::Config(
            "multiple databases configured; use --database <name> or set default_database".into(),
        ))
    }

    /// Resolve migrations_dir for a given database name.
    pub fn migrations_dir_for(&self, db_name: &str) -> PathBuf {
        self.databases
            .get(db_name)
            .and_then(|d| d.migrations_dir.clone())
            .unwrap_or_else(|| self.migrations_dir.join(db_name))
    }
}

// ---------------------------------------------------------------------------
// Agent config (dbward-agent.toml) — has DB credentials
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub agent_id: String,
    #[serde(default = "default_poll_interval")]
    pub poll_interval_ms: u64,
    #[serde(default = "default_lease_duration")]
    pub lease_duration_secs: u64,
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent_tasks: u32,
    pub server: AgentServerConfig,
    #[serde(default)]
    pub capabilities: AgentCapabilities,
    pub databases: BTreeMap<String, AgentDatabaseConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentServerConfig {
    pub url: String,
    pub agent_token: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentCapabilities {
    #[serde(default)]
    pub environments: Vec<String>,
    #[serde(default)]
    pub databases: Vec<String>,
    #[serde(default)]
    pub operations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentDatabaseConfig {
    pub url: String,
    pub migrations_dir: Option<PathBuf>,
}

/// Resolved database config with URL — only agent produces this.
#[derive(Debug, Clone)]
pub struct ResolvedDatabaseConfig {
    pub name: String,
    pub url: String,
    pub migrations_dir: PathBuf,
}

impl AgentConfig {
    pub fn resolve_database(&self, name: &str) -> Result<ResolvedDatabaseConfig, Error> {
        let db = self
            .databases
            .get(name)
            .ok_or_else(|| Error::Config(format!("database '{name}' not configured in agent")))?;
        let migrations_dir = db
            .migrations_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("db/migrations").join(name));
        Ok(ResolvedDatabaseConfig {
            name: name.to_string(),
            url: db.url.clone(),
            migrations_dir,
        })
    }
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

fn default_migrations_dir() -> PathBuf {
    PathBuf::from("db/migrations")
}
fn default_poll_interval() -> u64 {
    1000
}
fn default_lease_duration() -> u64 {
    300
}
fn default_max_concurrent() -> u32 {
    2
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_config_resolve_single_db() {
        let config: ClientConfig = toml::from_str(r#"
            [server]
            url = "http://localhost:3000"
            [databases.app]
        "#).unwrap();
        assert_eq!(config.resolve_database_name(None).unwrap(), "app");
    }

    #[test]
    fn client_config_resolve_by_name() {
        let config: ClientConfig = toml::from_str(r#"
            [server]
            url = "http://localhost:3000"
            [databases.primary]
            [databases.analytics]
        "#).unwrap();
        assert_eq!(config.resolve_database_name(Some("analytics")).unwrap(), "analytics");
    }

    #[test]
    fn client_config_resolve_default() {
        let config: ClientConfig = toml::from_str(r#"
            default_database = "primary"
            [server]
            url = "http://localhost:3000"
            [databases.primary]
            [databases.analytics]
        "#).unwrap();
        assert_eq!(config.resolve_database_name(None).unwrap(), "primary");
    }

    #[test]
    fn client_config_multiple_without_default_errors() {
        let config: ClientConfig = toml::from_str(r#"
            [server]
            url = "http://localhost:3000"
            [databases.a]
            [databases.b]
        "#).unwrap();
        assert!(config.resolve_database_name(None).is_err());
    }

    #[test]
    fn client_config_empty_databases_returns_default() {
        let config: ClientConfig = toml::from_str(r#"
            [server]
            url = "http://localhost:3000"
        "#).unwrap();
        assert_eq!(config.resolve_database_name(None).unwrap(), "default");
    }

    #[test]
    fn client_config_migrations_dir() {
        let config: ClientConfig = toml::from_str(r#"
            [server]
            url = "http://localhost:3000"
            [databases.app]
            migrations_dir = "custom/migrations"
        "#).unwrap();
        assert_eq!(config.migrations_dir_for("app"), PathBuf::from("custom/migrations"));
        assert_eq!(config.migrations_dir_for("other"), PathBuf::from("db/migrations/other"));
    }

    #[test]
    fn agent_config_parse() {
        let config: AgentConfig = toml::from_str(r#"
            agent_id = "agent-1"
            [server]
            url = "http://localhost:3000"
            agent_token = "agt_secret"
            [databases.app]
            url = "postgres://localhost/app"
        "#).unwrap();
        assert_eq!(config.agent_id, "agent-1");
        let r = config.resolve_database("app").unwrap();
        assert_eq!(r.url, "postgres://localhost/app");
    }

    #[test]
    fn agent_config_resolve_unknown_errors() {
        let config: AgentConfig = toml::from_str(r#"
            agent_id = "agent-1"
            [server]
            url = "http://localhost:3000"
            agent_token = "agt_secret"
            [databases.app]
            url = "postgres://localhost/app"
        "#).unwrap();
        assert!(config.resolve_database("unknown").is_err());
    }
}
