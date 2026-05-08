use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

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
    /// Internal base URL for OIDC HTTP calls when issuer is not directly reachable.
    /// All endpoint URLs from discovery have their issuer prefix replaced with this.
    /// Example: issuer=http://localhost:8080/realms/dbward, backchannel_url=http://keycloak:8080/realms/dbward
    pub backchannel_url: Option<String>,
    /// URL base shown to user for browser access (e.g. http://localhost:8080/realms/dbward)
    /// When set, replaces issuer host in displayed URLs like device flow verification_uri.
    pub browser_url: Option<String>,
}

impl ClientConfig {
    pub fn resolve_relative_paths(&mut self, base_dir: &Path) {
        self.migrations_dir = resolve_relative_path(base_dir, &self.migrations_dir);
        for db in self.databases.values_mut() {
            if let Some(path) = db.migrations_dir.as_mut() {
                *path = resolve_relative_path(base_dir, path);
            }
        }
    }

    /// Resolve which database name to use (no URL — client doesn't have it).
    pub fn resolve_database_name(&self, selected: Option<&str>) -> Result<String, Error> {
        if let Some(sel) = selected {
            if self.databases.contains_key(sel) || self.databases.is_empty() {
                return Ok(sel.to_string());
            }
            if !self.databases.contains_key(sel) {
                return Err(Error::Config(format!(
                    "database '{sel}' not found in config"
                )));
            }
        }
        if let Some(ref def) = self.default_database {
            return Ok(def.clone());
        }
        if self.databases.len() == 1 {
            return Ok(self.databases.keys().next().unwrap().clone());
        }
        if self.databases.is_empty() {
            if self.default_database.is_some() {
                // Already handled above; unreachable in practice
                return Ok("default".to_string());
            }
            return Err(Error::Config(
                "no database configured; use --database <name> or set default_database in config"
                    .into(),
            ));
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
            .unwrap_or_else(|| {
                if self.databases.len() <= 1 {
                    self.migrations_dir.clone()
                } else {
                    self.migrations_dir.join(db_name)
                }
            })
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
    #[serde(default = "default_drain_timeout")]
    pub drain_timeout_secs: u64,
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent_tasks: u32,
    /// DB-level statement timeout in seconds (default: 30). Set to 0 to disable.
    pub statement_timeout_secs: Option<u64>,
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
    pub statement_timeout_secs: Option<u64>,
}

impl AgentConfig {
    pub fn validate(&self) -> Result<(), Error> {
        if self.agent_id.trim().is_empty() {
            return Err(Error::Config("agent_id must not be empty".into()));
        }
        if !self.server.url.starts_with("http://") && !self.server.url.starts_with("https://") {
            return Err(Error::Config(format!(
                "server.url must start with http:// or https://, got: {}",
                self.server.url
            )));
        }
        if self.server.agent_token.trim().is_empty() {
            return Err(Error::Config("server.agent_token must not be empty".into()));
        }
        if self.databases.is_empty() {
            return Err(Error::Config(
                "at least one [databases.*] section must be configured".into(),
            ));
        }
        for cap_db in &self.capabilities.databases {
            if !self.databases.contains_key(cap_db) {
                return Err(Error::Config(format!(
                    "capabilities.databases contains '{cap_db}' but no [databases.{cap_db}] section exists"
                )));
            }
        }
        Ok(())
    }

    pub fn resolve_relative_paths(&mut self, base_dir: &Path) {
        for db in self.databases.values_mut() {
            if let Some(path) = db.migrations_dir.as_mut() {
                *path = resolve_relative_path(base_dir, path);
            }
        }
    }

    pub fn resolve_database(&self, name: &str) -> Result<ResolvedDatabaseConfig, Error> {
        let db = self
            .databases
            .get(name)
            .ok_or_else(|| Error::Config(format!("database '{name}' not configured in agent")))?;
        let migrations_dir = db.migrations_dir.clone().unwrap_or_else(|| {
            if self.databases.len() <= 1 {
                PathBuf::from("db/migrations")
            } else {
                PathBuf::from("db/migrations").join(name)
            }
        });
        Ok(ResolvedDatabaseConfig {
            name: name.to_string(),
            url: db.url.clone(),
            migrations_dir,
            statement_timeout_secs: self.statement_timeout_secs.or(Some(30)),
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
fn default_drain_timeout() -> u64 {
    60
}
fn default_max_concurrent() -> u32 {
    2
}

fn resolve_relative_path(base_dir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_config_resolve_single_db() {
        let config: ClientConfig = toml::from_str(
            r#"
            [server]
            url = "http://localhost:3000"
            [databases.app]
        "#,
        )
        .unwrap();
        assert_eq!(config.resolve_database_name(None).unwrap(), "app");
    }

    #[test]
    fn client_config_resolve_by_name() {
        let config: ClientConfig = toml::from_str(
            r#"
            [server]
            url = "http://localhost:3000"
            [databases.primary]
            [databases.analytics]
        "#,
        )
        .unwrap();
        assert_eq!(
            config.resolve_database_name(Some("analytics")).unwrap(),
            "analytics"
        );
    }

    #[test]
    fn client_config_resolve_default() {
        let config: ClientConfig = toml::from_str(
            r#"
            default_database = "primary"
            [server]
            url = "http://localhost:3000"
            [databases.primary]
            [databases.analytics]
        "#,
        )
        .unwrap();
        assert_eq!(config.resolve_database_name(None).unwrap(), "primary");
    }

    #[test]
    fn client_config_multiple_without_default_errors() {
        let config: ClientConfig = toml::from_str(
            r#"
            [server]
            url = "http://localhost:3000"
            [databases.a]
            [databases.b]
        "#,
        )
        .unwrap();
        assert!(config.resolve_database_name(None).is_err());
    }

    #[test]
    fn client_config_empty_databases_errors_without_default() {
        let config: ClientConfig = toml::from_str(
            r#"
            [server]
            url = "http://localhost:3000"
        "#,
        )
        .unwrap();
        assert!(config.resolve_database_name(None).is_err());
    }

    #[test]
    fn client_config_default_database_used_when_no_databases() {
        let config: ClientConfig = toml::from_str(
            r#"
            default_database = "myapp"
            [server]
            url = "http://localhost:3000"
        "#,
        )
        .unwrap();
        assert_eq!(config.resolve_database_name(None).unwrap(), "myapp");
    }

    #[test]
    fn client_config_migrations_dir() {
        let config: ClientConfig = toml::from_str(
            r#"
            [server]
            url = "http://localhost:3000"
            [databases.app]
            migrations_dir = "custom/migrations"
        "#,
        )
        .unwrap();
        assert_eq!(
            config.migrations_dir_for("app"),
            PathBuf::from("custom/migrations")
        );
        assert_eq!(
            config.migrations_dir_for("other"),
            PathBuf::from("db/migrations")
        );
    }

    #[test]
    fn client_config_migrations_dir_multiple_databases_uses_database_subdir() {
        let config: ClientConfig = toml::from_str(
            r#"
            [server]
            url = "http://localhost:3000"
            [databases.primary]
            [databases.analytics]
        "#,
        )
        .unwrap();
        assert_eq!(
            config.migrations_dir_for("analytics"),
            PathBuf::from("db/migrations/analytics")
        );
    }

    #[test]
    fn client_config_resolve_relative_paths_from_config_dir() {
        let mut config: ClientConfig = toml::from_str(
            r#"
            migrations_dir = "db/migrations"
            [server]
            url = "http://localhost:3000"
            [databases.app]
            migrations_dir = "db/custom"
        "#,
        )
        .unwrap();
        config.resolve_relative_paths(Path::new("/workspace/services/user-service"));
        assert_eq!(
            config.migrations_dir,
            PathBuf::from("/workspace/services/user-service/db/migrations")
        );
        assert_eq!(
            config.migrations_dir_for("app"),
            PathBuf::from("/workspace/services/user-service/db/custom")
        );
    }

    #[test]
    fn agent_config_parse() {
        let config: AgentConfig = toml::from_str(
            r#"
            agent_id = "agent-1"
            [server]
            url = "http://localhost:3000"
            agent_token = "agt_secret"
            [databases.app]
            url = "postgres://localhost/app"
        "#,
        )
        .unwrap();
        assert_eq!(config.agent_id, "agent-1");
        let r = config.resolve_database("app").unwrap();
        assert_eq!(r.url, "postgres://localhost/app");
        assert_eq!(r.migrations_dir, PathBuf::from("db/migrations"));
    }

    #[test]
    fn agent_config_resolve_unknown_errors() {
        let config: AgentConfig = toml::from_str(
            r#"
            agent_id = "agent-1"
            [server]
            url = "http://localhost:3000"
            agent_token = "agt_secret"
            [databases.app]
            url = "postgres://localhost/app"
        "#,
        )
        .unwrap();
        assert!(config.resolve_database("unknown").is_err());
    }

    #[test]
    fn agent_config_multiple_databases_default_to_named_subdir() {
        let config: AgentConfig = toml::from_str(
            r#"
            agent_id = "agent-1"
            [server]
            url = "http://localhost:3000"
            agent_token = "agt_secret"
            [databases.primary]
            url = "postgres://localhost/app"
            [databases.analytics]
            url = "postgres://localhost/analytics"
        "#,
        )
        .unwrap();
        assert_eq!(
            config.resolve_database("analytics").unwrap().migrations_dir,
            PathBuf::from("db/migrations/analytics")
        );
    }

    #[test]
    fn agent_config_resolve_relative_paths_from_config_dir() {
        let mut config: AgentConfig = toml::from_str(
            r#"
            agent_id = "agent-1"
            [server]
            url = "http://localhost:3000"
            agent_token = "agt_secret"
            [databases.app]
            url = "postgres://localhost/app"
            migrations_dir = "db/custom"
        "#,
        )
        .unwrap();
        config.resolve_relative_paths(Path::new("/workspace/infra"));
        assert_eq!(
            config.resolve_database("app").unwrap().migrations_dir,
            PathBuf::from("/workspace/infra/db/custom")
        );
    }
}
