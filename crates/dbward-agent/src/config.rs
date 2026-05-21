use serde::Deserialize;
use std::collections::HashMap;
use std::fmt;

use crate::AgentError;

#[derive(Clone, Deserialize)]
pub struct AgentConfig {
    pub agent_id: Option<String>,
    pub poll_interval_ms: Option<u64>,
    pub max_concurrent_tasks: Option<u32>,
    pub drain_timeout_secs: Option<u64>,
    pub statement_timeout_secs: Option<u64>,
    // TODO(v0.2): send to server during poll so lease = max(policy, agent_requested)
    pub lease_duration_secs: Option<u64>,
    pub operations: Option<Vec<String>>,
    pub startup_retry_initial_ms: Option<u64>,
    pub startup_retry_max_ms: Option<u64>,
    pub startup_max_wait_secs: Option<u64>,
    #[serde(default)]
    pub schema_sync: SchemaSyncConfig,
    pub server: ServerConfig,
    pub databases: HashMap<String, HashMap<String, DatabaseEntry>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SchemaSyncConfig {
    pub enabled: bool,
    pub sync_on_startup: bool,
    pub interval_secs: u64,
}

impl Default for SchemaSyncConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sync_on_startup: true,
            interval_secs: 0,
        }
    }
}

#[derive(Clone, Deserialize)]
pub struct ServerConfig {
    pub url: String,
    pub agent_token: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseEntry {
    pub url: String,
}

impl AgentConfig {
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, AgentError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| AgentError::Config(format!("{}: {e}", path.display())))?;
        Self::from_toml(&content)
    }

    pub fn from_toml(input: &str) -> Result<Self, AgentError> {
        let expanded = expand_env_vars(input);
        let config: Self =
            toml::from_str(&expanded).map_err(|e| AgentError::Config(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), AgentError> {
        if !self.server.url.starts_with("http://") && !self.server.url.starts_with("https://") {
            return Err(AgentError::Config(
                "server.url must have http or https scheme".into(),
            ));
        }
        if self.databases.is_empty() {
            return Err(AgentError::Config(
                "at least 1 database must be configured".into(),
            ));
        }
        Ok(())
    }

    pub fn agent_id(&self) -> String {
        self.agent_id.clone().unwrap_or_else(|| {
            hostname::get()
                .map(|h| h.to_string_lossy().into())
                .unwrap_or_else(|_| "unknown".into())
        })
    }

    pub fn poll_interval_ms(&self) -> u64 {
        self.poll_interval_ms.unwrap_or(1000)
    }

    pub fn max_concurrent_tasks(&self) -> u32 {
        self.max_concurrent_tasks.unwrap_or(2)
    }

    pub fn drain_timeout_secs(&self) -> u64 {
        self.drain_timeout_secs.unwrap_or(60)
    }

    pub fn statement_timeout_secs(&self) -> u64 {
        self.statement_timeout_secs.unwrap_or(30)
    }

    pub fn lease_duration_secs(&self) -> u64 {
        self.lease_duration_secs.unwrap_or(300)
    }

    pub fn operations(&self) -> Vec<String> {
        self.operations.clone().unwrap_or_else(|| {
            vec![
                "execute_select".into(),
                "execute_dml".into(),
                "migrate_up".into(),
                "migrate_down".into(),
                "migrate_status".into(),
            ]
        })
    }

    pub fn startup_retry_initial_ms(&self) -> u64 {
        self.startup_retry_initial_ms.unwrap_or(1000)
    }

    pub fn startup_retry_max_ms(&self) -> u64 {
        self.startup_retry_max_ms.unwrap_or(15000)
    }

    pub fn startup_max_wait_secs(&self) -> u64 {
        self.startup_max_wait_secs.unwrap_or(0)
    }
}

impl fmt::Debug for AgentConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentConfig")
            .field("agent_id", &self.agent_id)
            .field("poll_interval_ms", &self.poll_interval_ms)
            .field("max_concurrent_tasks", &self.max_concurrent_tasks)
            .field("drain_timeout_secs", &self.drain_timeout_secs)
            .field("statement_timeout_secs", &self.statement_timeout_secs)
            .field("lease_duration_secs", &self.lease_duration_secs)
            .field("operations", &self.operations)
            .field("server", &self.server)
            .field("databases", &self.databases)
            .finish()
    }
}

impl fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConfig")
            .field("url", &self.url)
            .field("agent_token", &"[REDACTED]")
            .finish()
    }
}

fn expand_env_vars(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' && chars.peek() == Some(&'{') {
            chars.next(); // consume '{'
            let mut var_name = String::new();
            for ch in chars.by_ref() {
                if ch == '}' {
                    break;
                }
                var_name.push(ch);
            }
            result.push_str(&std::env::var(&var_name).unwrap_or_default());
        } else {
            result.push(c);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_config() {
        let toml = r#"
[server]
url = "http://localhost:8080"
agent_token = "secret"

[databases.mydb.production]
url = "postgres://localhost/mydb"
"#;
        let config = AgentConfig::from_toml(toml).unwrap();
        assert_eq!(config.server.url, "http://localhost:8080");
        assert_eq!(
            config.agent_id(),
            hostname::get().unwrap().to_string_lossy().to_string()
        );
    }

    #[test]
    fn env_var_expansion() {
        unsafe { std::env::set_var("TEST_AGENT_URL", "http://expanded:9090") };
        let toml = r#"
[server]
url = "${TEST_AGENT_URL}"
agent_token = "tok"

[databases.db.dev]
url = "postgres://localhost/x"
"#;
        let config = AgentConfig::from_toml(toml).unwrap();
        assert_eq!(config.server.url, "http://expanded:9090");
        unsafe { std::env::remove_var("TEST_AGENT_URL") };
    }

    #[test]
    fn validation_missing_scheme() {
        let toml = r#"
[server]
url = "localhost:8080"
agent_token = "tok"

[databases.db.dev]
url = "postgres://localhost/x"
"#;
        let err = AgentConfig::from_toml(toml).unwrap_err();
        assert!(err.to_string().contains("http"));
    }

    #[test]
    fn validation_no_databases() {
        let toml = r#"
[server]
url = "http://localhost:8080"
agent_token = "tok"

[databases]
"#;
        let err = AgentConfig::from_toml(toml).unwrap_err();
        assert!(err.to_string().contains("database"));
    }
}
