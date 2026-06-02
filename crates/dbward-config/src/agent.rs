use std::collections::HashMap;
use std::fmt;
use std::path::Path;

use serde::Deserialize;

use crate::ConfigError;
use crate::expand::expand_env_vars;

#[derive(Clone, Deserialize)]
pub struct AgentConfig {
    pub agent_id: Option<String>,
    pub poll_interval_ms: Option<u64>,
    pub max_concurrent_tasks: Option<u32>,
    pub drain_timeout_secs: Option<u64>,
    pub statement_timeout_secs: Option<u64>,
    pub lease_duration_secs: Option<u64>,
    pub operations: Option<Vec<String>>,
    pub startup_retry_initial_ms: Option<u64>,
    pub startup_retry_max_ms: Option<u64>,
    pub startup_max_wait_secs: Option<u64>,
    #[serde(default)]
    pub schema_sync: SchemaSyncConfig,
    pub server: AgentServerConfig,
    pub databases: HashMap<String, HashMap<String, DatabaseEntry>>,
}

impl AgentConfig {
    /// Load, expand env vars, parse, and validate in one step.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        Self::from_str(&content, &path.display().to_string())
    }

    /// Parse from TOML string. Expands env vars (strict) and validates.
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
        if !self.server.url.starts_with("http://") && !self.server.url.starts_with("https://") {
            return Err(ConfigError::Validation(
                "server.url must have http or https scheme".into(),
            ));
        }
        if self.databases.is_empty() {
            return Err(ConfigError::Validation(
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
        self.startup_max_wait_secs.unwrap_or(60)
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
pub struct AgentServerConfig {
    pub url: String,
    pub agent_token: String,
}

impl fmt::Debug for AgentServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentServerConfig")
            .field("url", &self.url)
            .field("agent_token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseEntry {
    pub url: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_env<F: FnOnce()>(vars: &[(&str, Option<&str>)], f: F) {
        let _guard = ENV_LOCK.lock().unwrap();
        let originals: Vec<_> = vars
            .iter()
            .map(|(k, _)| (*k, std::env::var(k).ok()))
            .collect();
        for (k, v) in vars {
            match v {
                Some(v) => unsafe { std::env::set_var(k, v) },
                None => unsafe { std::env::remove_var(k) },
            }
        }
        f();
        for (k, original) in &originals {
            match original {
                Some(v) => unsafe { std::env::set_var(k, v) },
                None => unsafe { std::env::remove_var(k) },
            }
        }
    }

    #[test]
    fn parse_valid_config() {
        let toml = r#"
[server]
url = "http://localhost:8080"
agent_token = "secret"

[databases.mydb.production]
url = "postgres://localhost/mydb"
"#;
        let cfg = AgentConfig::from_str(toml, "test").unwrap();
        assert_eq!(cfg.server.url, "http://localhost:8080");
    }

    #[test]
    fn env_var_expansion() {
        with_env(
            &[("CFGTEST_AGENT_URL", Some("http://expanded:9090"))],
            || {
                let toml = r#"
[server]
url = "${CFGTEST_AGENT_URL}"
agent_token = "tok"

[databases.db.dev]
url = "postgres://localhost/x"
"#;
                let cfg = AgentConfig::from_str(toml, "test").unwrap();
                assert_eq!(cfg.server.url, "http://expanded:9090");
            },
        );
    }

    #[test]
    fn undefined_env_var_is_error() {
        with_env(&[("CFGTEST_AGENT_UNDEF", None)], || {
            let toml = r#"
[server]
url = "${CFGTEST_AGENT_UNDEF}"
agent_token = "tok"

[databases.db.dev]
url = "postgres://localhost/x"
"#;
            let err = AgentConfig::from_str(toml, "test").unwrap_err();
            assert!(err.to_string().contains("CFGTEST_AGENT_UNDEF"));
        });
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
        let err = AgentConfig::from_str(toml, "test").unwrap_err();
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
        let err = AgentConfig::from_str(toml, "test").unwrap_err();
        assert!(err.to_string().contains("database"));
    }

    #[test]
    fn startup_max_wait_secs_defaults_to_60() {
        let toml = r#"
[server]
url = "http://localhost:8080"
agent_token = "tok"

[databases.db.dev]
url = "postgres://localhost/x"
"#;
        let cfg = AgentConfig::from_str(toml, "test").unwrap();
        assert_eq!(cfg.startup_max_wait_secs(), 60);
    }

    #[test]
    fn startup_max_wait_secs_explicit_zero() {
        let toml = r#"
startup_max_wait_secs = 0

[server]
url = "http://localhost:8080"
agent_token = "tok"

[databases.db.dev]
url = "postgres://localhost/x"
"#;
        let cfg = AgentConfig::from_str(toml, "test").unwrap();
        assert_eq!(cfg.startup_max_wait_secs(), 0);
    }
}
