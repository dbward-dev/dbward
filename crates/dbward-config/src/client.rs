use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::ConfigError;
use crate::expand::expand_toml_value;

#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    pub default_database: Option<String>,
    pub default_environment: Option<String>,
    #[serde(default = "default_migrations_dir")]
    pub migrations_dir: PathBuf,
    pub server: ServerSection,
    #[serde(default)]
    pub databases: BTreeMap<String, DatabaseSection>,
    #[serde(default)]
    pub results: ResultsSection,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerSection {
    pub url: String,
    pub token: Option<String>,
    pub oidc: Option<OidcSection>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OidcSection {
    pub issuer: String,
    pub client_id: String,
    pub discovery_url: Option<String>,
    pub backchannel_url: Option<String>,
    pub browser_url: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DatabaseSection {
    pub migrations_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResultFormatConfig {
    #[default]
    Table,
    Json,
    Csv,
    Vertical,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ResultsSection {
    pub dir: Option<PathBuf>,
    pub format: Option<ResultFormatConfig>,
}

fn default_migrations_dir() -> PathBuf {
    PathBuf::from("migrations")
}

impl ClientConfig {
    /// Load, expand env vars, parse, and resolve paths in one step.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            return Err(ConfigError::NotFound(path.to_path_buf()));
        }
        let content = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        let mut value: toml::Value = toml::from_str(&content).map_err(|e| ConfigError::Parse {
            path: path.display().to_string(),
            message: e.to_string(),
        })?;
        expand_toml_value(&mut value, "")?;
        let mut cfg: Self = value.try_into().map_err(|e| ConfigError::Parse {
            path: path.display().to_string(),
            message: e.to_string(),
        })?;
        let base_dir = path
            .parent()
            .ok_or_else(|| ConfigError::Validation("config path has no parent directory".into()))?;
        cfg.resolve_relative_paths(base_dir);
        Ok(cfg)
    }

    pub fn resolve_relative_paths(&mut self, base_dir: &Path) {
        self.migrations_dir = resolve_relative(base_dir, &self.migrations_dir);
        for db in self.databases.values_mut() {
            if let Some(path) = db.migrations_dir.as_mut() {
                *path = resolve_relative(base_dir, path);
            }
        }
        if let Some(dir) = self.results.dir.as_mut() {
            *dir = expand_tilde_and_resolve(base_dir, dir);
        }
    }

    pub fn resolve_database_name(&self, selected: Option<&str>) -> Result<String, ConfigError> {
        if let Some(sel) = selected {
            if self.databases.contains_key(sel) || self.databases.is_empty() {
                return Ok(sel.to_string());
            }
            if !self.databases.contains_key(sel) {
                return Err(ConfigError::Validation(format!(
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
            return Err(ConfigError::Validation(
                "no database configured; use --database <name> or set default_database in config"
                    .into(),
            ));
        }
        Err(ConfigError::Validation(
            "multiple databases configured; use --database <name> or set default_database".into(),
        ))
    }

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

fn resolve_relative(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn expand_tilde_and_resolve(base: &Path, path: &Path) -> PathBuf {
    if let Some(s) = path.to_str()
        && let Some(rest) = s.strip_prefix("~/")
        && let Some(home) = dirs::home_dir()
    {
        return home.join(rest);
    }
    resolve_relative(base, path)
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
    fn simple_expansion() {
        with_env(&[("CFGTEST_CLI_HOST", Some("localhost"))], || {
            let toml = r#"
[server]
url = "http://${CFGTEST_CLI_HOST}:3000"
token = "tok"
"#;
            let mut val: toml::Value = toml::from_str(toml).unwrap();
            expand_toml_value(&mut val, "").unwrap();
            assert_eq!(
                val["server"]["url"].as_str().unwrap(),
                "http://localhost:3000"
            );
        });
    }

    #[test]
    fn default_value() {
        with_env(&[("CFGTEST_CLI_UNSET", None)], || {
            let toml = r#"
[server]
url = "http://${CFGTEST_CLI_UNSET:-127.0.0.1}:3000"
token = "tok"
"#;
            let mut val: toml::Value = toml::from_str(toml).unwrap();
            expand_toml_value(&mut val, "").unwrap();
            assert_eq!(
                val["server"]["url"].as_str().unwrap(),
                "http://127.0.0.1:3000"
            );
        });
    }

    #[test]
    fn missing_var_error() {
        with_env(&[("CFGTEST_CLI_MISSING", None)], || {
            let toml = r#"
[server]
url = "http://host"
token = "${CFGTEST_CLI_MISSING}"
"#;
            let mut val: toml::Value = toml::from_str(toml).unwrap();
            let err = expand_toml_value(&mut val, "").unwrap_err();
            assert!(err.to_string().contains("CFGTEST_CLI_MISSING"));
        });
    }
}
