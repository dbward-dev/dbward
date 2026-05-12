use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use serde::Deserialize;

use crate::error::CliError;

// ---------------------------------------------------------------------------
// Client config (dbward.toml)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    pub default_database: Option<String>,
    pub default_environment: Option<String>,
    #[serde(default = "default_migrations_dir")]
    pub migrations_dir: PathBuf,
    pub server: ServerSection,
    #[serde(default)]
    pub databases: BTreeMap<String, DatabaseSection>,
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

fn default_migrations_dir() -> PathBuf {
    PathBuf::from("migrations")
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

    pub fn resolve_database_name(&self, selected: Option<&str>) -> Result<String, CliError> {
        if let Some(sel) = selected {
            if self.databases.contains_key(sel) || self.databases.is_empty() {
                return Ok(sel.to_string());
            }
            if !self.databases.contains_key(sel) {
                return Err(CliError::Config(format!(
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
            return Err(CliError::Config(
                "no database configured; use --database <name> or set default_database in config"
                    .into(),
            ));
        }
        Err(CliError::Config(
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

fn resolve_relative_path(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

// ---------------------------------------------------------------------------
// Config loading
// ---------------------------------------------------------------------------

pub fn load(config_path: &Path) -> Result<ClientConfig, CliError> {
    let mut config = load_from_toml::<ClientConfig>(config_path)?;
    let base_dir = config_path
        .parent()
        .ok_or_else(|| CliError::Config("config path has no parent directory".into()))?;
    config.resolve_relative_paths(base_dir);
    Ok(config)
}

fn load_from_toml<T>(config_path: &Path) -> Result<T, CliError>
where
    T: serde::de::DeserializeOwned,
{
    if !config_path.exists() {
        return Err(CliError::Config(format!(
            "config file not found: {}. Run 'dbward init' or create dbward.toml",
            config_path.display()
        )));
    }
    let content = std::fs::read_to_string(config_path)?;
    let mut value: toml::Value = toml::from_str(&content)
        .map_err(|e| CliError::Config(format!("{}: {e}", config_path.display())))?;
    expand_env_vars(&mut value, "")?;
    value
        .try_into()
        .map_err(|e| CliError::Config(format!("{}: {e}", config_path.display())))
}

// ---------------------------------------------------------------------------
// Environment variable expansion
// ---------------------------------------------------------------------------

static ENV_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}").unwrap());

fn expand_env_vars(value: &mut toml::Value, path: &str) -> Result<(), CliError> {
    match value {
        toml::Value::Table(table) => {
            for (key, val) in table.iter_mut() {
                let child_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                expand_env_vars(val, &child_path)?;
            }
        }
        toml::Value::Array(arr) => {
            for (i, val) in arr.iter_mut().enumerate() {
                expand_env_vars(val, &format!("{path}[{i}]"))?;
            }
        }
        toml::Value::String(s) if s.contains("${") => {
            let mut err: Option<CliError> = None;
            let expanded = ENV_RE.replace_all(s, |caps: &regex::Captures| {
                if err.is_some() {
                    return String::new();
                }
                let var = &caps[1];
                let default = caps.get(2).map(|m| m.as_str());

                if let Some(d) = default
                    && d.contains("${")
                {
                    err = Some(CliError::Config(format!(
                        "{path}: nested ${{}} expansion is not supported"
                    )));
                    return String::new();
                }

                match std::env::var(var) {
                    Ok(v) => v,
                    Err(_) => {
                        if let Some(d) = default {
                            d.to_string()
                        } else {
                            err = Some(CliError::Config(format!(
                                "{path}: environment variable {var} is not set"
                            )));
                            String::new()
                        }
                    }
                }
            });

            if let Some(e) = err {
                return Err(e);
            }

            if expanded.contains("${") {
                return Err(CliError::Config(format!(
                    "{path}: malformed ${{}} expression"
                )));
            }

            *s = expanded.into_owned();
        }
        _ => {}
    }
    Ok(())
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

    fn expand(toml_str: &str) -> Result<toml::Value, CliError> {
        let mut val: toml::Value = toml::from_str(toml_str).unwrap();
        expand_env_vars(&mut val, "")?;
        Ok(val)
    }

    #[test]
    fn simple_expansion() {
        with_env(&[("TEST_HOST_CLI", Some("localhost"))], || {
            let val = expand(r#"host = "${TEST_HOST_CLI}""#).unwrap();
            assert_eq!(val["host"].as_str().unwrap(), "localhost");
        });
    }

    #[test]
    fn default_value() {
        with_env(&[("UNSET_VAR_CLI_TEST", None)], || {
            let val = expand(r#"v = "${UNSET_VAR_CLI_TEST:-fallback}""#).unwrap();
            assert_eq!(val["v"].as_str().unwrap(), "fallback");
        });
    }

    #[test]
    fn missing_var_error() {
        with_env(&[("MISSING_VAR_CLI_XYZ", None)], || {
            let err = expand(r#"token = "${MISSING_VAR_CLI_XYZ}""#).unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains("MISSING_VAR_CLI_XYZ"));
            assert!(msg.contains("not set"));
        });
    }
}
