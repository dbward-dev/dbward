//! Two-layer config resolution: global (~/.config/dbward/) + project (CWD/dbward.toml).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::ConfigError;
use crate::client::{ClientConfig, DatabaseSection, OidcSection, ResultsSection, ServerSection};
use crate::expand::expand_toml_value;

/// Where a config value originated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Global,
    Project,
    Env,
}

/// Result of merging config layers with source tracking.
#[derive(Debug)]
pub struct MergedConfig {
    pub config: ClientConfig,
    pub url_source: Source,
    pub auth_source: Option<Source>,
    pub sources_loaded: Vec<(Source, PathBuf)>,
}

/// Raw layer — all fields optional so we can detect presence.
#[derive(Debug, Default, Deserialize)]
struct RawLayerConfig {
    default_database: Option<String>,
    default_environment: Option<String>,
    migrations_dir: Option<PathBuf>,
    server: Option<RawServerSection>,
    #[serde(default)]
    databases: Option<BTreeMap<String, DatabaseSection>>,
    #[serde(default)]
    results: Option<ResultsSection>,
}

#[derive(Debug, Default, Deserialize)]
struct RawServerSection {
    url: Option<String>,
    token: Option<String>,
    oidc: Option<OidcSection>,
}

/// Platform-aware global config directory.
/// macOS: $XDG_CONFIG_HOME/dbward or ~/.config/dbward
/// Linux/Windows: dirs::config_dir()/dbward
pub fn global_config_dir() -> PathBuf {
    if cfg!(target_os = "macos") {
        if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME")
            && !xdg.is_empty()
        {
            return PathBuf::from(xdg).join("dbward");
        }
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".config/dbward")
    } else {
        dirs::config_dir()
            .unwrap_or_else(|| {
                dirs::home_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join(".config")
            })
            .join("dbward")
    }
}

/// Load merged config with source tracking.
///
/// - `explicit_config`: if Some, standalone mode (no global merge unless merge_global=true)
/// - `merge_global`: force global merge even in standalone mode
pub fn load_merged(
    explicit_config: Option<&Path>,
    merge_global: bool,
) -> Result<MergedConfig, ConfigError> {
    let auto_detect = explicit_config.is_none();
    let use_global = auto_detect || merge_global;

    let mut sources: Vec<(Source, PathBuf)> = Vec::new();
    let mut url_source = None;
    let mut auth_source = None;

    // --- Load global layer ---
    let global_dir = global_config_dir();
    let global_path = global_dir.join("config.toml");
    let (global_layer, global_path) = if use_global && global_path.exists() {
        sources.push((Source::Global, global_path.clone()));
        (
            Some(load_raw_layer(&global_path, &global_dir)?),
            global_path,
        )
    } else {
        (None, global_path)
    };

    // --- Load project/explicit layer ---
    let project_path = if let Some(p) = explicit_config {
        if p.exists() {
            Some(p.to_path_buf())
        } else {
            return Err(ConfigError::NotFound(p.to_path_buf()));
        }
    } else {
        let cwd_config = PathBuf::from("dbward.toml");
        if cwd_config.exists() {
            Some(cwd_config)
        } else {
            None
        }
    };

    let project_layer = if let Some(ref pp) = project_path {
        let base_dir = pp.parent().unwrap_or(Path::new("."));
        sources.push((Source::Project, pp.clone()));
        Some(load_raw_layer(pp, base_dir)?)
    } else {
        None
    };

    // --- Check we have at least one source ---
    let has_env_config = std::env::var("DBWARD_SERVER_URL")
        .map(|v| !v.is_empty())
        .unwrap_or(false)
        && std::env::var("DBWARD_TOKEN")
            .map(|v| !v.is_empty())
            .unwrap_or(false);
    if global_layer.is_none() && project_layer.is_none() && !has_env_config {
        return Err(ConfigError::Validation(
            "no configuration found. Set DBWARD_SERVER_URL + DBWARD_TOKEN, or run: dbward init"
                .into(),
        ));
    }

    // --- Merge ---
    let mut server_url = String::new();
    let mut server_token: Option<String> = None;
    let mut server_oidc: Option<OidcSection> = None;
    let mut default_database: Option<String> = None;
    let mut default_environment: Option<String> = None;
    let mut migrations_dir = PathBuf::from("migrations");
    let mut databases: BTreeMap<String, DatabaseSection> = BTreeMap::new();

    // Apply global
    if let Some(ref g) = global_layer {
        if let Some(ref s) = g.server {
            if let Some(ref u) = s.url {
                server_url = u.clone();
                url_source = Some(Source::Global);
            }
            if let Some(ref t) = s.token
                && !t.is_empty()
            {
                server_token = Some(t.clone());
                auth_source = Some(Source::Global);
            }
            if let Some(ref o) = s.oidc {
                server_oidc = Some(o.clone());
                auth_source = Some(Source::Global);
            }
        }
        if let Some(ref d) = g.default_database {
            default_database = Some(d.clone());
        }
        if let Some(ref e) = g.default_environment {
            default_environment = Some(e.clone());
        }
        // Warn if global has project-only fields
        if g.migrations_dir.is_some() {
            eprintln!(
                "warning: migrations_dir in global config is ignored (project-only field): {}",
                global_path.display()
            );
        }
        if g.databases.is_some() {
            eprintln!(
                "warning: [databases] in global config is ignored (project-only field): {}",
                global_path.display()
            );
        }
    }

    // Apply project (overrides global)
    if let Some(ref p) = project_layer {
        if let Some(ref s) = p.server {
            if let Some(ref u) = s.url {
                server_url = u.clone();
                url_source = Some(Source::Project);
            }
            if let Some(ref t) = s.token
                && !t.is_empty()
            {
                server_token = Some(t.clone());
                auth_source = Some(Source::Project);
                // Warn about token in project config (only for auto-detected, not --config)
                if let Some(ref pp) = project_path
                    && auto_detect
                {
                    eprintln!(
                        "warning: server.token in project config may be committed to VCS: {}",
                        pp.display()
                    );
                }
            }
            if s.oidc.is_some() {
                server_oidc = s.oidc.clone();
                auth_source = Some(Source::Project);
                // OIDC replaces token if both set at project level
                if s.token.is_none() {
                    server_token = None;
                }
            }
        }
        if let Some(ref d) = p.default_database {
            default_database = Some(d.clone());
        }
        if let Some(ref e) = p.default_environment {
            default_environment = Some(e.clone());
        }
        if let Some(ref m) = p.migrations_dir {
            migrations_dir = m.clone();
        }
        if let Some(ref db) = p.databases {
            databases = db.clone();
        }
    }

    // --- Results from either layer (project wins per-field) ---
    let mut results = global_layer
        .as_ref()
        .and_then(|g| g.results.clone())
        .unwrap_or_default();
    if let Some(ref p) = project_layer
        && let Some(ref pr) = p.results
    {
        if pr.dir.is_some() {
            results.dir = pr.dir.clone();
        }
        if pr.format.is_some() {
            results.format = pr.format;
        }
    }
    // Resolve results.dir relative to the highest-priority config that set it
    if let Some(ref mut dir) = results.dir {
        let base = if project_layer
            .as_ref()
            .and_then(|p| p.results.as_ref())
            .and_then(|r| r.dir.as_ref())
            .is_some()
        {
            project_path
                .as_ref()
                .and_then(|p| p.parent())
                .unwrap_or(Path::new("."))
        } else {
            global_path.parent().unwrap_or(Path::new("."))
        };
        // Expand ~/
        if let Some(s) = dir.to_str() {
            if let Some(rest) = s.strip_prefix("~/") {
                if let Some(home) = dirs::home_dir() {
                    *dir = home.join(rest);
                }
            } else if !dir.is_absolute() {
                *dir = base.join(&*dir);
            }
        }
    }

    // --- Env var overrides ---
    if let Ok(u) = std::env::var("DBWARD_SERVER_URL")
        && !u.is_empty()
    {
        server_url = u;
        url_source = Some(Source::Env);
    }
    if let Ok(t) = std::env::var("DBWARD_TOKEN")
        && !t.is_empty()
    {
        server_token = Some(t);
        auth_source = Some(Source::Env);
    }
    // Empty DBWARD_TOKEN = unset (does NOT count as re-bind)

    // --- Auth safety rule ---
    if let (Some(us), Some(as_)) = (url_source, auth_source)
        && us != as_
        && us > as_
    {
        // URL from higher-precedence source than auth → exfiltration risk
        return Err(ConfigError::Validation(format!(
            "server.url from {:?} but auth inherited from {:?}. \
                 Explicitly set auth for this server URL.",
            us, as_
        )));
    }
    // URL set but no auth at all
    if url_source.is_some()
        && auth_source.is_none()
        && server_token.is_none()
        && server_oidc.is_none()
    {
        // This is OK — authenticate() will error later with a clear message
    }

    // Fallback: if no server URL at all
    if server_url.is_empty() {
        return Err(ConfigError::Validation(
            "server.url not configured in any config layer".into(),
        ));
    }

    let config = ClientConfig {
        default_database,
        default_environment,
        migrations_dir,
        server: ServerSection {
            url: server_url,
            token: server_token,
            oidc: server_oidc,
        },
        databases,
        results,
    };

    Ok(MergedConfig {
        config,
        url_source: url_source.unwrap_or(Source::Global),
        auth_source,
        sources_loaded: sources,
    })
}

fn load_raw_layer(path: &Path, base_dir: &Path) -> Result<RawLayerConfig, ConfigError> {
    let content = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let mut value: toml::Value = toml::from_str(&content).map_err(|e| ConfigError::Parse {
        path: path.display().to_string(),
        message: e.to_string(),
    })?;
    expand_toml_value(&mut value, "")?;
    let mut layer: RawLayerConfig = value.try_into().map_err(|e| ConfigError::Parse {
        path: path.display().to_string(),
        message: e.to_string(),
    })?;

    // Resolve relative paths against this layer's base dir
    if let Some(ref mut m) = layer.migrations_dir
        && m.is_relative()
    {
        *m = base_dir.join(&*m);
    }
    if let Some(ref mut dbs) = layer.databases {
        for db in dbs.values_mut() {
            if let Some(ref mut p) = db.migrations_dir
                && p.is_relative()
            {
                *p = base_dir.join(&*p);
            }
        }
    }

    Ok(layer)
}

// Implement ordering for Source (Global < Project < Env)
impl PartialOrd for Source {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Source {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        fn rank(s: &Source) -> u8 {
            match s {
                Source::Global => 0,
                Source::Project => 1,
                Source::Env => 2,
            }
        }
        rank(self).cmp(&rank(other))
    }
}

/// Compute scoped credentials path for an (issuer, client_id) pair.
pub fn scoped_credentials_path(issuer: &str, client_id: &str) -> PathBuf {
    use sha2::{Digest, Sha256};
    let input = format!("{issuer}\n{client_id}");
    let hash = Sha256::digest(input.as_bytes());
    let hex: String = hash.iter().take(8).map(|b| format!("{b:02x}")).collect();
    global_config_dir()
        .join("credentials")
        .join(format!("{hex}.json"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn global_config_dir_is_not_empty() {
        let dir = global_config_dir();
        assert!(!dir.as_os_str().is_empty());
        assert!(dir.to_string_lossy().contains("dbward"));
    }

    #[test]
    fn scoped_credentials_path_is_deterministic() {
        let p1 = scoped_credentials_path("https://auth.example.com", "cli");
        let p2 = scoped_credentials_path("https://auth.example.com", "cli");
        assert_eq!(p1, p2);
    }

    #[test]
    fn scoped_credentials_path_differs_by_issuer() {
        let p1 = scoped_credentials_path("https://a.com", "cli");
        let p2 = scoped_credentials_path("https://b.com", "cli");
        assert_ne!(p1, p2);
    }

    #[test]
    fn load_merged_project_only() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("dbward.toml");
        fs::write(
            &cfg_path,
            r#"
migrations_dir = "m"

[server]
url = "http://localhost:3000"
token = "dbw_test"
"#,
        )
        .unwrap();

        let result = load_merged(Some(&cfg_path), false).unwrap();
        assert_eq!(result.config.server.url, "http://localhost:3000");
        assert_eq!(result.config.server.token.as_deref(), Some("dbw_test"));
        assert_eq!(result.config.migrations_dir, dir.path().join("m"));
    }

    #[test]
    fn load_merged_missing_file_errors() {
        let result = load_merged(Some(Path::new("/nonexistent/dbward.toml")), false);
        assert!(result.is_err());
    }
}
