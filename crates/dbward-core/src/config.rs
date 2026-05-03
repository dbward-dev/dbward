use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{Environment, Error, Role};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub databases: BTreeMap<String, DatabaseConfig>,
    pub default_database: Option<String>,
    pub environment: Environment,
    pub role: Role,
    #[serde(default = "default_migrations_dir")]
    pub migrations_dir: PathBuf,
    pub server: Option<ServerConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub migrations_dir: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct ResolvedDatabaseConfig {
    pub name: String,
    pub url: String,
    pub migrations_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub url: String,
    pub token: Option<String>,
    pub public_key: Option<String>,
    pub oidc: Option<ClientOidcConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientOidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub discovery_url: Option<String>,
}

fn default_migrations_dir() -> PathBuf {
    PathBuf::from("db/migrations")
}

impl Config {
    /// Resolve which database to use.
    /// Priority: selected > default_database > auto (if only one DB).
    pub fn resolve_database(&self, selected: Option<&str>) -> Result<ResolvedDatabaseConfig, Error> {
        let (name, db) = if let Some(sel) = selected {
            let db = self.databases.get(sel)
                .ok_or_else(|| Error::Config(format!("database '{sel}' not found in config")))?;
            (sel.to_string(), db)
        } else if let Some(ref def) = self.default_database {
            let db = self.databases.get(def)
                .ok_or_else(|| Error::Config(format!("default_database '{def}' not found in config")))?;
            (def.clone(), db)
        } else if self.databases.len() == 1 {
            let (name, db) = self.databases.iter().next().unwrap();
            (name.clone(), db)
        } else if self.databases.is_empty() {
            return Err(Error::Config("no databases configured".into()));
        } else {
            return Err(Error::Config(
                "multiple databases configured; use --database <name> or set default_database".into(),
            ));
        };

        let migrations_dir = db.migrations_dir.clone()
            .unwrap_or_else(|| self.migrations_dir.join(&name));

        Ok(ResolvedDatabaseConfig { name, url: db.url.clone(), migrations_dir })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_single_db_auto() {
        let config: Config = toml::from_str(r#"
            environment = "development"
            role = "developer"
            [databases.default]
            url = "postgres://localhost/mydb"
        "#).unwrap();
        let r = config.resolve_database(None).unwrap();
        assert_eq!(r.name, "default");
        assert_eq!(r.url, "postgres://localhost/mydb");
        assert_eq!(r.migrations_dir, PathBuf::from("db/migrations/default"));
    }

    #[test]
    fn resolve_by_name() {
        let config: Config = toml::from_str(r#"
            environment = "production"
            role = "developer"
            [databases.primary]
            url = "postgres://primary/app"
            [databases.analytics]
            url = "postgres://analytics/app"
        "#).unwrap();
        let r = config.resolve_database(Some("analytics")).unwrap();
        assert_eq!(r.name, "analytics");
    }

    #[test]
    fn resolve_default_database() {
        let config: Config = toml::from_str(r#"
            environment = "production"
            role = "developer"
            default_database = "primary"
            [databases.primary]
            url = "postgres://primary/app"
            [databases.analytics]
            url = "postgres://analytics/app"
        "#).unwrap();
        assert_eq!(config.resolve_database(None).unwrap().name, "primary");
    }

    #[test]
    fn resolve_custom_migrations_dir() {
        let config: Config = toml::from_str(r#"
            environment = "development"
            role = "developer"
            [databases.app]
            url = "postgres://localhost/app"
            migrations_dir = "custom/migrations"
        "#).unwrap();
        assert_eq!(config.resolve_database(None).unwrap().migrations_dir, PathBuf::from("custom/migrations"));
    }

    #[test]
    fn resolve_multiple_without_default_errors() {
        let config: Config = toml::from_str(r#"
            environment = "development"
            role = "developer"
            [databases.a]
            url = "postgres://a/db"
            [databases.b]
            url = "postgres://b/db"
        "#).unwrap();
        assert!(config.resolve_database(None).is_err());
    }

    #[test]
    fn resolve_unknown_name_errors() {
        let config: Config = toml::from_str(r#"
            environment = "development"
            role = "developer"
            [databases.default]
            url = "postgres://localhost/mydb"
        "#).unwrap();
        assert!(config.resolve_database(Some("nonexistent")).is_err());
    }
}
