use std::path::Path;

use dbward_core::{Config, DatabaseConfig, Environment, Error, Role};

pub fn load(
    config_path: &Path,
    database_url: &Option<String>,
    environment: &Option<String>,
    role: &Option<Role>,
    database_name: &Option<String>,
) -> Result<Config, Error> {
    let mut config = if config_path.exists() {
        let content = std::fs::read_to_string(config_path).map_err(Error::Io)?;
        toml::from_str::<Config>(&content)
            .map_err(|e| Error::Config(format!("{config_path:?}: {e}")))?
    } else {
        let url = database_url
            .clone()
            .ok_or_else(|| Error::Config("no config file and DBWARD_DATABASE_URL not set".into()))?;
        let mut databases = std::collections::BTreeMap::new();
        databases.insert("default".into(), DatabaseConfig { url, migrations_dir: None });
        Config {
            databases,
            default_database: None,
            environment: Environment::Development,
            role: Role::Developer,
            migrations_dir: "db/migrations".into(),
            server: None,
        }
    };

    // Override database URL into the selected (or default) database entry
    if let Some(url) = database_url {
        let name = database_name.as_deref()
            .or(config.default_database.as_deref())
            .unwrap_or("default");
        config.databases.entry(name.to_string())
            .and_modify(|db| db.url = url.clone())
            .or_insert_with(|| DatabaseConfig { url: url.clone(), migrations_dir: None });
    }
    if let Some(env_str) = environment {
        config.environment = match env_str.as_str() {
            "production" => Environment::Production,
            "staging" => Environment::Staging,
            "development" => Environment::Development,
            other => Environment::Custom(other.to_string()),
        };
    }
    if let Some(r) = role {
        config.role = *r;
    }

    Ok(config)
}
