use std::path::Path;

use dbward_core::{Config, DatabaseConfig, Environment, Error, Role};

pub fn load(
    config_path: &Path,
    database_url: &Option<String>,
    environment: &Option<String>,
    role: &Option<Role>,
) -> Result<Config, Error> {
    let mut config = if config_path.exists() {
        let content = std::fs::read_to_string(config_path).map_err(Error::Io)?;
        toml::from_str::<Config>(&content)
            .map_err(|e| Error::Config(format!("{config_path:?}: {e}")))?
    } else {
        // No config file — require DATABASE_URL at minimum
        let url = database_url
            .clone()
            .ok_or_else(|| Error::Config("no config file and DBWARD_DATABASE_URL not set".into()))?;
        Config {
            database: DatabaseConfig { url },
            environment: Environment::Development,
            role: Role::Developer,
            migrations_dir: "db/migrations".into(),
            server: None,
        }
    };

    if let Some(url) = database_url {
        config.database.url = url.clone();
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
