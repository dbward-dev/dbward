use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{Environment, Role};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub database: DatabaseConfig,
    pub environment: Environment,
    pub role: Role,
    #[serde(default = "default_migrations_dir")]
    pub migrations_dir: PathBuf,
    pub server: Option<ServerConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
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
}

fn default_migrations_dir() -> PathBuf {
    PathBuf::from("db/migrations")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_minimal_config() {
        let toml = r#"
            environment = "staging"
            role = "developer"
            migrations_dir = "migrations"

            [database]
            url = "postgres://localhost/mydb"
        "#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.environment, Environment::Staging);
        assert_eq!(config.role, Role::Developer);
        assert_eq!(config.migrations_dir, PathBuf::from("migrations"));
    }

    #[test]
    fn default_migrations_dir() {
        let toml = r#"
            environment = "development"
            role = "admin"

            [database]
            url = "postgres://localhost/mydb"
        "#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.migrations_dir, PathBuf::from("db/migrations"));
    }
}
