use thiserror::Error;

#[derive(Debug, Error)]
pub enum CliError {
    #[error("config: {0}")]
    Config(String),

    #[error("auth: {0}")]
    Auth(String),

    #[error("server: {0}")]
    Server(String),

    /// Network/connection failure (distinct from server-side errors)
    #[error("server: {0}")]
    Transport(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

impl From<serde_json::Error> for CliError {
    fn from(e: serde_json::Error) -> Self {
        CliError::Other(e.to_string())
    }
}

impl From<dbward_migrate::MigrateError> for CliError {
    fn from(e: dbward_migrate::MigrateError) -> Self {
        CliError::Other(e.to_string())
    }
}

impl From<dbward_config::ConfigError> for CliError {
    fn from(e: dbward_config::ConfigError) -> Self {
        CliError::Config(e.to_string())
    }
}
