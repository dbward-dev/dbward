use thiserror::Error;

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("config error: {0}")]
    Config(String),
    #[error("token verification failed: {0}")]
    TokenVerification(String),
    #[error("driver error: {0}")]
    Driver(#[from] dbward_driver::DriverError),
    #[error("migration error: {0}")]
    Migration(#[from] dbward_migrate::MigrateError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("drain timeout exceeded")]
    DrainTimeout,
    #[error("server error: {status} {body}")]
    ServerError { status: u16, body: String },
    #[error("job already claimed")]
    AlreadyClaimed,
    #[error("unsupported operation: {0}")]
    UnsupportedOperation(String),
}
