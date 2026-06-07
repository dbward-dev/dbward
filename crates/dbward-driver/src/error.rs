use thiserror::Error;

#[derive(Debug, Error)]
pub enum DriverError {
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    #[error("authentication failed: {0}")]
    AuthenticationFailed(String),
    #[error("query failed: {0}")]
    QueryFailed(String),
    #[error("query timed out")]
    Timeout,
    #[error("query cancelled")]
    Cancelled,
    #[error("unsupported URL scheme: {0}")]
    UnsupportedScheme(String),
    #[error("migration partially applied (version {version}): {message}")]
    PartialMigration { version: String, message: String },
    #[error("migration timed out (version {version}): {message}")]
    MigrationTimeout { version: String, message: String },
}

impl DriverError {
    /// Whether this error indicates a connectivity issue (connection lost/refused).
    pub fn is_connectivity_error(&self) -> bool {
        match self {
            Self::ConnectionFailed(_) => true,
            Self::QueryFailed(msg) => {
                let lower = msg.to_lowercase();
                lower.contains("connection")
                    || lower.contains("broken pipe")
                    || lower.contains("reset by peer")
            }
            _ => false,
        }
    }
}
