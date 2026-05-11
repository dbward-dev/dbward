use thiserror::Error;

#[derive(Debug, Error)]
pub enum DriverError {
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    #[error("query failed: {0}")]
    QueryFailed(String),
    #[error("query timed out")]
    Timeout,
    #[error("query cancelled")]
    Cancelled,
    #[error("unsupported URL scheme: {0}")]
    UnsupportedScheme(String),
}
