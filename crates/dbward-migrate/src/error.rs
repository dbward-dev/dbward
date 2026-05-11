use thiserror::Error;

#[derive(Debug, Error)]
pub enum MigrateError {
    #[error("driver error: {0}")]
    Driver(#[from] dbward_driver::DriverError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Config(String),
}
