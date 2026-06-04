use thiserror::Error;

#[derive(Debug, Error)]
pub enum MigrateError {
    #[error("driver error: {0}")]
    Driver(#[from] dbward_driver::DriverError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Config(String),
    #[error("migration cancelled")]
    Cancelled,
    #[error("migration partially applied: {source}")]
    PartialApplied {
        /// Versions successfully completed before the failure (applied for up, reverted for down).
        completed: Vec<String>,
        #[source]
        source: Box<MigrateError>,
    },
}
