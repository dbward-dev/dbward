use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("{context}: undefined environment variable: ${{{var}}}")]
    UndefinedEnvVar { var: String, context: String },

    #[error("{context}: nested ${{}} expansion is not supported")]
    NestedExpansion { context: String },

    #[error("{context}: malformed ${{}} expression")]
    MalformedExpansion { context: String },

    #[error("{path}: {message}")]
    Parse { path: String, message: String },

    #[error("{0}")]
    Validation(String),

    #[error("config file not found: {0}")]
    NotFound(PathBuf),
}
