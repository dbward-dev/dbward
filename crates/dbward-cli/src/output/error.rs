use thiserror::Error;

use super::types::{CliOutcome, EnvelopeError, RenderPlan};

/// CLI error type. Represents failures where the operation did not complete.
///
/// For data-bearing non-zero exits (doctor, audit verify, pending approval),
/// use `CliResponse::with_issues()` instead.
#[derive(Debug, Error)]
pub enum CliError {
    /// Argument parse error (clap usage error).
    #[error("usage: {0}")]
    Usage(String),

    /// Authentication failure (token expired, not logged in, etc.).
    #[error("auth: {0}")]
    Auth(String),

    /// Configuration error (missing file, invalid format, etc.).
    #[error("config: {0}")]
    Config(String),

    /// Network/connection failure (DNS, TCP, TLS).
    #[error("network: {0}")]
    Network(String),

    /// Server API error (non-2xx response with structured error).
    #[error("api: [{code}] {message}")]
    Api { code: String, message: String },

    /// Request timed out.
    #[error("timed out after {seconds}s")]
    Timeout { seconds: u64 },

    /// Preflight blocked / confirmation required.
    #[error("blocked: {reason}")]
    Blocked { reason: String },

    /// Internal/unexpected error.
    #[error("{0}")]
    Internal(String),
}

impl CliError {
    /// Convert to JSON envelope error fields (code, message).
    pub fn to_envelope(&self) -> (String, String) {
        match self {
            Self::Usage(msg) => ("usage".into(), msg.clone()),
            Self::Auth(msg) => ("auth_error".into(), msg.clone()),
            Self::Config(msg) => ("config_error".into(), msg.clone()),
            Self::Network(msg) => ("network_error".into(), msg.clone()),
            Self::Api { code, message } => (code.clone(), message.clone()),
            Self::Timeout { seconds } => {
                ("timeout".into(), format!("timed out after {seconds}s"))
            }
            Self::Blocked { reason } => ("blocked".into(), reason.clone()),
            Self::Internal(msg) => ("internal_error".into(), msg.clone()),
        }
    }

    /// Exit code for this error variant.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(_) => 2,
            Self::Timeout { .. } => 124,
            _ => 1,
        }
    }

    /// Data payload for error conversions. Always None for CliError.
    /// Data-bearing non-zero exits go through CliResponse::with_issues().
    pub fn payload(&self) -> Option<serde_json::Value> {
        None
    }
}

impl From<CliError> for CliOutcome {
    fn from(err: CliError) -> Self {
        let (code, message) = err.to_envelope();
        Self {
            ok: false,
            data: err.payload(),
            warnings: vec![],
            error: Some(EnvelopeError { code, message }),
            render: RenderPlan::none(),
            exit_code: err.exit_code(),
        }
    }
}

// ---------------------------------------------------------------------------
// Conversions from common error types
// ---------------------------------------------------------------------------

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        CliError::Internal(format!("io: {e}"))
    }
}

impl From<serde_json::Error> for CliError {
    fn from(e: serde_json::Error) -> Self {
        CliError::Internal(e.to_string())
    }
}

impl From<dbward_config::ConfigError> for CliError {
    fn from(e: dbward_config::ConfigError) -> Self {
        CliError::Config(e.to_string())
    }
}

impl From<dbward_migrate::MigrateError> for CliError {
    fn from(e: dbward_migrate::MigrateError) -> Self {
        CliError::Internal(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_error_exit_code_is_2() {
        let err = CliError::Usage("missing arg".into());
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn timeout_error_exit_code_is_124() {
        let err = CliError::Timeout { seconds: 30 };
        assert_eq!(err.exit_code(), 124);
    }

    #[test]
    fn general_errors_exit_code_is_1() {
        assert_eq!(CliError::Auth("expired".into()).exit_code(), 1);
        assert_eq!(CliError::Config("bad".into()).exit_code(), 1);
        assert_eq!(CliError::Network("refused".into()).exit_code(), 1);
        assert_eq!(
            CliError::Api {
                code: "not_found".into(),
                message: "x".into()
            }
            .exit_code(),
            1
        );
        assert_eq!(CliError::Blocked { reason: "x".into() }.exit_code(), 1);
        assert_eq!(CliError::Internal("x".into()).exit_code(), 1);
    }

    #[test]
    fn to_envelope_produces_expected_codes() {
        let (code, _) = CliError::Auth("x".into()).to_envelope();
        assert_eq!(code, "auth_error");

        let (code, _) = CliError::Config("x".into()).to_envelope();
        assert_eq!(code, "config_error");

        let (code, msg) = CliError::Timeout { seconds: 5 }.to_envelope();
        assert_eq!(code, "timeout");
        assert!(msg.contains("5s"));
    }

    #[test]
    fn cli_outcome_from_cli_error() {
        let err = CliError::Auth("token expired".into());
        let outcome: CliOutcome = err.into();

        assert!(!outcome.ok);
        assert_eq!(outcome.exit_code, 1);
        assert!(outcome.data.is_none());
        assert_eq!(outcome.error.as_ref().unwrap().code, "auth_error");
        assert!(outcome.error.as_ref().unwrap().message.contains("token expired"));
    }

    #[test]
    fn payload_always_none() {
        assert!(CliError::Auth("x".into()).payload().is_none());
        assert!(CliError::Internal("x".into()).payload().is_none());
    }
}
