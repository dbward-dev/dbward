use crate::DriverError;

/// Classify a sqlx connection error by checking for authentication failure codes.
pub(crate) fn classify_connect_error(e: sqlx::Error, auth_codes: &[&str]) -> DriverError {
    if let sqlx::Error::Database(ref db_err) = e
        && let Some(code) = db_err.code()
        && auth_codes.iter().any(|c| code.as_ref() == *c)
    {
        return DriverError::AuthenticationFailed(e.to_string());
    }
    DriverError::ConnectionFailed(e.to_string())
}

/// Validate a migration version string for safe interpolation into comments.
pub(crate) fn validate_migration_version(version: &str) -> Result<(), DriverError> {
    const FORBIDDEN: &[char] = &['\'', ';', '\\', '\n', '\r', '\0'];
    if version.contains(FORBIDDEN) {
        return Err(DriverError::QueryFailed(
            "invalid migration version".into(),
        ));
    }
    Ok(())
}
