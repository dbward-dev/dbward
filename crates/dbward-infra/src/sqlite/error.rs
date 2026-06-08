use dbward_app::error::AppError;

/// Convert a rusqlite error to AppError with context.
pub(crate) fn db_err(context: &'static str) -> impl FnOnce(rusqlite::Error) -> AppError {
    move |e| AppError::Internal(format!("{context}: {e}"))
}

/// Convert a serde_json error to AppError with context.
pub(crate) fn json_err(context: &'static str) -> impl FnOnce(serde_json::Error) -> AppError {
    move |e| AppError::Internal(format!("{context}: {e}"))
}
