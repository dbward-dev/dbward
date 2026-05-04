use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ApiError {
    pub error: String,
    pub code: Option<String>,
    pub hint: Option<String>,
    #[serde(skip)]
    pub status: StatusCode,
}

impl ApiError {
    pub fn new(status: StatusCode, error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            code: None,
            hint: None,
            status,
        }
    }

    pub fn with_code(mut self, code: impl Into<String>) -> Self {
        self.code = Some(code.into());
        self
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub fn bad_request(error: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, error)
    }

    pub fn not_found(error: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, error)
    }

    pub fn forbidden(error: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, error)
    }

    pub fn conflict(error: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, error)
    }

    pub fn internal(error: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, error)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status;
        (status, axum::Json(self)).into_response()
    }
}

// Gradual migration: convert from legacy (StatusCode, String) tuples
impl From<(StatusCode, String)> for ApiError {
    fn from((status, error): (StatusCode, String)) -> Self {
        Self::new(status, error)
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)
    }
}
