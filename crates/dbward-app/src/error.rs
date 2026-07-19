use dbward_domain::auth::Permission;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("forbidden: {0}")]
    Forbidden(#[from] AuthzError),

    #[error("authentication failed: {0}")]
    Auth(#[from] AuthError),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("gone: {0}")]
    Gone(String),

    #[error("validation: {0}")]
    Validation(String),

    #[error("plan limit: {0}")]
    PlanLimit(String),

    #[error("payload too large: {0}")]
    PayloadTooLarge(String),

    #[error("rate limited: {0}")]
    RateLimited(String),

    #[error("internal: {0}")]
    Internal(String),
}

impl AppError {
    pub fn code(&self) -> &'static str {
        match self {
            AppError::Forbidden(_) => "forbidden",
            AppError::Auth(e) => e.code(),
            AppError::NotFound(_) => "request.not_found",
            AppError::Conflict(_) => "request.conflict",
            AppError::Gone(_) => "request.gone",
            AppError::Validation(_) => "validation.failed",
            AppError::PlanLimit(_) => "policy.limit_exceeded",
            AppError::PayloadTooLarge(_) => "payload.too_large",
            AppError::RateLimited(_) => "preflight.rate_limited",
            AppError::Internal(_) => "internal_error",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthzError {
    #[error("permission denied: {permission} — {reason}")]
    Forbidden {
        permission: Permission,
        reason: String,
    },

    #[error("scope denied: {database}:{environment}")]
    ScopeDenied {
        database: String,
        environment: String,
    },

    #[error("approval denied: {reason}")]
    ApprovalDenied { reason: String },
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("missing authorization header")]
    MissingToken,

    #[error("invalid token")]
    InvalidToken,

    #[error("token expired")]
    TokenExpired,

    #[error("token revoked")]
    TokenRevoked,

    #[error("user suspended")]
    UserSuspended,

    #[error("OIDC not configured")]
    OidcNotConfigured,

    #[error("OIDC verification failed: {0}")]
    OidcVerificationFailed(String),

    #[error("internal: {0}")]
    Internal(String),

    #[error("user limit reached")]
    UserLimitReached,

    #[error("no roles resolved for subject")]
    NoRolesResolved,

    #[error("scope ceiling blocks all resolved roles")]
    InsufficientScope,
}

impl AuthError {
    pub fn code(&self) -> &'static str {
        match self {
            AuthError::MissingToken => "auth.missing_token",
            AuthError::InvalidToken => "auth.invalid_token",
            AuthError::TokenExpired => "auth.token_expired",
            AuthError::TokenRevoked => "auth.token_revoked",
            AuthError::UserSuspended => "auth.user_suspended",
            AuthError::OidcNotConfigured => "auth.oidc_not_configured",
            AuthError::OidcVerificationFailed(_) => "auth.oidc_failed",
            AuthError::Internal(_) => "internal_error",
            AuthError::UserLimitReached => "policy.limit_exceeded",
            AuthError::NoRolesResolved => "auth.no_roles_resolved",
            AuthError::InsufficientScope => "auth.insufficient_scope",
        }
    }
}
