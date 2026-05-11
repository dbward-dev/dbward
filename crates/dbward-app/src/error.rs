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

    #[error("internal: {0}")]
    Internal(String),
}

#[derive(Debug, thiserror::Error)]
pub enum AuthzError {
    #[error("permission denied: {permission} — {reason}")]
    Forbidden { permission: Permission, reason: String },

    #[error("scope denied: {database}:{environment}")]
    ScopeDenied { database: String, environment: String },
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
}
