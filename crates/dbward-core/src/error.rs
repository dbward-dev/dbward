use thiserror::Error;

use crate::{Operation, Role};

#[derive(Debug, Error)]
pub enum Error {
    #[error("{role} is not allowed to perform {operation}")]
    PermissionDenied { role: Role, operation: Operation },

    #[error("DDL statements must go through migrations")]
    DdlNotAllowed,

    #[error("multi-statement queries are not allowed")]
    MultiStatement,

    #[error("execution token error: {0}")]
    Token(String),

    #[error("database error: {0}")]
    Database(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
