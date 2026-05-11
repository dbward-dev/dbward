use crate::values::Operation;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    PostgreSql,
    MySql,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmlReason {
    Statement,
    DangerousFunction,
    SemanticEscalation,
    UnknownStatement,
    ParseFailure,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Classification {
    pub operation: Operation,
    pub dml_reason: Option<DmlReason>,
    pub statement_count: usize,
    pub statements: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassifyError {
    Rejected { reason: String },
    Empty,
}

impl fmt::Display for ClassifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected { reason } => write!(f, "rejected: {reason}"),
            Self::Empty => write!(f, "empty query"),
        }
    }
}

impl std::error::Error for ClassifyError {}
