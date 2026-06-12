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
    Ddl,
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
    pub is_ddl_only: bool,
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

/// Statement-level categorization for break-glass bypass decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementCategory {
    ReadOnly,
    Dml,
    /// DDL the classifier already allows (CREATE TABLE, VIEW, INDEX, ALTER TABLE)
    SafeDdl,
    /// DDL bypassable via break-glass --allow-ddl
    BreakGlassDdl,
    /// Privilege/infra DDL — NEVER bypassable
    PrivilegeDdl,
    /// Transaction control — NEVER bypassable
    TxControl,
    /// Security boundary — NEVER bypassable
    SecurityBoundary,
    /// Code execution — NEVER bypassable
    CodeExecution,
    /// Unknown — fail-closed as DML
    Unknown,
}

impl StatementCategory {
    /// Whether this category is eligible for break-glass DDL bypass.
    pub fn is_break_glass_eligible(self) -> bool {
        matches!(self, Self::BreakGlassDdl | Self::SafeDdl)
    }
}
