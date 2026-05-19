use sqlparser::ast::Statement;
use sqlparser::dialect::{MySqlDialect, PostgreSqlDialect};
use sqlparser::parser::Parser;

use crate::services::classification::Dialect;

pub const MAX_SQL_BYTES: usize = 1_048_576;
pub const MAX_STATEMENTS: usize = 100;

/// Error from SQL parsing/validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    Empty,
    NullBytes,
    TooLarge,
    TooManyStatements,
    Rejected { reason: String },
    /// Parser failed but SQL is not outright rejected — fail-closed as DML.
    ParseFailed,
}

/// Parse and validate SQL into AST statements.
/// Performs pre-parse checks (size, null bytes, opaque keywords).
pub fn parse_statements(sql: &str, dialect: Dialect) -> Result<Vec<Statement>, ParseError> {
    if sql.contains('\0') {
        return Err(ParseError::NullBytes);
    }

    let trimmed = sql.trim();
    if trimmed.is_empty() {
        return Err(ParseError::Empty);
    }

    if trimmed.len() > MAX_SQL_BYTES {
        return Err(ParseError::TooLarge);
    }

    // Reject opaque statements
    if first_keyword_is(trimmed, "DO") {
        return Err(ParseError::Rejected {
            reason: "DO statements are not allowed; body content cannot be inspected".into(),
        });
    }
    if first_keyword_is(trimmed, "LOAD") {
        return Err(ParseError::Rejected {
            reason: "LOAD DATA is not allowed".into(),
        });
    }

    let d: &dyn sqlparser::dialect::Dialect = match dialect {
        Dialect::PostgreSql => &PostgreSqlDialect {},
        Dialect::MySql => &MySqlDialect {},
    };

    match Parser::parse_sql(d, trimmed) {
        Ok(stmts) => {
            if stmts.is_empty() {
                return Err(ParseError::Empty);
            }
            if stmts.len() > MAX_STATEMENTS {
                return Err(ParseError::TooManyStatements);
            }
            Ok(stmts)
        }
        Err(_) => {
            if contains_opaque_keyword(trimmed) {
                Err(ParseError::Rejected {
                    reason: "DO statements are not allowed; body content cannot be inspected"
                        .into(),
                })
            } else {
                Err(ParseError::ParseFailed)
            }
        }
    }
}

/// Check if the first significant keyword matches `target`.
fn first_keyword_is(sql: &str, target: &str) -> bool {
    let bytes = sql.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    while i < len {
        let b = bytes[i];
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if (b == b'-' && i + 1 < len && bytes[i + 1] == b'-') || b == b'#' {
            i += 1;
            while i < len && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if b == b'/' && i + 1 < len && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < len && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i += 2;
            continue;
        }
        let start = i;
        while i < len && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
            i += 1;
        }
        return sql[start..i].eq_ignore_ascii_case(target);
    }
    false
}

fn contains_opaque_keyword(sql: &str) -> bool {
    for part in sql.split(';') {
        if first_keyword_is(part, "DO") {
            return true;
        }
    }
    false
}
