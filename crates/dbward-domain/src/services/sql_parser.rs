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
    Rejected {
        reason: String,
    },
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

#[cfg(test)]
mod tests {
    use super::*;

    // --- Error paths ---

    #[test]
    fn empty_string_returns_empty() {
        assert_eq!(
            parse_statements("", Dialect::PostgreSql),
            Err(ParseError::Empty)
        );
    }

    #[test]
    fn whitespace_only_returns_empty() {
        assert_eq!(
            parse_statements("   \n\t  ", Dialect::PostgreSql),
            Err(ParseError::Empty)
        );
    }

    #[test]
    fn null_bytes_rejected() {
        assert_eq!(
            parse_statements("SELECT \0", Dialect::PostgreSql),
            Err(ParseError::NullBytes)
        );
    }

    #[test]
    fn null_byte_before_valid_sql() {
        assert_eq!(
            parse_statements("\0SELECT 1", Dialect::PostgreSql),
            Err(ParseError::NullBytes)
        );
    }

    #[test]
    fn too_large_rejected() {
        let big = "SELECT ".to_string() + &"x".repeat(MAX_SQL_BYTES);
        assert_eq!(
            parse_statements(&big, Dialect::PostgreSql),
            Err(ParseError::TooLarge)
        );
    }

    #[test]
    fn at_max_bytes_not_too_large() {
        let sql = "S".repeat(MAX_SQL_BYTES);
        // May fail to parse but should NOT be TooLarge
        assert_ne!(
            parse_statements(&sql, Dialect::PostgreSql),
            Err(ParseError::TooLarge)
        );
    }

    #[test]
    fn exceeds_max_bytes_rejected() {
        let sql = "S".repeat(MAX_SQL_BYTES + 1);
        assert_eq!(
            parse_statements(&sql, Dialect::PostgreSql),
            Err(ParseError::TooLarge)
        );
    }

    #[test]
    fn do_statement_rejected() {
        assert!(matches!(
            parse_statements("DO $$ BEGIN NULL; END $$;", Dialect::PostgreSql),
            Err(ParseError::Rejected { .. })
        ));
    }

    #[test]
    fn do_case_insensitive() {
        assert!(matches!(
            parse_statements("do $$ BEGIN NULL; END $$;", Dialect::PostgreSql),
            Err(ParseError::Rejected { .. })
        ));
    }

    #[test]
    fn do_after_comment_rejected() {
        assert!(matches!(
            parse_statements("-- comment\nDO $$ BEGIN NULL; END $$;", Dialect::PostgreSql),
            Err(ParseError::Rejected { .. })
        ));
    }

    #[test]
    fn do_after_block_comment_rejected() {
        assert!(matches!(
            parse_statements("/* block */ DO $$ BEGIN NULL; END $$;", Dialect::PostgreSql),
            Err(ParseError::Rejected { .. })
        ));
    }

    #[test]
    fn load_data_rejected() {
        assert!(matches!(
            parse_statements("LOAD DATA INFILE '/tmp/x' INTO TABLE t", Dialect::MySql),
            Err(ParseError::Rejected { .. })
        ));
    }

    #[test]
    fn too_many_statements_rejected() {
        let sql = (0..=MAX_STATEMENTS)
            .map(|i| format!("SELECT {i}"))
            .collect::<Vec<_>>()
            .join("; ");
        assert_eq!(
            parse_statements(&sql, Dialect::PostgreSql),
            Err(ParseError::TooManyStatements)
        );
    }

    #[test]
    fn unparseable_sql_returns_parse_failed() {
        assert_eq!(
            parse_statements("NOT VALID SQL HERE", Dialect::PostgreSql),
            Err(ParseError::ParseFailed)
        );
    }

    #[test]
    fn unparseable_with_do_in_body_returns_rejected() {
        // "SELECT 1; DO something" — second part has DO, triggers contains_opaque_keyword
        assert!(matches!(
            parse_statements("INVALID; DO something", Dialect::PostgreSql),
            Err(ParseError::Rejected { .. })
        ));
    }

    // --- Normal paths ---

    #[test]
    fn simple_select_pg() {
        let stmts = parse_statements("SELECT 1", Dialect::PostgreSql).unwrap();
        assert_eq!(stmts.len(), 1);
    }

    #[test]
    fn simple_select_mysql() {
        let stmts = parse_statements("SELECT 1", Dialect::MySql).unwrap();
        assert_eq!(stmts.len(), 1);
    }

    #[test]
    fn multiple_statements() {
        let stmts = parse_statements("SELECT 1; SELECT 2; SELECT 3", Dialect::PostgreSql).unwrap();
        assert_eq!(stmts.len(), 3);
    }

    #[test]
    fn leading_trailing_whitespace_trimmed() {
        let stmts = parse_statements("  \n SELECT 1 \n  ", Dialect::PostgreSql).unwrap();
        assert_eq!(stmts.len(), 1);
    }

    #[test]
    fn dml_parses_correctly() {
        let stmts = parse_statements(
            "UPDATE users SET name = 'test' WHERE id = 1",
            Dialect::PostgreSql,
        )
        .unwrap();
        assert_eq!(stmts.len(), 1);
    }

    #[test]
    fn ddl_parses_correctly() {
        let stmts =
            parse_statements("CREATE TABLE t (id INT PRIMARY KEY)", Dialect::PostgreSql).unwrap();
        assert_eq!(stmts.len(), 1);
    }

    #[test]
    fn exactly_max_statements_allowed() {
        let sql = (0..MAX_STATEMENTS)
            .map(|i| format!("SELECT {i}"))
            .collect::<Vec<_>>()
            .join("; ");
        let stmts = parse_statements(&sql, Dialect::PostgreSql).unwrap();
        assert_eq!(stmts.len(), MAX_STATEMENTS);
    }

    // --- first_keyword_is edge cases ---

    #[test]
    fn hash_comment_skipped_mysql() {
        // MySQL # comment before LOAD
        assert!(matches!(
            parse_statements(
                "# comment\nLOAD DATA INFILE '/x' INTO TABLE t",
                Dialect::MySql
            ),
            Err(ParseError::Rejected { .. })
        ));
    }

    #[test]
    fn parses_select_with_do_in_function_name() {
        let result = parse_statements("SELECT do_something()", Dialect::PostgreSql);
        assert!(result.is_ok());
    }
}
