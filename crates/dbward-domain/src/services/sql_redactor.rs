use sqlparser::ast::{Expr, Value, VisitMut, VisitorMut};
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;
use std::ops::ControlFlow;

struct LiteralRedactor;

impl VisitorMut for LiteralRedactor {
    type Break = ();

    fn pre_visit_value(&mut self, value: &mut Value) -> ControlFlow<Self::Break> {
        match value {
            Value::Null | Value::Placeholder(_) => {}
            _ => *value = Value::Placeholder("?".into()),
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expr: &mut Expr) -> ControlFlow<Self::Break> {
        match expr {
            Expr::TypedString { .. } | Expr::Interval(_) => {
                *expr = Expr::Value(Value::Placeholder("?".into()).with_empty_span());
            }
            _ => {}
        }
        ControlFlow::Continue(())
    }
}

/// Redact literal values from SQL using AST visitor.
/// Returns redacted SQL on success, placeholder on parse failure.
pub fn redact_literals(sql: &str) -> String {
    match Parser::parse_sql(&GenericDialect {}, sql) {
        Ok(mut stmts) => {
            let _ = stmts.visit(&mut LiteralRedactor);
            stmts
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join("; ")
        }
        Err(_) => "<redaction-failed: unparseable SQL>".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_string_literals() {
        let sql = "SELECT * FROM users WHERE name = 'alice'";
        let redacted = redact_literals(sql);
        assert!(!redacted.contains("alice"));
        assert!(redacted.contains("?"));
    }

    #[test]
    fn redacts_numeric_literals() {
        let sql = "DELETE FROM orders WHERE id = 42";
        let redacted = redact_literals(sql);
        assert!(!redacted.contains("42"));
    }

    #[test]
    fn preserves_null_and_placeholders() {
        let sql = "INSERT INTO t VALUES (NULL, $1)";
        let redacted = redact_literals(sql);
        assert!(redacted.contains("NULL"));
        assert!(redacted.contains("$1"));
    }

    #[test]
    fn parse_failure_returns_placeholder() {
        let sql = "NOT VALID SQL {{{{";
        let redacted = redact_literals(sql);
        assert!(redacted.contains("redaction-failed"));
    }
}
