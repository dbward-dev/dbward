use crate::values::Operation;

/// Classify SQL text into an Operation.
/// Strips EXPLAIN [ANALYZE] prefix and classifies the underlying statement.
/// Only SELECT/SHOW/DESCRIBE (without mutation) are considered read-only.
pub fn classify(sql: &str) -> Operation {
    let trimmed = sql.trim_start();
    let upper = trimmed.to_ascii_uppercase();

    // Strip EXPLAIN [ANALYZE [VERBOSE]] prefix to classify the underlying statement
    let effective = if upper.starts_with("EXPLAIN") {
        let rest = upper["EXPLAIN".len()..].trim_start();
        let rest = if rest.starts_with("ANALYZE") {
            rest["ANALYZE".len()..].trim_start()
        } else {
            rest
        };
        let rest = if rest.starts_with("VERBOSE") {
            rest["VERBOSE".len()..].trim_start()
        } else {
            rest
        };
        rest
    } else {
        &upper
    };

    if effective.starts_with("SELECT")
        || effective.starts_with("SHOW")
        || effective.starts_with("DESCRIBE")
        || effective.starts_with("VALUES")
        || effective.starts_with("TABLE")
    {
        Operation::ExecuteSelect
    } else {
        // EXPLAIN ANALYZE DELETE, INSERT, UPDATE, CREATE, DROP, etc. → DML
        Operation::ExecuteDml
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_variants() {
        assert_eq!(classify("SELECT 1"), Operation::ExecuteSelect);
        assert_eq!(classify("  select * from t"), Operation::ExecuteSelect);
        assert_eq!(classify("SHOW tables"), Operation::ExecuteSelect);
        assert_eq!(classify("DESCRIBE users"), Operation::ExecuteSelect);
    }

    #[test]
    fn explain_select_is_readonly() {
        assert_eq!(classify("EXPLAIN SELECT 1"), Operation::ExecuteSelect);
        assert_eq!(classify("EXPLAIN ANALYZE SELECT 1"), Operation::ExecuteSelect);
        assert_eq!(classify("EXPLAIN ANALYZE VERBOSE SELECT 1"), Operation::ExecuteSelect);
    }

    #[test]
    fn explain_analyze_dml_is_dml() {
        assert_eq!(classify("EXPLAIN ANALYZE DELETE FROM users"), Operation::ExecuteDml);
        assert_eq!(classify("EXPLAIN ANALYZE INSERT INTO t VALUES (1)"), Operation::ExecuteDml);
        assert_eq!(classify("EXPLAIN ANALYZE UPDATE t SET x=1"), Operation::ExecuteDml);
    }

    #[test]
    fn dml_variants() {
        assert_eq!(classify("INSERT INTO t VALUES (1)"), Operation::ExecuteDml);
        assert_eq!(classify("UPDATE t SET x=1"), Operation::ExecuteDml);
        assert_eq!(classify("DELETE FROM t"), Operation::ExecuteDml);
        assert_eq!(classify("DROP TABLE t"), Operation::ExecuteDml);
        assert_eq!(classify("CREATE TABLE t (id int)"), Operation::ExecuteDml);
        assert_eq!(classify("TRUNCATE t"), Operation::ExecuteDml);
    }
}
