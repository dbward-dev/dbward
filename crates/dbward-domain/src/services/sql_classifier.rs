use crate::values::Operation;

/// Classify SQL text into an Operation based on the first keyword.
pub fn classify(sql: &str) -> Operation {
    let trimmed = sql.trim_start();
    let upper = trimmed.to_ascii_uppercase();
    if upper.starts_with("SELECT")
        || upper.starts_with("EXPLAIN")
        || upper.starts_with("SHOW")
        || upper.starts_with("DESCRIBE")
    {
        Operation::ExecuteSelect
    } else {
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
        assert_eq!(classify("EXPLAIN ANALYZE SELECT 1"), Operation::ExecuteSelect);
        assert_eq!(classify("SHOW tables"), Operation::ExecuteSelect);
        assert_eq!(classify("DESCRIBE users"), Operation::ExecuteSelect);
    }

    #[test]
    fn dml_variants() {
        assert_eq!(classify("INSERT INTO t VALUES (1)"), Operation::ExecuteDml);
        assert_eq!(classify("UPDATE t SET x=1"), Operation::ExecuteDml);
        assert_eq!(classify("DELETE FROM t"), Operation::ExecuteDml);
        assert_eq!(classify("DROP TABLE t"), Operation::ExecuteDml);
        assert_eq!(classify("CREATE TABLE t (id int)"), Operation::ExecuteDml);
    }
}
