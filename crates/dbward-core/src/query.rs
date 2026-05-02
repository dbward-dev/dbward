use serde::{Deserialize, Serialize};

use crate::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum QueryType {
    Select,
    Insert,
    Update,
    Delete,
}

#[derive(Debug, Serialize)]
pub struct QueryResult {
    pub query_type: QueryType,
    pub rows: Vec<serde_json::Value>,
    pub rows_affected: u64,
}

pub fn classify_query(sql: &str) -> Result<QueryType, Error> {
    // Reject multi-statement queries (SQL injection prevention)
    let trimmed_end = sql.trim_end().trim_end_matches(';');
    if trimmed_end.contains(';') {
        return Err(Error::MultiStatement);
    }

    let upper = sql.trim_start().to_uppercase();
    if upper.starts_with("WITH") {
        // Writable CTE detection: scan CTE bodies for DML keywords
        if let Some(dml) = detect_writable_cte(&upper) {
            return Ok(dml);
        }
        Ok(QueryType::Select)
    } else if upper.starts_with("SELECT") {
        Ok(QueryType::Select)
    } else if upper.starts_with("INSERT") {
        Ok(QueryType::Insert)
    } else if upper.starts_with("UPDATE") {
        Ok(QueryType::Update)
    } else if upper.starts_with("DELETE") {
        Ok(QueryType::Delete)
    } else {
        Err(Error::DdlNotAllowed)
    }
}

/// Scan CTE bodies (content inside parentheses after AS) for DML keywords.
fn detect_writable_cte(upper: &str) -> Option<QueryType> {
    let mut depth = 0;
    let mut cte_body_start = false;
    let bytes = upper.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        match bytes[i] {
            b'(' => {
                depth += 1;
                if depth == 1 {
                    cte_body_start = true;
                }
            }
            b')' => {
                depth -= 1;
            }
            _ if cte_body_start && depth == 1 && !bytes[i].is_ascii_whitespace() => {
                cte_body_start = false;
                let rest = &upper[i..];
                if rest.starts_with("INSERT") {
                    return Some(QueryType::Insert);
                } else if rest.starts_with("UPDATE") {
                    return Some(QueryType::Update);
                } else if rest.starts_with("DELETE") {
                    return Some(QueryType::Delete);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_select() {
        assert!(matches!(classify_query("SELECT 1"), Ok(QueryType::Select)));
        assert!(matches!(
            classify_query("  select * from users"),
            Ok(QueryType::Select)
        ));
        assert!(matches!(
            classify_query("WITH cte AS (SELECT 1) SELECT * FROM cte"),
            Ok(QueryType::Select)
        ));
    }

    #[test]
    fn classifies_dml() {
        assert!(matches!(
            classify_query("INSERT INTO users VALUES (1)"),
            Ok(QueryType::Insert)
        ));
        assert!(matches!(
            classify_query("UPDATE users SET name = 'x'"),
            Ok(QueryType::Update)
        ));
        assert!(matches!(
            classify_query("DELETE FROM users"),
            Ok(QueryType::Delete)
        ));
    }

    #[test]
    fn rejects_ddl() {
        assert!(classify_query("CREATE TABLE t (id int)").is_err());
        assert!(classify_query("ALTER TABLE t ADD COLUMN x int").is_err());
        assert!(classify_query("DROP TABLE t").is_err());
    }

    #[test]
    fn rejects_multi_statement() {
        assert!(classify_query("SELECT 1; DROP TABLE users").is_err());
        assert!(classify_query("SELECT 1; SELECT 2").is_err());
    }

    #[test]
    fn allows_trailing_semicolon() {
        assert!(classify_query("SELECT 1;").is_ok());
        assert!(classify_query("SELECT 1 ;  ").is_ok());
    }

    #[test]
    fn detects_writable_cte_delete() {
        let sql = "WITH deleted AS (DELETE FROM users RETURNING *) SELECT * FROM deleted";
        assert!(matches!(classify_query(sql), Ok(QueryType::Delete)));
    }

    #[test]
    fn detects_writable_cte_insert() {
        let sql = "WITH ins AS (INSERT INTO archive SELECT * FROM users RETURNING *) SELECT * FROM ins";
        assert!(matches!(classify_query(sql), Ok(QueryType::Insert)));
    }

    #[test]
    fn detects_writable_cte_update() {
        let sql = "WITH upd AS (UPDATE users SET active = false RETURNING *) SELECT * FROM upd";
        assert!(matches!(classify_query(sql), Ok(QueryType::Update)));
    }

    #[test]
    fn readonly_cte_stays_select() {
        let sql = "WITH cte AS (SELECT id FROM users) SELECT * FROM cte";
        assert!(matches!(classify_query(sql), Ok(QueryType::Select)));
    }

    #[test]
    fn recursive_cte_stays_select() {
        let sql = "WITH RECURSIVE tree AS (SELECT 1 AS n UNION ALL SELECT n+1 FROM tree WHERE n < 10) SELECT * FROM tree";
        assert!(matches!(classify_query(sql), Ok(QueryType::Select)));
    }

    #[test]
    fn nested_cte_with_writable() {
        let sql = "WITH a AS (SELECT 1), b AS (DELETE FROM users RETURNING *) SELECT * FROM b";
        assert!(matches!(classify_query(sql), Ok(QueryType::Delete)));
    }
}
