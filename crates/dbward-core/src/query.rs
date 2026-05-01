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
    let trimmed = sql.trim_start().to_uppercase();
    if trimmed.starts_with("SELECT") || trimmed.starts_with("WITH") {
        Ok(QueryType::Select)
    } else if trimmed.starts_with("INSERT") {
        Ok(QueryType::Insert)
    } else if trimmed.starts_with("UPDATE") {
        Ok(QueryType::Update)
    } else if trimmed.starts_with("DELETE") {
        Ok(QueryType::Delete)
    } else {
        Err(Error::DdlNotAllowed)
    }
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
}
