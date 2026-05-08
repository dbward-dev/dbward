use serde::{Deserialize, Serialize};
use sqlparser::ast::{Query, SetExpr, Statement};
use sqlparser::dialect::{MySqlDialect, PostgreSqlDialect};
use sqlparser::parser::Parser;

use crate::Error;

/// Check if SQL contains multiple statements (MySQL dialect).
pub fn is_multi_statement_mysql(sql: &str) -> bool {
    match Parser::parse_sql(&MySqlDialect {}, sql.trim()) {
        Ok(stmts) => stmts.len() > 1,
        Err(_) => false,
    }
}

/// Split multi-statement SQL into individual statements (MySQL dialect).
pub fn split_statements_mysql(sql: &str) -> Vec<String> {
    match Parser::parse_sql(&MySqlDialect {}, sql.trim()) {
        Ok(stmts) if stmts.len() > 1 => stmts.iter().map(|s| s.to_string()).collect(),
        _ => vec![sql.to_string()],
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum QueryType {
    Select,
    Insert,
    Update,
    Delete,
    Dml,
}

#[derive(Debug, Serialize)]
pub struct QueryResult {
    pub query_type: QueryType,
    pub rows: Vec<serde_json::Value>,
    pub rows_affected: u64,
    pub truncated: bool,
    pub truncation_reason: Option<String>,
}

/// Dangerous functions that can cause side effects when called inside SELECT.
const DANGEROUS_FUNCTIONS: &[&str] = &[
    // PostgreSQL: external connections / file I/O
    "dblink",
    "dblink_exec",
    "dblink_connect",
    "lo_export",
    "lo_import",
    "lo_unlink",
    "pg_read_file",
    "pg_read_binary_file",
    "pg_ls_dir",
    "pg_execute_server_program",
    "copy_to",
    "copy_from",
    // PostgreSQL: session manipulation
    "set_config",
    // PostgreSQL: DoS
    "pg_cancel_backend",
    "pg_terminate_backend",
    "pg_sleep",
    "pg_advisory_lock",
    "pg_advisory_xact_lock",
    // PostgreSQL: notification channel
    "pg_notify",
    // MySQL: file / shell
    "sys_exec",
    "sys_eval",
    "load_file",
    // MySQL: DoS
    "sleep",
    "benchmark",
];

/// SET variables that are safe to change without approval.
const SAFE_SET_VARIABLES: &[&str] = &[
    "statement_timeout",
    "lock_timeout",
    "idle_in_transaction_session_timeout",
    "timezone",
    "datestyle",
    "client_encoding",
    "application_name",
    "extra_float_digits",
    // MySQL
    "autocommit",
    "sql_mode",
    "character_set_client",
    "wait_timeout",
];

pub fn classify_query(sql: &str) -> Result<QueryType, Error> {
    classify_query_with_dialect(sql, &PostgreSqlDialect {})
}

pub fn classify_query_mysql(sql: &str) -> Result<QueryType, Error> {
    classify_query_with_dialect(sql, &MySqlDialect {})
}

fn classify_query_with_dialect(
    sql: &str,
    dialect: &dyn sqlparser::dialect::Dialect,
) -> Result<QueryType, Error> {
    // Pre-parse: reject null bytes
    if sql.contains('\0') {
        return Err(Error::UnsupportedStatement(
            "query contains null bytes".into(),
        ));
    }

    let trimmed = sql.trim();
    if trimmed.is_empty() {
        return Err(Error::Config("empty query".into()));
    }

    let statements = Parser::parse_sql(dialect, trimmed)
        .map_err(|e| Error::UnsupportedStatement(format!("failed to parse SQL: {e}")))?;

    if statements.is_empty() {
        return Err(Error::Config("empty query".into()));
    }

    // Classify each statement and escalate to the most dangerous
    let mut worst = Classification::Select;
    for stmt in &statements {
        let c = classify_statement(stmt);
        worst = worst.escalate(c);
    }

    match worst {
        Classification::Select => Ok(QueryType::Select),
        Classification::Dml(qt) => Ok(qt),
        Classification::Rejected(reason) => Err(Error::UnsupportedStatement(reason)),
    }
}

#[derive(Debug, Clone)]
enum Classification {
    Select,
    Dml(QueryType),
    Rejected(String),
}

impl Classification {
    fn escalate(self, other: Classification) -> Classification {
        match (&self, &other) {
            (Classification::Rejected(_), _) => self,
            (_, Classification::Rejected(_)) => other,
            (Classification::Dml(_), _) => self,
            (_, Classification::Dml(_)) => other,
            _ => self,
        }
    }
}

fn classify_statement(stmt: &Statement) -> Classification {
    match stmt {
        // === Select (read-only) ===
        Statement::Query(query) => classify_query_node(query),
        Statement::Explain {
            analyze: false, ..
        } => Classification::Select,
        Statement::ExplainTable { .. } => Classification::Select,
        Statement::ShowVariable { .. } => Classification::Select,
        Statement::ShowTables { .. } => Classification::Select,
        Statement::ShowColumns { .. } => Classification::Select,
        Statement::ShowCreate { .. } => Classification::Select,
        Statement::ShowDatabases { .. } => Classification::Select,
        Statement::ShowSchemas { .. } => Classification::Select,
        Statement::ShowViews { .. } => Classification::Select,
        Statement::ShowCollation { .. } => Classification::Select,
        Statement::ShowStatus { .. } => Classification::Select,
        Statement::ShowVariables { .. } => Classification::Select,
        Statement::ShowFunctions { .. } => Classification::Select,

        // === DML (data modification) ===
        Statement::Insert(_) => Classification::Dml(QueryType::Insert),
        Statement::Update(_) => Classification::Dml(QueryType::Update),
        Statement::Delete(_) => Classification::Dml(QueryType::Delete),
        Statement::Merge(_) => Classification::Dml(QueryType::Dml),
        Statement::Copy { .. } => Classification::Dml(QueryType::Dml),
        Statement::Call(_) => Classification::Dml(QueryType::Dml),
        Statement::Truncate(_) => Classification::Dml(QueryType::Dml),

        // EXPLAIN ANALYZE: actually executes the inner statement
        Statement::Explain {
            analyze: true,
            statement,
            ..
        } => classify_statement(statement),

        // EXECUTE: runs a prepared statement (unknown content)
        Statement::Execute { .. } => Classification::Dml(QueryType::Dml),

        // SET: only safe variables allowed
        Statement::Set(set) => classify_set(set),

        // LISTEN/NOTIFY: side effects
        Statement::NOTIFY { .. } => Classification::Dml(QueryType::Dml),
        Statement::LISTEN { .. } => Classification::Dml(QueryType::Dml),

        // === Rejected ===
        Statement::StartTransaction { .. } => {
            Classification::Rejected("transaction control (BEGIN) is not allowed; each request is an independent execution unit".into())
        }
        Statement::Commit { .. } => {
            Classification::Rejected("transaction control (COMMIT) is not allowed".into())
        }
        Statement::Rollback { .. } => {
            Classification::Rejected("transaction control (ROLLBACK) is not allowed".into())
        }
        Statement::Savepoint { .. } => {
            Classification::Rejected("transaction control (SAVEPOINT) is not allowed".into())
        }
        Statement::LockTables { .. } => {
            Classification::Rejected("LOCK TABLE is not allowed".into())
        }

        // Everything else: fail-closed
        other => Classification::Rejected(format!(
            "unsupported statement type. Only SELECT, INSERT, UPDATE, DELETE, TRUNCATE, MERGE, COPY, CALL are supported. Got: {}",
            statement_type_name(other)
        )),
    }
}

/// Inspect a Query node for writable CTEs, SELECT INTO, and dangerous functions.
fn classify_query_node(query: &Query) -> Classification {
    let mut result = Classification::Select;

    // Layer 2: SELECT ... INTO (MySQL OUTFILE / PG INTO)
    if let SetExpr::Select(select) = query.body.as_ref() {
        if select.into.is_some() {
            result = result.escalate(Classification::Dml(QueryType::Dml));
        }
    }

    // Layer 2: Writable CTE inspection
    if let Some(with) = &query.with {
        for cte in &with.cte_tables {
            if query_contains_dml(&cte.query) {
                result = result.escalate(Classification::Dml(QueryType::Dml));
                break;
            }
        }
    }

    // Layer 2: Dangerous function detection
    if query_has_dangerous_function(query) {
        result = result.escalate(Classification::Dml(QueryType::Dml));
    }

    result
}

/// Check if a Query's body contains DML (for writable CTE detection).
fn query_contains_dml(query: &Query) -> bool {
    match query.body.as_ref() {
        SetExpr::Insert(_) => true,
        SetExpr::Update(_) => true,
        SetExpr::SetOperation { left, right, .. } => {
            set_expr_contains_dml(left) || set_expr_contains_dml(right)
        }
        _ => {
            // sqlparser may represent DELETE in CTE as text or other variant.
            // Fallback: check the rendered SQL for DML keywords.
            let body_sql = query.body.to_string().to_uppercase();
            body_sql.starts_with("DELETE")
                || body_sql.starts_with("INSERT")
                || body_sql.starts_with("UPDATE")
        }
    }
}

fn set_expr_contains_dml(expr: &SetExpr) -> bool {
    match expr {
        SetExpr::Insert(_) | SetExpr::Update(_) => true,
        SetExpr::SetOperation { left, right, .. } => {
            set_expr_contains_dml(left) || set_expr_contains_dml(right)
        }
        _ => {
            let s = expr.to_string().to_uppercase();
            s.starts_with("DELETE") || s.starts_with("INSERT") || s.starts_with("UPDATE")
        }
    }
}

/// Walk the query AST looking for calls to dangerous functions.
fn query_has_dangerous_function(query: &Query) -> bool {
    let sql_repr = format!("{query}");
    let lower = sql_repr.to_lowercase();
    // Fast path: if none of the dangerous function names appear in the SQL text, skip AST walk
    DANGEROUS_FUNCTIONS.iter().any(|f| lower.contains(f))
}

/// Classify SET statements: only allow safe variables.
fn classify_set(set: &sqlparser::ast::Set) -> Classification {
    match set {
        sqlparser::ast::Set::SingleAssignment { variable, .. } => {
            let var_name = variable
                .0
                .iter()
                .map(|i| i.to_string().to_lowercase())
                .collect::<Vec<_>>()
                .join(".");
            if SAFE_SET_VARIABLES
                .iter()
                .any(|s| s.eq_ignore_ascii_case(&var_name))
            {
                Classification::Select
            } else {
                Classification::Rejected(format!(
                    "SET {var_name} is not allowed. Allowed: {}",
                    SAFE_SET_VARIABLES.join(", ")
                ))
            }
        }
        sqlparser::ast::Set::SetRole { .. } => {
            Classification::Rejected("SET ROLE is not allowed".into())
        }
        sqlparser::ast::Set::SetSessionAuthorization(_) => {
            Classification::Rejected("SET SESSION AUTHORIZATION is not allowed".into())
        }
        sqlparser::ast::Set::SetTransaction { .. } => {
            Classification::Rejected("SET TRANSACTION is not allowed".into())
        }
        sqlparser::ast::Set::SetTimeZone { .. } => Classification::Select,
        sqlparser::ast::Set::SetNames { .. } => Classification::Select,
        sqlparser::ast::Set::SetNamesDefault { .. } => Classification::Select,
        sqlparser::ast::Set::MultipleAssignments { assignments } => {
            // Check each assignment variable
            for a in assignments {
                let var_name = a
                    .name
                    .0
                    .iter()
                    .map(|i| i.to_string().to_lowercase())
                    .collect::<Vec<_>>()
                    .join(".");
                if !SAFE_SET_VARIABLES
                    .iter()
                    .any(|s| s.eq_ignore_ascii_case(&var_name))
                {
                    return Classification::Rejected(format!(
                        "SET {var_name} is not allowed. Allowed: {}",
                        SAFE_SET_VARIABLES.join(", ")
                    ));
                }
            }
            Classification::Select
        }
        _ => Classification::Rejected("unsupported SET variant".into()),
    }
}

fn statement_type_name(stmt: &Statement) -> &'static str {
    match stmt {
        Statement::Query(_) => "SELECT",
        Statement::Insert(_) => "INSERT",
        Statement::Update(_) => "UPDATE",
        Statement::Delete(_) => "DELETE",
        Statement::CreateTable(_) => "CREATE TABLE",
        Statement::CreateView(_) => "CREATE VIEW",
        Statement::CreateIndex(_) => "CREATE INDEX",
        Statement::AlterTable(_) => "ALTER TABLE",
        Statement::Drop { .. } => "DROP",
        Statement::Grant(_) => "GRANT",
        Statement::Revoke(_) => "REVOKE",
        Statement::Truncate(_) => "TRUNCATE",
        Statement::Prepare { .. } => "PREPARE",
        Statement::Deallocate { .. } => "DEALLOCATE",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // === Layer 1: AST structural classification ===

    #[test]
    fn classifies_select() {
        assert_eq!(classify_query("SELECT 1").unwrap(), QueryType::Select);
        assert_eq!(
            classify_query("  select * from users").unwrap(),
            QueryType::Select
        );
    }

    #[test]
    fn classifies_with_select() {
        assert_eq!(
            classify_query("WITH cte AS (SELECT 1) SELECT * FROM cte").unwrap(),
            QueryType::Select
        );
    }

    #[test]
    fn classifies_insert() {
        assert_eq!(
            classify_query("INSERT INTO users VALUES (1)").unwrap(),
            QueryType::Insert
        );
    }

    #[test]
    fn classifies_update() {
        assert_eq!(
            classify_query("UPDATE users SET name = 'x'").unwrap(),
            QueryType::Update
        );
    }

    #[test]
    fn classifies_delete() {
        assert_eq!(
            classify_query("DELETE FROM users").unwrap(),
            QueryType::Delete
        );
    }

    #[test]
    fn classifies_truncate() {
        assert_eq!(
            classify_query("TRUNCATE TABLE users").unwrap(),
            QueryType::Dml
        );
    }

    #[test]
    fn classifies_call() {
        assert_eq!(classify_query("CALL my_proc()").unwrap(), QueryType::Dml);
    }

    #[test]
    fn classifies_copy() {
        assert_eq!(
            classify_query("COPY users FROM '/tmp/data.csv'").unwrap(),
            QueryType::Dml
        );
        assert_eq!(
            classify_query("COPY users TO '/tmp/dump.csv'").unwrap(),
            QueryType::Dml
        );
    }

    #[test]
    fn explain_select_is_read() {
        assert_eq!(
            classify_query("EXPLAIN SELECT 1").unwrap(),
            QueryType::Select
        );
    }

    #[test]
    fn explain_analyze_delete_is_dml() {
        assert_eq!(
            classify_query("EXPLAIN ANALYZE DELETE FROM t").unwrap(),
            QueryType::Delete
        );
    }

    #[test]
    fn explain_analyze_select_is_read() {
        assert_eq!(
            classify_query("EXPLAIN ANALYZE SELECT 1").unwrap(),
            QueryType::Select
        );
    }

    #[test]
    fn comment_before_delete_is_dml() {
        assert_eq!(
            classify_query("/* comment */ DELETE FROM t").unwrap(),
            QueryType::Delete
        );
    }

    #[test]
    fn case_insensitive() {
        assert_eq!(classify_query("dElEtE fRoM t").unwrap(), QueryType::Delete);
    }

    #[test]
    fn rejects_create_table() {
        assert!(classify_query("CREATE TABLE t (id int)").is_err());
    }

    #[test]
    fn rejects_alter_table() {
        assert!(classify_query("ALTER TABLE t ADD COLUMN x int").is_err());
    }

    #[test]
    fn rejects_drop() {
        assert!(classify_query("DROP TABLE t").is_err());
    }

    #[test]
    fn rejects_grant() {
        assert!(classify_query("GRANT ALL ON t TO public").is_err());
    }

    #[test]
    fn rejects_begin() {
        assert!(classify_query("BEGIN").is_err());
    }

    #[test]
    fn rejects_commit() {
        assert!(classify_query("COMMIT").is_err());
    }

    #[test]
    fn rejects_lock_table() {
        assert!(classify_query("LOCK TABLE users IN EXCLUSIVE MODE").is_err());
    }

    #[test]
    fn rejects_prepare() {
        assert!(classify_query("PREPARE stmt AS SELECT 1").is_err());
    }

    #[test]
    fn execute_is_dml() {
        assert_eq!(classify_query("EXECUTE stmt").unwrap(), QueryType::Dml);
    }

    #[test]
    fn show_tables_is_select() {
        assert_eq!(
            classify_query_mysql("SHOW TABLES").unwrap(),
            QueryType::Select
        );
    }

    // === Layer 2: Semantic inspection ===

    #[test]
    fn writable_cte_is_dml() {
        let sql = "WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d";
        assert!(matches!(
            classify_query(sql).unwrap(),
            QueryType::Dml | QueryType::Delete
        ));
    }

    #[test]
    fn dangerous_function_dblink() {
        let sql = "SELECT dblink_exec('connstr', 'DELETE FROM t')";
        assert_eq!(classify_query(sql).unwrap(), QueryType::Dml);
    }

    #[test]
    fn dangerous_function_lo_export() {
        let sql = "SELECT lo_export(12345, '/tmp/secret')";
        assert_eq!(classify_query(sql).unwrap(), QueryType::Dml);
    }

    #[test]
    fn dangerous_function_set_config() {
        let sql = "SELECT set_config('role', 'admin', false)";
        assert_eq!(classify_query(sql).unwrap(), QueryType::Dml);
    }

    #[test]
    fn dangerous_function_pg_terminate() {
        let sql = "SELECT pg_terminate_backend(1234)";
        assert_eq!(classify_query(sql).unwrap(), QueryType::Dml);
    }

    #[test]
    fn dangerous_function_pg_sleep() {
        let sql = "SELECT pg_sleep(999)";
        assert_eq!(classify_query(sql).unwrap(), QueryType::Dml);
    }

    #[test]
    fn safe_function_not_flagged() {
        let sql = "SELECT count(*), now() FROM users";
        assert_eq!(classify_query(sql).unwrap(), QueryType::Select);
    }

    #[test]
    fn safe_set_timeout() {
        assert_eq!(
            classify_query("SET statement_timeout = '5s'").unwrap(),
            QueryType::Select
        );
    }

    #[test]
    fn set_role_rejected() {
        assert!(classify_query("SET ROLE admin").is_err());
    }

    #[test]
    fn set_search_path_rejected() {
        assert!(classify_query("SET search_path TO evil_schema, public").is_err());
    }

    // === Edge cases ===

    #[test]
    fn empty_query_rejected() {
        assert!(classify_query("").is_err());
    }

    #[test]
    fn whitespace_only_rejected() {
        assert!(classify_query("   \n\t  ").is_err());
    }

    #[test]
    fn null_byte_rejected() {
        assert!(classify_query("SELECT \01").is_err());
    }

    #[test]
    fn trailing_semicolon() {
        assert_eq!(classify_query("SELECT 1;").unwrap(), QueryType::Select);
    }

    #[test]
    fn multi_statement_dml() {
        // Multiple DML statements: escalate to most dangerous
        let result = classify_query("INSERT INTO t VALUES (1); UPDATE t SET x = 2");
        assert!(result.is_ok());
        let qt = result.unwrap();
        assert!(matches!(qt, QueryType::Insert | QueryType::Update));
    }

    #[test]
    fn multi_statement_with_ddl_rejected() {
        assert!(classify_query("INSERT INTO t VALUES (1); DROP TABLE t").is_err());
    }
}
