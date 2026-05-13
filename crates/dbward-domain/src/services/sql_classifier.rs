use crate::services::classification::{Classification, ClassifyError, Dialect, DmlReason};
use crate::values::Operation;
use sqlparser::ast::{Set, SetExpr, Statement};
use sqlparser::dialect::{MySqlDialect, PostgreSqlDialect};
use sqlparser::parser::Parser;

const MAX_SQL_BYTES: usize = 1_048_576;
const MAX_STATEMENTS: usize = 100;

/// Dangerous functions that can cause side effects when called inside SELECT.
const DANGEROUS_FUNCTIONS: &[&str] = &[
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
    "set_config",
    "pg_cancel_backend",
    "pg_terminate_backend",
    "pg_sleep",
    "pg_advisory_lock",
    "pg_advisory_xact_lock",
    "pg_notify",
    "sys_exec",
    "sys_eval",
    "load_file",
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
    "autocommit",
    "sql_mode",
    "character_set_client",
    "wait_timeout",
];

pub fn classify(sql: &str, dialect: Dialect) -> Result<Classification, ClassifyError> {
    if sql.contains('\0') {
        return Err(ClassifyError::Rejected {
            reason: "query contains null bytes".into(),
        });
    }

    let trimmed = sql.trim();
    if trimmed.is_empty() {
        return Err(ClassifyError::Empty);
    }

    if trimmed.len() > MAX_SQL_BYTES {
        return Err(ClassifyError::Rejected {
            reason: format!("query exceeds maximum size of {MAX_SQL_BYTES} bytes"),
        });
    }

    let _parser_dialect: &dyn sqlparser::dialect::Dialect = match dialect {
        Dialect::PostgreSql => &PostgreSqlDialect {},
        Dialect::MySql => &MySqlDialect {},
    };

    // Pre-parse: reject LOAD DATA (sqlparser can't parse it for PG/MySQL dialects)
    let upper = trimmed.to_ascii_uppercase();
    if upper.starts_with("LOAD DATA") || upper.starts_with("LOAD\t") || upper.starts_with("LOAD\n") {
        return Err(ClassifyError::Rejected {
            reason: "LOAD DATA is not allowed".into(),
        });
    }

    // Parse directly — MAX_SQL_BYTES (1MB) limit above prevents pathological inputs
    let statements = {
        let d: &dyn sqlparser::dialect::Dialect = match dialect {
            Dialect::PostgreSql => &PostgreSqlDialect {},
            Dialect::MySql => &MySqlDialect {},
        };
        match Parser::parse_sql(d, trimmed) {
            Ok(stmts) => stmts,
            Err(_) => {
                // Parse failure → fail-closed: treat as DML (requires approval)
                return Ok(Classification {
                    operation: Operation::ExecuteDml,
                    dml_reason: Some(DmlReason::ParseFailure),
                    statement_count: 1,
                    statements: vec![trimmed.to_string()],
                });
            }
        }
    };

    if statements.is_empty() {
        return Err(ClassifyError::Empty);
    }

    if statements.len() > MAX_STATEMENTS {
        return Err(ClassifyError::Rejected {
            reason: format!("query exceeds maximum of {MAX_STATEMENTS} statements"),
        });
    }

    let stmt_strings: Vec<String> = statements.iter().map(|s| s.to_string()).collect();

    // Classify each statement, escalating to the most restrictive
    let mut worst = InternalClass::Select;
    for stmt in &statements {
        let c = classify_statement(stmt);
        worst = worst.escalate(c);
    }

    match worst {
        InternalClass::Select => Ok(Classification {
            operation: Operation::ExecuteSelect,
            dml_reason: None,
            statement_count: stmt_strings.len(),
            statements: stmt_strings,
        }),
        InternalClass::Dml(reason) => Ok(Classification {
            operation: Operation::ExecuteDml,
            dml_reason: Some(reason),
            statement_count: stmt_strings.len(),
            statements: stmt_strings,
        }),
        InternalClass::Rejected(reason) => Err(ClassifyError::Rejected { reason }),
    }
}

#[derive(Debug)]
enum InternalClass {
    Select,
    Dml(DmlReason),
    Rejected(String),
}

impl InternalClass {
    fn escalate(self, other: InternalClass) -> InternalClass {
        match (&self, &other) {
            (InternalClass::Rejected(_), _) => self,
            (_, InternalClass::Rejected(_)) => other,
            (InternalClass::Dml(_), _) => self,
            (_, InternalClass::Dml(_)) => other,
            _ => self,
        }
    }
}

fn classify_statement(stmt: &Statement) -> InternalClass {
    match stmt {
        // === Select (read-only) ===
        Statement::Query(query) => classify_query_node(query),
        Statement::Explain { analyze: false, .. } => InternalClass::Select,
        Statement::ExplainTable { .. } => InternalClass::Select,
        Statement::ShowVariable { .. } => InternalClass::Select,
        Statement::ShowTables { .. } => InternalClass::Select,
        Statement::ShowColumns { .. } => InternalClass::Select,
        Statement::ShowCreate { .. } => InternalClass::Select,
        Statement::ShowDatabases { .. } => InternalClass::Select,
        Statement::ShowSchemas { .. } => InternalClass::Select,
        Statement::ShowViews { .. } => InternalClass::Select,
        Statement::ShowCollation { .. } => InternalClass::Select,
        Statement::ShowStatus { .. } => InternalClass::Select,
        Statement::ShowVariables { .. } => InternalClass::Select,
        Statement::ShowFunctions { .. } => InternalClass::Select,

        // === DML (data modification) ===
        Statement::Insert(_) => InternalClass::Dml(DmlReason::Statement),
        Statement::Update(_) => InternalClass::Dml(DmlReason::Statement),
        Statement::Delete(_) => InternalClass::Dml(DmlReason::Statement),
        Statement::Merge(_) => InternalClass::Dml(DmlReason::Statement),
        Statement::Copy { .. } => InternalClass::Dml(DmlReason::Statement),
        Statement::Call(_) => InternalClass::Dml(DmlReason::Statement),
        Statement::Truncate(_) => InternalClass::Dml(DmlReason::Statement),

        // EXPLAIN ANALYZE: actually executes the inner statement
        Statement::Explain {
            analyze: true,
            statement,
            ..
        } => classify_statement(statement),

        // EXECUTE: runs a prepared statement (unknown content)
        Statement::Execute { .. } => InternalClass::Dml(DmlReason::UnknownStatement),

        // SET: only safe variables allowed
        Statement::Set(set) => classify_set(set),

        // LISTEN/NOTIFY: side effects
        Statement::NOTIFY { .. } => InternalClass::Dml(DmlReason::Statement),
        Statement::LISTEN { .. } => InternalClass::Dml(DmlReason::Statement),

        // === Rejected (DDL / TX control) ===
        Statement::StartTransaction { .. } => InternalClass::Rejected(
            "transaction control (BEGIN) is not allowed; each request is an independent execution unit".into(),
        ),
        Statement::Commit { .. } => {
            InternalClass::Rejected("transaction control (COMMIT) is not allowed".into())
        }
        Statement::Rollback { .. } => {
            InternalClass::Rejected("transaction control (ROLLBACK) is not allowed".into())
        }
        Statement::Savepoint { .. } => {
            InternalClass::Rejected("transaction control (SAVEPOINT) is not allowed".into())
        }
        Statement::LockTables { .. } => {
            InternalClass::Rejected("LOCK TABLE is not allowed".into())
        }

        // === Rejected (DDL) ===
        Statement::CreateTable(_)
        | Statement::CreateView(_)
        | Statement::CreateIndex(_)
        | Statement::CreateSchema { .. }
        | Statement::CreateDatabase { .. }
        | Statement::CreateFunction(_)
        | Statement::CreateProcedure { .. }
        | Statement::CreateSequence { .. }
        | Statement::CreateType { .. }
        | Statement::CreateRole(_)
        | Statement::AlterTable(_)
        | Statement::AlterIndex { .. }
        | Statement::AlterView { .. }
        | Statement::AlterRole { .. }
        | Statement::AlterSchema(_)
        | Statement::Drop { .. }
        | Statement::Grant(_)
        | Statement::Revoke(_) => InternalClass::Rejected(
            "DDL statements (CREATE, ALTER, DROP, GRANT, REVOKE) are not allowed; use migrations"
                .into(),
        ),

        Statement::LoadData { .. } => {
            InternalClass::Rejected("LOAD DATA is not allowed".into())
        }

        // Everything else: unknown → DML (fail-closed, requires approval)
        _ => InternalClass::Dml(DmlReason::UnknownStatement),
    }
}

fn classify_query_node(query: &sqlparser::ast::Query) -> InternalClass {
    let mut result = InternalClass::Select;

    // Layer 2: SELECT ... INTO
    if let SetExpr::Select(select) = query.body.as_ref() {
        if select.into.is_some() {
            result = result.escalate(InternalClass::Dml(DmlReason::SemanticEscalation));
        }
    }

    // Layer 2: Writable CTE inspection
    if let Some(with) = &query.with {
        for cte in &with.cte_tables {
            if query_contains_dml(&cte.query) {
                result = result.escalate(InternalClass::Dml(DmlReason::SemanticEscalation));
                break;
            }
        }
    }

    // Layer 2: Dangerous function detection
    if query_has_dangerous_function(query) {
        result = result.escalate(InternalClass::Dml(DmlReason::DangerousFunction));
    }

    result
}

fn query_contains_dml(query: &sqlparser::ast::Query) -> bool {
    match query.body.as_ref() {
        SetExpr::Insert(_) | SetExpr::Update(_) => true,
        SetExpr::SetOperation { left, right, .. } => {
            set_expr_contains_dml(left) || set_expr_contains_dml(right)
        }
        _ => {
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

fn query_has_dangerous_function(query: &sqlparser::ast::Query) -> bool {
    use sqlparser::ast::{Expr, Visit, Visitor};
    use std::ops::ControlFlow;

    struct DangerousFunctionVisitor {
        found: bool,
    }

    impl Visitor for DangerousFunctionVisitor {
        type Break = ();

        fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<()> {
            if let Expr::Function(func) = expr {
                let name = func
                    .name
                    .0
                    .last()
                    .and_then(|part| part.as_ident())
                    .map(|ident| ident.value.to_lowercase())
                    .unwrap_or_default();
                if DANGEROUS_FUNCTIONS.contains(&name.as_str()) {
                    self.found = true;
                    return ControlFlow::Break(());
                }
            }
            ControlFlow::Continue(())
        }
    }

    let mut visitor = DangerousFunctionVisitor { found: false };
    let _ = query.visit(&mut visitor);
    visitor.found
}

fn classify_set(set: &Set) -> InternalClass {
    match set {
        Set::SingleAssignment { variable, .. } => {
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
                InternalClass::Select
            } else {
                InternalClass::Rejected(format!(
                    "SET {var_name} is not allowed. Allowed: {}",
                    SAFE_SET_VARIABLES.join(", ")
                ))
            }
        }
        Set::SetRole { .. } => InternalClass::Rejected("SET ROLE is not allowed".into()),
        Set::SetSessionAuthorization(_) => {
            InternalClass::Rejected("SET SESSION AUTHORIZATION is not allowed".into())
        }
        Set::SetTransaction { .. } => {
            InternalClass::Rejected("SET TRANSACTION is not allowed".into())
        }
        Set::SetTimeZone { .. } => InternalClass::Select,
        Set::SetNames { .. } => InternalClass::Select,
        Set::SetNamesDefault { .. } => InternalClass::Select,
        Set::MultipleAssignments { assignments } => {
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
                    return InternalClass::Rejected(format!(
                        "SET {var_name} is not allowed. Allowed: {}",
                        SAFE_SET_VARIABLES.join(", ")
                    ));
                }
            }
            InternalClass::Select
        }
        _ => InternalClass::Rejected("unsupported SET variant".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pg(sql: &str) -> Result<Classification, ClassifyError> {
        classify(sql, Dialect::PostgreSql)
    }

    fn mysql(sql: &str) -> Result<Classification, ClassifyError> {
        classify(sql, Dialect::MySql)
    }

    // === Layer 1: AST structural classification ===

    #[test]
    fn classifies_select() {
        let c = pg("SELECT 1").unwrap();
        assert_eq!(c.operation, Operation::ExecuteSelect);
        assert_eq!(c.dml_reason, None);
    }

    #[test]
    fn classifies_select_from_table() {
        let c = pg("select * from users").unwrap();
        assert_eq!(c.operation, Operation::ExecuteSelect);
    }

    #[test]
    fn classifies_with_select() {
        let c = pg("WITH cte AS (SELECT 1) SELECT * FROM cte").unwrap();
        assert_eq!(c.operation, Operation::ExecuteSelect);
    }

    #[test]
    fn classifies_insert() {
        let c = pg("INSERT INTO users VALUES (1)").unwrap();
        assert_eq!(c.operation, Operation::ExecuteDml);
        assert_eq!(c.dml_reason, Some(DmlReason::Statement));
    }

    #[test]
    fn classifies_update() {
        let c = pg("UPDATE users SET name = 'x'").unwrap();
        assert_eq!(c.operation, Operation::ExecuteDml);
        assert_eq!(c.dml_reason, Some(DmlReason::Statement));
    }

    #[test]
    fn classifies_delete() {
        let c = pg("DELETE FROM users").unwrap();
        assert_eq!(c.operation, Operation::ExecuteDml);
        assert_eq!(c.dml_reason, Some(DmlReason::Statement));
    }

    #[test]
    fn classifies_truncate() {
        let c = pg("TRUNCATE TABLE users").unwrap();
        assert_eq!(c.operation, Operation::ExecuteDml);
        assert_eq!(c.dml_reason, Some(DmlReason::Statement));
    }

    #[test]
    fn classifies_call() {
        let c = pg("CALL my_proc()").unwrap();
        assert_eq!(c.operation, Operation::ExecuteDml);
    }

    #[test]
    fn classifies_copy() {
        let c = pg("COPY users FROM '/tmp/data.csv'").unwrap();
        assert_eq!(c.operation, Operation::ExecuteDml);
    }

    #[test]
    fn explain_select_is_read() {
        let c = pg("EXPLAIN SELECT 1").unwrap();
        assert_eq!(c.operation, Operation::ExecuteSelect);
    }

    #[test]
    fn explain_analyze_delete_is_dml() {
        let c = pg("EXPLAIN ANALYZE DELETE FROM t").unwrap();
        assert_eq!(c.operation, Operation::ExecuteDml);
    }

    #[test]
    fn explain_analyze_select_is_read() {
        let c = pg("EXPLAIN ANALYZE SELECT 1").unwrap();
        assert_eq!(c.operation, Operation::ExecuteSelect);
    }

    #[test]
    fn comment_before_delete_is_dml() {
        let c = pg("/* comment */ DELETE FROM t").unwrap();
        assert_eq!(c.operation, Operation::ExecuteDml);
    }

    #[test]
    fn case_insensitive() {
        let c = pg("dElEtE fRoM t").unwrap();
        assert_eq!(c.operation, Operation::ExecuteDml);
    }

    // === Rejected (DDL / TX control) ===

    #[test]
    fn rejects_create_table() {
        let r = pg("CREATE TABLE t (id int)");
        assert!(matches!(r, Err(ClassifyError::Rejected { .. })));
    }

    #[test]
    fn rejects_alter_table() {
        let r = pg("ALTER TABLE t ADD COLUMN x int");
        assert!(matches!(r, Err(ClassifyError::Rejected { .. })));
    }

    #[test]
    fn rejects_drop() {
        let r = pg("DROP TABLE t");
        assert!(matches!(r, Err(ClassifyError::Rejected { .. })));
    }

    #[test]
    fn rejects_grant() {
        let r = pg("GRANT ALL ON t TO public");
        assert!(matches!(r, Err(ClassifyError::Rejected { .. })));
    }

    #[test]
    fn rejects_begin() {
        let r = pg("BEGIN");
        assert!(matches!(r, Err(ClassifyError::Rejected { .. })));
    }

    #[test]
    fn rejects_commit() {
        let r = pg("COMMIT");
        assert!(matches!(r, Err(ClassifyError::Rejected { .. })));
    }

    #[test]
    fn lock_table_is_dml() {
        // sqlparser doesn't parse LOCK TABLE in PostgreSQL dialect → ParseFailure → DML
        let c = pg("LOCK TABLE users IN EXCLUSIVE MODE").unwrap();
        assert_eq!(c.operation, Operation::ExecuteDml);
        assert_eq!(c.dml_reason, Some(DmlReason::ParseFailure));
    }

    #[test]
    fn execute_is_dml() {
        let c = pg("EXECUTE stmt").unwrap();
        assert_eq!(c.operation, Operation::ExecuteDml);
        assert_eq!(c.dml_reason, Some(DmlReason::UnknownStatement));
    }

    #[test]
    fn show_tables_mysql() {
        let c = mysql("SHOW TABLES").unwrap();
        assert_eq!(c.operation, Operation::ExecuteSelect);
    }

    // === Layer 2: Semantic inspection ===

    #[test]
    fn writable_cte_is_dml() {
        let c = pg("WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d").unwrap();
        assert_eq!(c.operation, Operation::ExecuteDml);
        assert_eq!(c.dml_reason, Some(DmlReason::SemanticEscalation));
    }

    #[test]
    fn dangerous_function_dblink() {
        let c = pg("SELECT dblink_exec('connstr', 'DELETE FROM t')").unwrap();
        assert_eq!(c.operation, Operation::ExecuteDml);
        assert_eq!(c.dml_reason, Some(DmlReason::DangerousFunction));
    }

    #[test]
    fn dangerous_function_lo_export() {
        let c = pg("SELECT lo_export(12345, '/tmp/secret')").unwrap();
        assert_eq!(c.operation, Operation::ExecuteDml);
        assert_eq!(c.dml_reason, Some(DmlReason::DangerousFunction));
    }

    #[test]
    fn dangerous_function_set_config() {
        let c = pg("SELECT set_config('role', 'admin', false)").unwrap();
        assert_eq!(c.operation, Operation::ExecuteDml);
        assert_eq!(c.dml_reason, Some(DmlReason::DangerousFunction));
    }

    #[test]
    fn dangerous_function_pg_sleep() {
        let c = pg("SELECT pg_sleep(999)").unwrap();
        assert_eq!(c.operation, Operation::ExecuteDml);
        assert_eq!(c.dml_reason, Some(DmlReason::DangerousFunction));
    }

    #[test]
    fn safe_function_not_flagged() {
        let c = pg("SELECT count(*), now() FROM users").unwrap();
        assert_eq!(c.operation, Operation::ExecuteSelect);
    }

    #[test]
    fn safe_set_timeout() {
        let c = pg("SET statement_timeout = '5s'").unwrap();
        assert_eq!(c.operation, Operation::ExecuteSelect);
    }

    #[test]
    fn set_role_rejected() {
        assert!(matches!(pg("SET ROLE admin"), Err(ClassifyError::Rejected { .. })));
    }

    #[test]
    fn set_search_path_rejected() {
        assert!(matches!(
            pg("SET search_path TO evil_schema, public"),
            Err(ClassifyError::Rejected { .. })
        ));
    }

    // === Fail-closed: parse failure → DML ===

    #[test]
    fn parse_failure_is_dml() {
        let c = pg("THIS IS NOT VALID SQL AT ALL @#$%").unwrap();
        assert_eq!(c.operation, Operation::ExecuteDml);
        assert_eq!(c.dml_reason, Some(DmlReason::ParseFailure));
    }

    // === Unknown statement → DML ===

    // === Edge cases ===

    #[test]
    fn empty_query_rejected() {
        assert_eq!(pg(""), Err(ClassifyError::Empty));
    }

    #[test]
    fn whitespace_only_rejected() {
        assert_eq!(pg("   \n\t  "), Err(ClassifyError::Empty));
    }

    #[test]
    fn null_byte_rejected() {
        assert!(matches!(
            pg("SELECT \0"),
            Err(ClassifyError::Rejected { .. })
        ));
    }

    #[test]
    fn trailing_semicolon() {
        let c = pg("SELECT 1;").unwrap();
        assert_eq!(c.operation, Operation::ExecuteSelect);
    }

    #[test]
    fn multi_statement_escalates() {
        let c = pg("SELECT 1; INSERT INTO t VALUES (1)").unwrap();
        assert_eq!(c.operation, Operation::ExecuteDml);
        assert_eq!(c.statement_count, 2);
    }

    #[test]
    fn multi_statement_with_ddl_rejected() {
        let r = pg("INSERT INTO t VALUES (1); DROP TABLE t");
        assert!(matches!(r, Err(ClassifyError::Rejected { .. })));
    }

    // === Limits ===

    #[test]
    fn max_sql_bytes_rejected() {
        let huge = "S".repeat(MAX_SQL_BYTES + 1);
        let r = pg(&huge);
        assert!(matches!(r, Err(ClassifyError::Rejected { .. })));
    }

    #[test]
    fn max_statements_rejected() {
        let sql = std::iter::repeat_n("SELECT 1", MAX_STATEMENTS + 1)
            .collect::<Vec<_>>()
            .join("; ");
        let r = pg(&sql);
        assert!(matches!(r, Err(ClassifyError::Rejected { .. })));
    }

    // === Dialect: MySQL ===

    #[test]
    fn mysql_insert() {
        let c = mysql("INSERT INTO t VALUES (1)").unwrap();
        assert_eq!(c.operation, Operation::ExecuteDml);
    }

    #[test]
    fn mysql_select() {
        let c = mysql("SELECT * FROM users").unwrap();
        assert_eq!(c.operation, Operation::ExecuteSelect);
    }

    // === statement_count ===

    #[test]
    fn statement_count_single() {
        let c = pg("SELECT 1").unwrap();
        assert_eq!(c.statement_count, 1);
    }

    #[test]
    fn statement_count_multi() {
        let c = pg("SELECT 1; SELECT 2; SELECT 3").unwrap();
        assert_eq!(c.statement_count, 3);
        assert_eq!(c.statements.len(), 3);
    }

    // === Fix 1: LOAD DATA rejected ===

    #[test]
    fn load_data_rejected() {
        let err = mysql("LOAD DATA INFILE '/tmp/data.csv' INTO TABLE t").unwrap_err();
        assert!(matches!(err, ClassifyError::Rejected { .. }));
    }

    // === Fix 2: No false positives from string matching ===

    #[test]
    fn false_positive_table_named_sleep() {
        let c = pg("SELECT * FROM sleep_log").unwrap();
        assert_eq!(c.operation, Operation::ExecuteSelect);
    }

    #[test]
    fn false_positive_string_literal_dblink() {
        let c = pg("SELECT 'dblink' AS name").unwrap();
        assert_eq!(c.operation, Operation::ExecuteSelect);
    }

    #[test]
    fn dangerous_function_in_subquery() {
        let c = pg("SELECT * FROM (SELECT pg_sleep(10)) t").unwrap();
        assert_eq!(c.operation, Operation::ExecuteDml);
        assert_eq!(c.dml_reason, Some(DmlReason::DangerousFunction));
    }
}
