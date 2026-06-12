use crate::services::classification::{
    Classification, ClassifyError, Dialect, DmlReason, StatementCategory,
};
use sqlparser::ast::*;

/// Check if a DDL statement is considered "safe" for auto-approve.
pub fn is_safe_ddl_statement(stmt: &Statement, dialect: Option<Dialect>) -> bool {
    match stmt {
        Statement::CreateTable(ct) => !ct.or_replace && ct.query.is_none(),
        Statement::CreateIndex(ci) => {
            matches!(dialect, Some(Dialect::PostgreSql)) && ci.concurrently
        }
        Statement::CreateView(cv) => !cv.or_replace,
        Statement::AlterTable(at) => {
            matches!(dialect, Some(Dialect::PostgreSql))
                && at
                    .operations
                    .iter()
                    .all(|op| matches!(op, AlterTableOperation::AddColumn { .. }))
        }
        _ => false,
    }
}
use crate::services::sql_parser::{self, ParseError};
use crate::values::Operation;
use sqlparser::ast::{Set, SetExpr, Statement};

/// Classify SQL using pre-parsed statements.
pub fn classify_statements(statements: &[Statement]) -> Result<Classification, ClassifyError> {
    let stmt_strings: Vec<String> = statements.iter().map(|s| s.to_string()).collect();

    let mut worst = InternalClass::Select;
    for stmt in statements {
        let c = classify_statement(stmt);
        worst = worst.escalate(c);
    }

    // For multi-statement ExecuteSelect, enforce exactly one result-producing
    if matches!(worst, InternalClass::Select) && statements.len() > 1 {
        let mut found_result_producing = false;
        for stmt in statements {
            if is_result_producing(stmt) {
                if found_result_producing {
                    return Err(ClassifyError::Rejected {
                        reason: "multi-statement queries with multiple result sets are not \
                                 supported; submit each query separately"
                            .into(),
                    });
                }
                found_result_producing = true;
            } else if found_result_producing {
                return Err(ClassifyError::Rejected {
                    reason: "in a multi-statement batch, only SET statements are allowed \
                             before the query; no statements may follow it"
                        .into(),
                });
            }
        }
    }

    match worst {
        InternalClass::Select => Ok(Classification {
            operation: Operation::ExecuteSelect,
            dml_reason: None,
            statement_count: stmt_strings.len(),
            statements: stmt_strings,
            is_ddl_only: false,
        }),
        InternalClass::Dml(reason) => {
            let is_ddl_only = matches!(reason, DmlReason::Ddl);
            Ok(Classification {
                operation: Operation::ExecuteDml,
                dml_reason: Some(reason),
                statement_count: stmt_strings.len(),
                statements: stmt_strings,
                is_ddl_only,
            })
        }
        InternalClass::Rejected(reason) => Err(ClassifyError::Rejected { reason }),
    }
}

pub fn classify(sql: &str, dialect: Dialect) -> Result<Classification, ClassifyError> {
    match sql_parser::parse_statements(sql, dialect) {
        Ok(statements) => classify_statements(&statements),
        Err(ParseError::Empty) => Err(ClassifyError::Empty),
        Err(ParseError::NullBytes) => Err(ClassifyError::Rejected {
            reason: "query contains null bytes".into(),
        }),
        Err(ParseError::TooLarge) => Err(ClassifyError::Rejected {
            reason: format!("query exceeds maximum size of {} bytes", 1_048_576),
        }),
        Err(ParseError::TooManyStatements) => Err(ClassifyError::Rejected {
            reason: format!("query exceeds maximum of {} statements", 100),
        }),
        Err(ParseError::Rejected { reason }) => Err(ClassifyError::Rejected { reason }),
        Err(ParseError::ParseFailed) => {
            let trimmed = sql.trim();
            Ok(Classification {
                operation: Operation::ExecuteDml,
                dml_reason: Some(DmlReason::ParseFailure),
                statement_count: 1,
                statements: vec![trimmed.to_string()],
                is_ddl_only: false,
            })
        }
    }
}

/// Extended classification result that includes parsed AST.
pub struct ClassifyResult {
    pub classification: Result<Classification, ClassifyError>,
    /// Parsed statements — None only when parser itself failed.
    pub parsed_statements: Option<Vec<Statement>>,
}

/// Classify SQL and return parsed statements alongside the result.
/// Eliminates the need for re-parsing in bypass paths.
pub fn classify_full(sql: &str, dialect: Dialect) -> ClassifyResult {
    match sql_parser::parse_statements(sql, dialect) {
        Ok(statements) => {
            let classification = classify_statements(&statements);
            ClassifyResult {
                classification,
                parsed_statements: Some(statements),
            }
        }
        Err(ParseError::Empty) => ClassifyResult {
            classification: Err(ClassifyError::Empty),
            parsed_statements: None,
        },
        Err(ParseError::ParseFailed) => ClassifyResult {
            classification: Ok(Classification {
                operation: Operation::ExecuteDml,
                dml_reason: Some(DmlReason::ParseFailure),
                statement_count: 1,
                statements: vec![sql.trim().to_string()],
                is_ddl_only: false,
            }),
            parsed_statements: None,
        },
        Err(ParseError::NullBytes) => ClassifyResult {
            classification: Err(ClassifyError::Rejected {
                reason: "query contains null bytes".into(),
            }),
            parsed_statements: None,
        },
        Err(ParseError::TooLarge) => ClassifyResult {
            classification: Err(ClassifyError::Rejected {
                reason: format!("query exceeds maximum size of {} bytes", 1_048_576),
            }),
            parsed_statements: None,
        },
        Err(ParseError::TooManyStatements) => ClassifyResult {
            classification: Err(ClassifyError::Rejected {
                reason: format!("query exceeds maximum of {} statements", 100),
            }),
            parsed_statements: None,
        },
        Err(ParseError::Rejected { reason }) => ClassifyResult {
            classification: Err(ClassifyError::Rejected { reason }),
            parsed_statements: None,
        },
    }
}

/// Categorize a statement for break-glass bypass decisions.
pub fn categorize_statement(stmt: &Statement) -> StatementCategory {
    match stmt {
        Statement::Query(_)
        | Statement::ExplainTable { .. }
        | Statement::ShowVariable { .. }
        | Statement::ShowTables { .. }
        | Statement::ShowColumns { .. }
        | Statement::ShowCreate { .. }
        | Statement::ShowDatabases { .. }
        | Statement::ShowSchemas { .. }
        | Statement::ShowViews { .. }
        | Statement::ShowCollation { .. }
        | Statement::ShowStatus { .. }
        | Statement::ShowVariables { .. }
        | Statement::ShowFunctions { .. } => StatementCategory::ReadOnly,

        Statement::Explain { analyze: false, .. } => StatementCategory::ReadOnly,
        Statement::Explain {
            analyze: true,
            statement,
            ..
        } => categorize_statement(statement),

        Statement::Insert(_)
        | Statement::Update(_)
        | Statement::Delete(_)
        | Statement::Merge(_)
        | Statement::Copy { .. }
        | Statement::Call(_)
        | Statement::Execute { .. }
        | Statement::NOTIFY { .. }
        | Statement::LISTEN { .. } => StatementCategory::Dml,

        Statement::CreateTable(_)
        | Statement::CreateView(_)
        | Statement::CreateIndex(_)
        | Statement::AlterTable(_) => StatementCategory::SafeDdl,

        Statement::Drop { object_type, .. } => match object_type {
            ObjectType::Table | ObjectType::View | ObjectType::Index | ObjectType::Sequence => {
                StatementCategory::BreakGlassDdl
            }
            _ => StatementCategory::PrivilegeDdl,
        },
        Statement::CreateSequence { .. } => StatementCategory::BreakGlassDdl,
        Statement::Truncate(_) => StatementCategory::BreakGlassDdl,

        Statement::Grant(_)
        | Statement::Revoke(_)
        | Statement::CreateRole(_)
        | Statement::AlterRole { .. }
        | Statement::CreateSchema { .. }
        | Statement::AlterSchema(_)
        | Statement::CreateDatabase { .. }
        | Statement::AlterIndex { .. }
        | Statement::AlterView { .. }
        | Statement::CreateType { .. } => StatementCategory::PrivilegeDdl,

        Statement::CreateFunction(_)
        | Statement::CreateProcedure { .. }
        | Statement::LoadData { .. } => StatementCategory::CodeExecution,

        Statement::StartTransaction { .. }
        | Statement::Commit { .. }
        | Statement::Rollback { .. }
        | Statement::Savepoint { .. } => StatementCategory::TxControl,

        Statement::LockTables { .. } => StatementCategory::SecurityBoundary,

        Statement::Set(set) => categorize_set(set),

        _ => StatementCategory::Unknown,
    }
}

fn categorize_set(set: &Set) -> StatementCategory {
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
                StatementCategory::ReadOnly
            } else {
                StatementCategory::SecurityBoundary
            }
        }
        Set::SetRole { .. } | Set::SetSessionAuthorization(_) | Set::SetTransaction { .. } => {
            StatementCategory::SecurityBoundary
        }
        Set::SetTimeZone { .. } | Set::SetNames { .. } | Set::SetNamesDefault { .. } => {
            StatementCategory::ReadOnly
        }
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
                    return StatementCategory::SecurityBoundary;
                }
            }
            StatementCategory::ReadOnly
        }
        _ => StatementCategory::SecurityBoundary,
    }
}

/// Dangerous functions that can cause side effects when called inside SELECT.
const DANGEROUS_FUNCTIONS: &[&str] = &[
    "dblink",
    "dblink_exec",
    "dblink_connect",
    "lo_export",
    "lo_import",
    "lo_unlink",
    // PG Large Object mutators (SAFE-1: would bypass read-only tx)
    "lo_create",
    "lo_creat",
    "lo_from_bytea",
    "lo_put",
    "lo_truncate",
    "lo_truncate64",
    "lowrite",
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
    // PG sequence mutators (SAFE-1: side effects in read-only context)
    "nextval",
    "setval",
    "sys_exec",
    "sys_eval",
    "load_file",
    "sleep",
    "benchmark",
    // MySQL advisory locks
    "get_lock",
    "release_lock",
    "release_all_locks",
    "is_free_lock",
    "is_used_lock",
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
            (InternalClass::Dml(_), InternalClass::Dml(DmlReason::Ddl)) => self, // DML wins over DDL
            (InternalClass::Dml(DmlReason::Ddl), InternalClass::Dml(_)) => other,
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

        // === DDL (safe candidates — reviewed by sql_reviewer) ===
        Statement::CreateTable(_)
        | Statement::CreateView(_)
        | Statement::CreateIndex(_)
        | Statement::AlterTable(_) => InternalClass::Dml(DmlReason::Ddl),

        // === Rejected (DDL — infrastructure/permission/code execution) ===
        Statement::CreateSchema { .. }
        | Statement::CreateDatabase { .. }
        | Statement::CreateFunction(_)
        | Statement::CreateProcedure { .. }
        | Statement::CreateSequence { .. }
        | Statement::CreateType { .. }
        | Statement::CreateRole(_)
        | Statement::AlterIndex { .. }
        | Statement::AlterView { .. }
        | Statement::AlterRole { .. }
        | Statement::AlterSchema(_)
        | Statement::Drop { .. }
        | Statement::Grant(_)
        | Statement::Revoke(_) => InternalClass::Rejected(
            "DDL statements (DROP, GRANT, REVOKE, CREATE ROLE/FUNCTION/DATABASE) are not allowed. \
             Use 'dbward migrate create <name>' to generate a migration file, then 'dbward migrate up'."
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
    if let SetExpr::Select(select) = query.body.as_ref()
        && select.into.is_some()
    {
        result = result.escalate(InternalClass::Dml(DmlReason::SemanticEscalation));
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

    // Layer 2: FOR UPDATE/SHARE/NO KEY UPDATE/KEY SHARE → explicit row locking (recursive)
    if query_has_lock_clause(query) {
        result = result.escalate(InternalClass::Dml(DmlReason::SemanticEscalation));
    }

    result
}

fn query_has_lock_clause(query: &sqlparser::ast::Query) -> bool {
    use sqlparser::ast::{Query, Visit, Visitor};
    use std::ops::ControlFlow;

    struct LockVisitor {
        found: bool,
    }

    impl Visitor for LockVisitor {
        type Break = ();

        fn pre_visit_query(&mut self, q: &Query) -> ControlFlow<()> {
            if !q.locks.is_empty() {
                self.found = true;
                return ControlFlow::Break(());
            }
            ControlFlow::Continue(())
        }
    }

    let mut visitor = LockVisitor { found: false };
    let _ = query.visit(&mut visitor);
    visitor.found
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

/// Whether a statement produces a result set (rows) when executed.
/// Distinct from safety classification: SET is "Select" class but not result-producing.
fn is_result_producing(stmt: &Statement) -> bool {
    matches!(
        stmt,
        Statement::Query(_)
            | Statement::ShowVariable { .. }
            | Statement::ShowTables { .. }
            | Statement::ShowColumns { .. }
            | Statement::ShowCreate { .. }
            | Statement::ShowDatabases { .. }
            | Statement::ShowSchemas { .. }
            | Statement::ShowViews { .. }
            | Statement::ShowCollation { .. }
            | Statement::ShowStatus { .. }
            | Statement::ShowVariables { .. }
            | Statement::ShowFunctions { .. }
            | Statement::ExplainTable { .. }
            | Statement::Explain { .. }
    )
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

/// Replace string literals with `?` for audit safety.
pub fn redact_literals(sql: &str) -> String {
    let mut result = String::with_capacity(sql.len());
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\'' {
            result.push('?');
            while let Some(nc) = chars.next() {
                if nc == '\'' {
                    if chars.peek() == Some(&'\'') {
                        chars.next();
                    } else {
                        break;
                    }
                }
            }
        } else {
            result.push(c);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::sql_parser::{MAX_SQL_BYTES, MAX_STATEMENTS};

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
        let c = pg("CREATE TABLE t (id int)").unwrap();
        assert_eq!(c.operation, Operation::ExecuteDml);
        assert!(c.is_ddl_only);
    }

    #[test]
    fn rejects_alter_table() {
        let c = pg("ALTER TABLE t ADD COLUMN x int").unwrap();
        assert_eq!(c.operation, Operation::ExecuteDml);
        assert!(c.is_ddl_only);
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
        assert!(matches!(
            pg("SET ROLE admin"),
            Err(ClassifyError::Rejected { .. })
        ));
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

    #[test]
    fn mysql_replace_into_is_dml() {
        let c = mysql("REPLACE INTO t (a) VALUES (1)").unwrap();
        assert_eq!(c.operation, Operation::ExecuteDml);
    }

    // === DO statements rejected ===

    #[test]
    fn do_block_pg_rejected() {
        let err = pg("DO $$ BEGIN DELETE FROM t; END $$").unwrap_err();
        assert!(matches!(err, ClassifyError::Rejected { .. }));
    }

    #[test]
    fn do_mysql_rejected() {
        let err = mysql("DO SLEEP(1)").unwrap_err();
        assert!(matches!(err, ClassifyError::Rejected { .. }));
    }

    #[test]
    fn do_with_comment_rejected() {
        let err = pg("-- comment\nDO $$ BEGIN END $$").unwrap_err();
        assert!(matches!(err, ClassifyError::Rejected { .. }));
    }

    #[test]
    fn do_with_block_comment_rejected() {
        let err = pg("/* comment */ DO $$ BEGIN END $$").unwrap_err();
        assert!(matches!(err, ClassifyError::Rejected { .. }));
    }

    #[test]
    fn do_in_multi_statement_rejected() {
        let err = pg("SELECT 1; DO $$ BEGIN DELETE FROM t; END $$").unwrap_err();
        assert!(matches!(err, ClassifyError::Rejected { .. }));
    }

    #[test]
    fn do_in_multi_statement_with_comment_rejected() {
        let err = pg("SELECT 1; -- comment\nDO $$ BEGIN END $$").unwrap_err();
        assert!(matches!(err, ClassifyError::Rejected { .. }));
    }

    #[test]
    fn do_with_hash_comment_rejected() {
        let err = mysql("# comment\nDO SLEEP(1)").unwrap_err();
        assert!(matches!(err, ClassifyError::Rejected { .. }));
    }

    // === statement_count ===

    #[test]
    fn statement_count_single() {
        let c = pg("SELECT 1").unwrap();
        assert_eq!(c.statement_count, 1);
    }

    #[test]
    fn statement_count_multi() {
        // Multi-statement pure-SELECT is now rejected
        let r = pg("SELECT 1; SELECT 2; SELECT 3");
        assert!(matches!(r, Err(ClassifyError::Rejected { .. })));
    }

    // === Multi-statement result-producing enforcement ===

    #[test]
    fn multi_select_rejected() {
        let r = pg("SELECT 1; SELECT 2");
        assert!(matches!(r, Err(ClassifyError::Rejected { .. })));
    }

    #[test]
    fn set_then_select_allowed() {
        let c = pg("SET statement_timeout = 5000; SELECT 1 AS val").unwrap();
        assert_eq!(c.operation, Operation::ExecuteSelect);
        assert_eq!(c.statement_count, 2);
    }

    #[test]
    fn multiple_set_then_select_allowed() {
        let c = pg("SET statement_timeout = 5000; SET timezone = 'UTC'; SELECT 1").unwrap();
        assert_eq!(c.operation, Operation::ExecuteSelect);
        assert_eq!(c.statement_count, 3);
    }

    #[test]
    fn show_then_select_rejected() {
        let r = pg("SHOW server_version; SELECT 1");
        assert!(matches!(r, Err(ClassifyError::Rejected { .. })));
    }

    #[test]
    fn select_then_set_rejected() {
        let r = pg("SELECT 1; SET statement_timeout = 5000");
        assert!(matches!(r, Err(ClassifyError::Rejected { .. })));
    }

    #[test]
    fn explain_then_select_rejected() {
        let r = pg("EXPLAIN SELECT 1; SELECT 2");
        assert!(matches!(r, Err(ClassifyError::Rejected { .. })));
    }

    #[test]
    fn set_then_show_allowed() {
        let c = mysql("SET sql_mode = 'STRICT_TRANS_TABLES'; SHOW TABLES").unwrap();
        assert_eq!(c.operation, Operation::ExecuteSelect);
        assert_eq!(c.statement_count, 2);
    }

    #[test]
    fn multi_set_without_query_allowed() {
        let c = pg("SET statement_timeout = 5000; SET timezone = 'UTC'").unwrap();
        assert_eq!(c.operation, Operation::ExecuteSelect);
        assert_eq!(c.statement_count, 2);
    }

    #[test]
    fn set_timezone_then_select_allowed() {
        let c = pg("SET TIME ZONE 'America/New_York'; SELECT now()").unwrap();
        assert_eq!(c.operation, Operation::ExecuteSelect);
        assert_eq!(c.statement_count, 2);
    }

    #[test]
    fn set_names_then_select_allowed() {
        let c = mysql("SET NAMES utf8mb4; SELECT 1").unwrap();
        assert_eq!(c.operation, Operation::ExecuteSelect);
        assert_eq!(c.statement_count, 2);
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

    #[test]
    fn is_safe_ddl_create_table() {
        let stmts = sql_parser::parse_statements(
            "CREATE TABLE t (id INT PRIMARY KEY)",
            Dialect::PostgreSql,
        )
        .unwrap();
        assert!(is_safe_ddl_statement(&stmts[0], Some(Dialect::PostgreSql)));
    }

    #[test]
    fn is_safe_ddl_create_table_or_replace_not_safe() {
        let stmts =
            sql_parser::parse_statements("CREATE OR REPLACE TABLE t (id INT)", Dialect::PostgreSql);
        // May not parse on PG; if it does, it should not be safe
        if let Ok(stmts) = stmts {
            assert!(!is_safe_ddl_statement(&stmts[0], Some(Dialect::PostgreSql)));
        }
    }

    #[test]
    fn is_safe_ddl_create_index_concurrently() {
        let stmts = sql_parser::parse_statements(
            "CREATE INDEX CONCURRENTLY idx ON t(col)",
            Dialect::PostgreSql,
        )
        .unwrap();
        assert!(is_safe_ddl_statement(&stmts[0], Some(Dialect::PostgreSql)));
    }

    #[test]
    fn is_safe_ddl_create_index_without_concurrently_not_safe() {
        let stmts = sql_parser::parse_statements("CREATE INDEX idx ON t(col)", Dialect::PostgreSql)
            .unwrap();
        assert!(!is_safe_ddl_statement(&stmts[0], Some(Dialect::PostgreSql)));
    }

    #[test]
    fn is_safe_ddl_mysql_create_index_not_safe() {
        let stmts =
            sql_parser::parse_statements("CREATE INDEX idx ON t(col)", Dialect::MySql).unwrap();
        assert!(!is_safe_ddl_statement(&stmts[0], Some(Dialect::MySql)));
    }

    #[test]
    fn is_safe_ddl_alter_table_add_column_pg() {
        let stmts =
            sql_parser::parse_statements("ALTER TABLE t ADD COLUMN name TEXT", Dialect::PostgreSql)
                .unwrap();
        assert!(is_safe_ddl_statement(&stmts[0], Some(Dialect::PostgreSql)));
    }

    #[test]
    fn is_safe_ddl_drop_table_not_safe() {
        let stmts = sql_parser::parse_statements("DROP TABLE t", Dialect::PostgreSql);
        // DROP is rejected by classifier, but if it reaches here
        if let Ok(stmts) = stmts {
            assert!(!is_safe_ddl_statement(&stmts[0], Some(Dialect::PostgreSql)));
        }
    }

    // SAFE-1: dangerous function additions
    #[test]
    fn nextval_classified_as_dml() {
        let r = pg("SELECT nextval('my_seq')").unwrap();
        assert_eq!(r.operation, Operation::ExecuteDml);
        assert_eq!(r.dml_reason, Some(DmlReason::DangerousFunction));
    }

    #[test]
    fn setval_classified_as_dml() {
        let r = pg("SELECT setval('my_seq', 100)").unwrap();
        assert_eq!(r.operation, Operation::ExecuteDml);
        assert_eq!(r.dml_reason, Some(DmlReason::DangerousFunction));
    }

    #[test]
    fn mysql_get_lock_classified_as_dml() {
        let r = mysql("SELECT GET_LOCK('mylock', 10)").unwrap();
        assert_eq!(r.operation, Operation::ExecuteDml);
        assert_eq!(r.dml_reason, Some(DmlReason::DangerousFunction));
    }

    #[test]
    fn lo_create_classified_as_dml() {
        let r = pg("SELECT lo_create(0)").unwrap();
        assert_eq!(r.operation, Operation::ExecuteDml);
        assert_eq!(r.dml_reason, Some(DmlReason::DangerousFunction));
    }

    // SAFE-1: FOR UPDATE/SHARE detection
    #[test]
    fn for_update_classified_as_dml() {
        let r = pg("SELECT * FROM users FOR UPDATE").unwrap();
        assert_eq!(r.operation, Operation::ExecuteDml);
        assert_eq!(r.dml_reason, Some(DmlReason::SemanticEscalation));
    }

    #[test]
    fn for_share_classified_as_dml() {
        let r = pg("SELECT * FROM users FOR SHARE").unwrap();
        assert_eq!(r.operation, Operation::ExecuteDml);
        assert_eq!(r.dml_reason, Some(DmlReason::SemanticEscalation));
    }

    #[test]
    fn for_no_key_update_classified_as_dml() {
        // sqlparser 0.61 cannot parse FOR NO KEY UPDATE → ParseFailure → ExecuteDml
        let r = pg("SELECT * FROM users FOR NO KEY UPDATE").unwrap();
        assert_eq!(r.operation, Operation::ExecuteDml);
    }

    #[test]
    fn for_key_share_classified_as_dml() {
        // sqlparser 0.61 cannot parse FOR KEY SHARE → ParseFailure → ExecuteDml
        let r = pg("SELECT * FROM users FOR KEY SHARE").unwrap();
        assert_eq!(r.operation, Operation::ExecuteDml);
    }

    #[test]
    fn subquery_for_update_classified_as_dml() {
        let r = pg("SELECT * FROM (SELECT id FROM users FOR UPDATE) sub").unwrap();
        assert_eq!(r.operation, Operation::ExecuteDml);
    }

    #[test]
    fn currval_remains_execute_select() {
        let r = pg("SELECT currval('my_seq')").unwrap();
        assert_eq!(r.operation, Operation::ExecuteSelect);
    }

    #[test]
    fn lastval_remains_execute_select() {
        let r = pg("SELECT lastval()").unwrap();
        assert_eq!(r.operation, Operation::ExecuteSelect);
    }

    #[test]
    fn release_lock_classified_as_dml() {
        let r = mysql("SELECT RELEASE_LOCK('x')").unwrap();
        assert_eq!(r.operation, Operation::ExecuteDml);
        assert_eq!(r.dml_reason, Some(DmlReason::DangerousFunction));
    }

    #[test]
    fn is_free_lock_classified_as_dml() {
        let r = mysql("SELECT IS_FREE_LOCK('x')").unwrap();
        assert_eq!(r.operation, Operation::ExecuteDml);
        assert_eq!(r.dml_reason, Some(DmlReason::DangerousFunction));
    }

    #[test]
    fn lo_put_classified_as_dml() {
        let r = pg("SELECT lo_put(1, 0, '\\x00')").unwrap();
        assert_eq!(r.operation, Operation::ExecuteDml);
        assert_eq!(r.dml_reason, Some(DmlReason::DangerousFunction));
    }

    #[test]
    fn lowrite_classified_as_dml() {
        let r = pg("SELECT lowrite(1, '\\x00')").unwrap();
        assert_eq!(r.operation, Operation::ExecuteDml);
        assert_eq!(r.dml_reason, Some(DmlReason::DangerousFunction));
    }

    #[test]
    fn for_update_in_cte_classified_as_dml() {
        let r =
            pg("WITH locked AS (SELECT id FROM users FOR UPDATE) SELECT * FROM locked").unwrap();
        assert_eq!(r.operation, Operation::ExecuteDml);
    }

    #[test]
    fn classification_statements_are_canonical() {
        let r = pg("select  id ,  name   from  users  where  active = true").unwrap();
        assert_eq!(r.statement_count, 1);
        assert!(r.statements[0].contains("SELECT"));
    }

    #[test]
    fn redact_literals_replaces_strings() {
        assert_eq!(
            redact_literals("SELECT * FROM users WHERE name = 'alice'"),
            "SELECT * FROM users WHERE name = ?"
        );
    }

    #[test]
    fn redact_literals_handles_escaped_quotes() {
        assert_eq!(redact_literals("SELECT 'it''s fine'"), "SELECT ?");
    }

    #[test]
    fn redact_literals_no_strings() {
        assert_eq!(redact_literals("SELECT 1"), "SELECT 1");
    }
}
