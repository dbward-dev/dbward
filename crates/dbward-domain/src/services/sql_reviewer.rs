use crate::services::classification::Dialect;
use crate::services::sql_parser;
use sqlparser::ast::*;
use std::ops::ControlFlow;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    Block,
    Warn,
    Off,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleId {
    NoWhereDelete,
    NoWhereUpdate,
    DropTable,
    DropColumn,
    NotNullWithoutDefault,
    CreateIndexNotConcurrently,
    AlterColumnType,
    Truncate,
    MixedDdlDml,
    LargeInList,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub rule: RuleId,
    pub action: RuleAction,
    pub message: String,
    pub statement_index: usize,
}

#[derive(Debug, Clone)]
pub struct ReviewResult {
    pub findings: Vec<Finding>,
    pub blocked: bool,
}

#[derive(Debug, Clone)]
pub struct ReviewRules {
    pub no_where_delete: RuleAction,
    pub no_where_update: RuleAction,
    pub drop_table: RuleAction,
    pub drop_column: RuleAction,
    pub not_null_without_default: RuleAction,
    pub create_index_not_concurrently: RuleAction,
    pub alter_column_type: RuleAction,
    pub truncate: RuleAction,
    pub mixed_ddl_dml: RuleAction,
    pub large_in_list: RuleAction,
}

impl Default for ReviewRules {
    fn default() -> Self {
        Self {
            no_where_delete: RuleAction::Warn,
            no_where_update: RuleAction::Warn,
            drop_table: RuleAction::Warn,
            drop_column: RuleAction::Warn,
            not_null_without_default: RuleAction::Warn,
            create_index_not_concurrently: RuleAction::Warn,
            alter_column_type: RuleAction::Warn,
            truncate: RuleAction::Warn,
            mixed_ddl_dml: RuleAction::Warn,
            large_in_list: RuleAction::Warn,
        }
    }
}

/// Review SQL statements for safety issues.
pub fn review(sql: &str, dialect: Option<Dialect>, rules: &ReviewRules) -> ReviewResult {
    let d = dialect.unwrap_or(Dialect::PostgreSql);
    match sql_parser::parse_statements(sql, d) {
        Ok(statements) => review_statements(&statements, dialect, rules),
        Err(_) => {
            // Parse failure → cannot review. Return empty (classifier handles rejection).
            ReviewResult {
                findings: vec![],
                blocked: false,
            }
        }
    }
}

/// Review pre-parsed statements.
pub fn review_statements(
    statements: &[Statement],
    dialect: Option<Dialect>,
    rules: &ReviewRules,
) -> ReviewResult {
    let mut findings = Vec::new();
    let mut has_ddl = false;
    let mut has_dml = false;

    for (idx, stmt) in statements.iter().enumerate() {
        check_no_where_delete(stmt, idx, rules.no_where_delete, &mut findings);
        check_no_where_update(stmt, idx, rules.no_where_update, &mut findings);
        check_drop_table(stmt, idx, rules.drop_table, &mut findings);
        check_drop_column(stmt, idx, rules.drop_column, &mut findings);
        check_not_null_without_default(stmt, idx, rules.not_null_without_default, &mut findings);
        if dialect == Some(Dialect::PostgreSql) {
            check_create_index_not_concurrently(
                stmt,
                idx,
                rules.create_index_not_concurrently,
                &mut findings,
            );
        }
        check_alter_column_type(stmt, idx, rules.alter_column_type, &mut findings);
        check_truncate(stmt, idx, rules.truncate, &mut findings);
        check_large_in_list(stmt, idx, rules.large_in_list, &mut findings);

        if is_ddl(stmt) {
            has_ddl = true;
        }
        if is_dml(stmt) {
            has_dml = true;
        }
    }

    if has_ddl && has_dml && rules.mixed_ddl_dml != RuleAction::Off {
        findings.push(Finding {
            rule: RuleId::MixedDdlDml,
            action: rules.mixed_ddl_dml,
            message: "DDL and DML mixed in same batch".into(),
            statement_index: 0,
        });
    }

    let blocked = findings.iter().any(|f| f.action == RuleAction::Block);
    ReviewResult { findings, blocked }
}

fn check_no_where_delete(
    stmt: &Statement,
    idx: usize,
    action: RuleAction,
    findings: &mut Vec<Finding>,
) {
    if action == RuleAction::Off {
        return;
    }
    if let Statement::Delete(del) = stmt {
        if del.selection.is_none() {
            findings.push(Finding {
                rule: RuleId::NoWhereDelete,
                action,
                message: "DELETE without WHERE clause".into(),
                statement_index: idx,
            });
        }
    }
}

fn check_no_where_update(
    stmt: &Statement,
    idx: usize,
    action: RuleAction,
    findings: &mut Vec<Finding>,
) {
    if action == RuleAction::Off {
        return;
    }
    if let Statement::Update(upd) = stmt {
        if upd.selection.is_none() {
            findings.push(Finding {
                rule: RuleId::NoWhereUpdate,
                action,
                message: "UPDATE without WHERE clause".into(),
                statement_index: idx,
            });
        }
    }
}

fn check_drop_table(stmt: &Statement, idx: usize, action: RuleAction, findings: &mut Vec<Finding>) {
    if action == RuleAction::Off {
        return;
    }
    if let Statement::Drop { object_type, .. } = stmt {
        if *object_type == ObjectType::Table {
            findings.push(Finding {
                rule: RuleId::DropTable,
                action,
                message: "DROP TABLE detected".into(),
                statement_index: idx,
            });
        }
    }
}

fn check_drop_column(
    stmt: &Statement,
    idx: usize,
    action: RuleAction,
    findings: &mut Vec<Finding>,
) {
    if action == RuleAction::Off {
        return;
    }
    if let Statement::AlterTable(alter) = stmt {
        for op in &alter.operations {
            if matches!(op, AlterTableOperation::DropColumn { .. }) {
                findings.push(Finding {
                    rule: RuleId::DropColumn,
                    action,
                    message: "DROP COLUMN detected".into(),
                    statement_index: idx,
                });
                return;
            }
        }
    }
}

fn check_not_null_without_default(
    stmt: &Statement,
    idx: usize,
    action: RuleAction,
    findings: &mut Vec<Finding>,
) {
    if action == RuleAction::Off {
        return;
    }
    if let Statement::AlterTable(alter) = stmt {
        for op in &alter.operations {
            if let AlterTableOperation::AddColumn { column_def, .. } = op {
                let has_not_null = column_def
                    .options
                    .iter()
                    .any(|o| matches!(o.option, ColumnOption::NotNull));
                let has_default = column_def
                    .options
                    .iter()
                    .any(|o| matches!(o.option, ColumnOption::Default(_)));
                if has_not_null && !has_default {
                    findings.push(Finding {
                        rule: RuleId::NotNullWithoutDefault,
                        action,
                        message: "ADD COLUMN NOT NULL without DEFAULT".into(),
                        statement_index: idx,
                    });
                    return;
                }
            }
        }
    }
}

fn check_create_index_not_concurrently(
    stmt: &Statement,
    idx: usize,
    action: RuleAction,
    findings: &mut Vec<Finding>,
) {
    if action == RuleAction::Off {
        return;
    }
    if let Statement::CreateIndex(ci) = stmt {
        if !ci.concurrently {
            findings.push(Finding {
                rule: RuleId::CreateIndexNotConcurrently,
                action,
                message: "CREATE INDEX without CONCURRENTLY".into(),
                statement_index: idx,
            });
        }
    }
}

fn check_alter_column_type(
    stmt: &Statement,
    idx: usize,
    action: RuleAction,
    findings: &mut Vec<Finding>,
) {
    if action == RuleAction::Off {
        return;
    }
    if let Statement::AlterTable(alter) = stmt {
        for op in &alter.operations {
            if matches!(
                op,
                AlterTableOperation::AlterColumn {
                    op: AlterColumnOperation::SetDataType { .. },
                    ..
                }
            ) {
                findings.push(Finding {
                    rule: RuleId::AlterColumnType,
                    action,
                    message: "ALTER COLUMN TYPE detected".into(),
                    statement_index: idx,
                });
                return;
            }
        }
    }
}

fn check_truncate(stmt: &Statement, idx: usize, action: RuleAction, findings: &mut Vec<Finding>) {
    if action == RuleAction::Off {
        return;
    }
    if matches!(stmt, Statement::Truncate(_)) {
        findings.push(Finding {
            rule: RuleId::Truncate,
            action,
            message: "TRUNCATE detected".into(),
            statement_index: idx,
        });
    }
}

fn check_large_in_list(
    stmt: &Statement,
    idx: usize,
    action: RuleAction,
    findings: &mut Vec<Finding>,
) {
    if action == RuleAction::Off {
        return;
    }
    let _ = visit_expressions(stmt, |expr| {
        if let Expr::InList { list, .. } = expr {
            if list.len() > 100 {
                findings.push(Finding {
                    rule: RuleId::LargeInList,
                    action,
                    message: format!("IN list with {} elements (>100)", list.len()),
                    statement_index: idx,
                });
            }
        }
        ControlFlow::<()>::Continue(())
    });
}

fn is_ddl(stmt: &Statement) -> bool {
    matches!(
        stmt,
        Statement::CreateTable(_)
            | Statement::CreateIndex(_)
            | Statement::AlterTable(_)
            | Statement::Drop { .. }
            | Statement::Truncate(_)
            | Statement::CreateView { .. }
    )
}

fn is_dml(stmt: &Statement) -> bool {
    matches!(
        stmt,
        Statement::Insert(_) | Statement::Update(_) | Statement::Delete(_)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn review_pg(sql: &str) -> ReviewResult {
        review(sql, Some(Dialect::PostgreSql), &ReviewRules::default())
    }

    fn review_mysql(sql: &str) -> ReviewResult {
        review(sql, Some(Dialect::MySql), &ReviewRules::default())
    }

    #[test]
    fn delete_without_where() {
        let r = review_pg("DELETE FROM users");
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].rule, RuleId::NoWhereDelete);
    }

    #[test]
    fn delete_with_where_passes() {
        let r = review_pg("DELETE FROM users WHERE id = 1");
        assert!(r.findings.is_empty());
    }

    #[test]
    fn update_without_where() {
        let r = review_pg("UPDATE users SET active = false");
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].rule, RuleId::NoWhereUpdate);
    }

    #[test]
    fn drop_table_detected() {
        let r = review_pg("DROP TABLE users");
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].rule, RuleId::DropTable);
    }

    #[test]
    fn truncate_detected() {
        let r = review_pg("TRUNCATE TABLE users");
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].rule, RuleId::Truncate);
    }

    #[test]
    fn create_index_not_concurrently_pg() {
        let r = review_pg("CREATE INDEX idx ON users(email)");
        assert!(r
            .findings
            .iter()
            .any(|f| f.rule == RuleId::CreateIndexNotConcurrently));
    }

    #[test]
    fn create_index_not_concurrently_skipped_for_mysql() {
        let r = review_mysql("CREATE INDEX idx ON users(email)");
        assert!(!r
            .findings
            .iter()
            .any(|f| f.rule == RuleId::CreateIndexNotConcurrently));
    }

    #[test]
    fn block_action_sets_blocked() {
        let rules = ReviewRules {
            no_where_delete: RuleAction::Block,
            ..Default::default()
        };
        let r = review("DELETE FROM users", Some(Dialect::PostgreSql), &rules);
        assert!(r.blocked);
    }

    #[test]
    fn off_suppresses_finding() {
        let rules = ReviewRules {
            no_where_delete: RuleAction::Off,
            ..Default::default()
        };
        let r = review("DELETE FROM users", Some(Dialect::PostgreSql), &rules);
        assert!(r.findings.is_empty());
    }

    #[test]
    fn select_produces_no_findings() {
        let r = review_pg("SELECT * FROM users WHERE id = 1");
        assert!(r.findings.is_empty());
    }
}
