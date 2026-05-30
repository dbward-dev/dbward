use crate::services::sql_reviewer::{Finding, RuleId};
use crate::values::Operation;

/// Risk levels ordered from lowest to highest. Unknown is intentionally last
/// so that `PartialOrd` derive treats it as the highest value (most restrictive).
/// DO NOT reorder variants without updating workflow_matcher's Unknown exclusion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
    Unknown,
}

#[derive(Debug, Clone)]
pub enum RiskFactor {
    ReadOnly,
    SafeDdl,
    CascadeDelete { targets: Vec<String> },
    LargeTable { rows: i64 },
    DropOperation,
    MultiStatement,
    ManyWarnings { count: usize },
    SchemaNotSynced,
}

#[derive(Debug, Clone)]
pub struct RiskAssessment {
    pub level: RiskLevel,
    pub factors: Vec<RiskFactor>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaStatus {
    Ready,
    Failed,
    NotSynced,
}

pub struct RiskInput<'a> {
    pub operation: Operation,
    pub findings: &'a [Finding],
    pub schema_status: SchemaStatus,
    pub tables: &'a [TableRiskInfo],
    pub statement_count: usize,
    pub has_dml: bool,
    pub allow_read_only: bool,
    pub safe_ddl: bool,
    pub max_estimated_rows: i64,
}

#[derive(Debug, Clone)]
pub struct TableRiskInfo {
    pub name: String,
    pub estimated_rows: i64,
    pub has_cascade_fk: bool,
    pub cascade_targets: Vec<String>,
}

pub fn evaluate(input: &RiskInput) -> RiskAssessment {
    // SELECT with allow_read_only → always Low
    if input.operation == Operation::ExecuteSelect && input.allow_read_only {
        return RiskAssessment {
            level: RiskLevel::Low,
            factors: vec![RiskFactor::ReadOnly],
        };
    }

    // Safe DDL → Low (schema status irrelevant for new object creation)
    if input.safe_ddl {
        return RiskAssessment {
            level: RiskLevel::Low,
            factors: vec![RiskFactor::SafeDdl],
        };
    }

    // Schema not available → Unknown
    if input.schema_status != SchemaStatus::Ready {
        return RiskAssessment {
            level: RiskLevel::Unknown,
            factors: vec![RiskFactor::SchemaNotSynced],
        };
    }

    let mut factors = Vec::new();
    let mut level = RiskLevel::Low;

    // Multi-statement DML
    if input.statement_count > 1 && input.has_dml {
        factors.push(RiskFactor::MultiStatement);
        level = level.max(RiskLevel::High);
    }

    // Warning count
    let warn_count = input.findings.len();
    if warn_count >= 3 {
        factors.push(RiskFactor::ManyWarnings { count: warn_count });
        level = level.max(RiskLevel::High);
    } else if warn_count > 0 {
        level = level.max(RiskLevel::Medium);
    }

    // DROP/TRUNCATE
    if input
        .findings
        .iter()
        .any(|f| matches!(f.rule, RuleId::DropTable | RuleId::Truncate))
    {
        factors.push(RiskFactor::DropOperation);
        level = level.max(RiskLevel::High);
    }

    // Table-level risks
    let effective_max_rows = input.max_estimated_rows;
    for table in input.tables {
        if table.has_cascade_fk && table.estimated_rows > effective_max_rows {
            factors.push(RiskFactor::CascadeDelete {
                targets: table.cascade_targets.clone(),
            });
            level = level.max(RiskLevel::High);
        } else if table.has_cascade_fk {
            factors.push(RiskFactor::CascadeDelete {
                targets: table.cascade_targets.clone(),
            });
            level = level.max(RiskLevel::Medium);
        } else if table.estimated_rows > effective_max_rows {
            factors.push(RiskFactor::LargeTable {
                rows: table.estimated_rows,
            });
            level = level.max(RiskLevel::Medium);
        }
    }

    RiskAssessment { level, factors }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::sql_reviewer::RuleAction;

    fn no_findings() -> Vec<Finding> {
        vec![]
    }
    fn no_tables() -> Vec<TableRiskInfo> {
        vec![]
    }

    #[test]
    fn select_with_allow_read_only_is_low() {
        let r = evaluate(&RiskInput {
            operation: Operation::ExecuteSelect,
            findings: &no_findings(),
            schema_status: SchemaStatus::Ready,
            tables: &no_tables(),
            statement_count: 1,
            has_dml: false,
            allow_read_only: true,
            max_estimated_rows: 1000,
            safe_ddl: false,
        });
        assert_eq!(r.level, RiskLevel::Low);
    }

    #[test]
    fn select_without_allow_read_only_needs_schema() {
        let r = evaluate(&RiskInput {
            operation: Operation::ExecuteSelect,
            findings: &no_findings(),
            schema_status: SchemaStatus::NotSynced,
            tables: &no_tables(),
            statement_count: 1,
            has_dml: false,
            allow_read_only: false,
            max_estimated_rows: 1000,
            safe_ddl: false,
        });
        assert_eq!(r.level, RiskLevel::Unknown);
    }

    #[test]
    fn schema_not_synced_returns_unknown() {
        let r = evaluate(&RiskInput {
            operation: Operation::ExecuteDml,
            findings: &no_findings(),
            schema_status: SchemaStatus::NotSynced,
            tables: &no_tables(),
            statement_count: 1,
            has_dml: true,
            allow_read_only: true,
            max_estimated_rows: 1000,
            safe_ddl: false,
        });
        assert_eq!(r.level, RiskLevel::Unknown);
    }

    #[test]
    fn small_dml_no_cascade_is_low() {
        let r = evaluate(&RiskInput {
            operation: Operation::ExecuteDml,
            findings: &no_findings(),
            schema_status: SchemaStatus::Ready,
            tables: &[TableRiskInfo {
                name: "orders".into(),
                estimated_rows: 100,
                has_cascade_fk: false,
                cascade_targets: vec![],
            }],
            statement_count: 1,
            has_dml: true,
            allow_read_only: true,
            max_estimated_rows: 1000,
            safe_ddl: false,
        });
        assert_eq!(r.level, RiskLevel::Low);
    }

    #[test]
    fn large_table_with_cascade_is_high() {
        let r = evaluate(&RiskInput {
            operation: Operation::ExecuteDml,
            findings: &no_findings(),
            schema_status: SchemaStatus::Ready,
            tables: &[TableRiskInfo {
                name: "orders".into(),
                estimated_rows: 50000,
                has_cascade_fk: true,
                cascade_targets: vec!["order_items".into()],
            }],
            statement_count: 1,
            has_dml: true,
            allow_read_only: true,
            max_estimated_rows: 1000,
            safe_ddl: false,
        });
        assert_eq!(r.level, RiskLevel::High);
    }

    #[test]
    fn drop_table_is_high() {
        let findings = vec![Finding {
            rule: RuleId::DropTable,
            action: RuleAction::Warn,
            message: "DROP TABLE".into(),
            statement_index: 0,
        }];
        let r = evaluate(&RiskInput {
            operation: Operation::ExecuteDml,
            findings: &findings,
            schema_status: SchemaStatus::Ready,
            tables: &no_tables(),
            statement_count: 1,
            has_dml: true,
            allow_read_only: true,
            max_estimated_rows: 1000,
            safe_ddl: false,
        });
        assert_eq!(r.level, RiskLevel::High);
    }

    #[test]
    fn multi_statement_dml_is_high() {
        let r = evaluate(&RiskInput {
            operation: Operation::ExecuteDml,
            findings: &no_findings(),
            schema_status: SchemaStatus::Ready,
            tables: &no_tables(),
            statement_count: 3,
            has_dml: true,
            allow_read_only: true,
            max_estimated_rows: 1000,
            safe_ddl: false,
        });
        assert_eq!(r.level, RiskLevel::High);
    }

    #[test]
    fn many_warnings_is_high() {
        let findings: Vec<Finding> = (0..3)
            .map(|i| Finding {
                rule: RuleId::NoWhereDelete,
                action: RuleAction::Warn,
                message: format!("warn {i}"),
                statement_index: i,
            })
            .collect();
        let r = evaluate(&RiskInput {
            operation: Operation::ExecuteDml,
            findings: &findings,
            schema_status: SchemaStatus::Ready,
            tables: &no_tables(),
            statement_count: 1,
            has_dml: true,
            allow_read_only: true,
            max_estimated_rows: 1000,
            safe_ddl: false,
        });
        assert_eq!(r.level, RiskLevel::High);
    }

    #[test]
    fn cascade_without_large_table_is_medium() {
        let r = evaluate(&RiskInput {
            operation: Operation::ExecuteDml,
            findings: &no_findings(),
            schema_status: SchemaStatus::Ready,
            tables: &[TableRiskInfo {
                name: "orders".into(),
                estimated_rows: 500,
                has_cascade_fk: true,
                cascade_targets: vec!["items".into()],
            }],
            statement_count: 1,
            has_dml: true,
            allow_read_only: true,
            max_estimated_rows: 1000,
            safe_ddl: false,
        });
        assert_eq!(r.level, RiskLevel::Medium);
    }
}
