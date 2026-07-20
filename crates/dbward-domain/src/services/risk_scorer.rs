use crate::services::sql_reviewer::{Finding, RuleId};
use crate::values::Operation;

/// Risk levels ordered from lowest to highest. Unknown and Unavailable are intentionally last
/// so that `PartialOrd` derive treats them as the highest values (most restrictive).
/// DO NOT reorder variants without updating workflow_matcher's exclusion logic.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
    Unknown,
    /// Parse failed or assessment unavailable — used in DecisionTrace only.
    Unavailable,
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

impl RiskFactor {
    pub fn name(&self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::SafeDdl => "safe_ddl",
            Self::CascadeDelete { .. } => "cascade_delete",
            Self::LargeTable { .. } => "large_table",
            Self::DropOperation => "drop_operation",
            Self::MultiStatement => "multi_statement",
            Self::ManyWarnings { .. } => "many_warnings",
            Self::SchemaNotSynced => "schema_not_synced",
        }
    }
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
    pub has_delete_stmt: bool,
    pub allow_read_only: bool,
    pub safe_ddl: bool,
    pub max_estimated_rows: i64,
}

/// Information about a child table affected by CASCADE DELETE on a parent.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CascadeChildInfo {
    pub table_name: String,
    pub schema_name: Option<String>,
    pub estimated_rows: i64,
    pub depth: u8,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TableRiskInfo {
    pub name: String,
    pub estimated_rows: i64,
    /// DEPRECATED(v0.2): Outbound FK info. NOT used in risk scoring.
    /// Kept for backward compatibility with stored risk_json.
    pub has_cascade_fk: bool,
    /// DEPRECATED(v0.2): See has_cascade_fk.
    pub cascade_targets: Vec<String>,
    /// Inbound: child tables affected by CASCADE when this table is DELETE target.
    #[serde(default)]
    pub cascade_children: Vec<CascadeChildInfo>,
    /// True if BFS hit depth limit with unvisited children remaining.
    #[serde(default)]
    pub cascade_children_truncated: bool,
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
    if input.findings.iter().any(|f| {
        matches!(
            f.rule,
            RuleId::DropTable
                | RuleId::Truncate
                | RuleId::DropIndex
                | RuleId::DropView
                | RuleId::DropSequence
        )
    }) {
        factors.push(RiskFactor::DropOperation);
        level = level.max(RiskLevel::High);
    }

    // Table-level risks
    let effective_max_rows = input.max_estimated_rows;
    for table in input.tables {
        // Inbound CASCADE: only fires when SQL contains DELETE
        if input.has_delete_stmt && !table.cascade_children.is_empty() {
            let max_child_rows = table
                .cascade_children
                .iter()
                .map(|c| c.estimated_rows)
                .max()
                .unwrap_or(0);
            let base_level = if max_child_rows > effective_max_rows
                || table.estimated_rows > effective_max_rows
            {
                RiskLevel::High
            } else {
                RiskLevel::Medium
            };
            let final_level = if table.cascade_children_truncated {
                base_level.max(RiskLevel::High)
            } else {
                base_level
            };
            factors.push(RiskFactor::CascadeDelete {
                targets: table
                    .cascade_children
                    .iter()
                    .map(|c| match &c.schema_name {
                        Some(s) if s != "public" => format!("{}.{}", s, c.table_name),
                        _ => c.table_name.clone(),
                    })
                    .collect(),
            });
            level = level.max(final_level);
            // Also report LargeTable if the parent itself is large
            if table.estimated_rows > effective_max_rows {
                factors.push(RiskFactor::LargeTable {
                    rows: table.estimated_rows,
                });
            }
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
            has_delete_stmt: false,
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
            has_delete_stmt: false,
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
            has_delete_stmt: false,
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
                cascade_children: vec![],
                cascade_children_truncated: false,
            }],
            statement_count: 1,
            has_dml: true,
            has_delete_stmt: false,
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
                name: "users".into(),
                estimated_rows: 50000,
                has_cascade_fk: false,
                cascade_targets: vec![],
                cascade_children: vec![CascadeChildInfo {
                    table_name: "orders".into(),
                    schema_name: Some("public".into()),
                    estimated_rows: 100000,
                    depth: 1,
                }],
                cascade_children_truncated: false,
            }],
            statement_count: 1,
            has_dml: true,
            has_delete_stmt: true,
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
            has_delete_stmt: false,
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
            has_delete_stmt: false,
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
            has_delete_stmt: false,
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
                name: "users".into(),
                estimated_rows: 500,
                has_cascade_fk: false,
                cascade_targets: vec![],
                cascade_children: vec![CascadeChildInfo {
                    table_name: "orders".into(),
                    schema_name: Some("public".into()),
                    estimated_rows: 200,
                    depth: 1,
                }],
                cascade_children_truncated: false,
            }],
            statement_count: 1,
            has_dml: true,
            has_delete_stmt: true,
            allow_read_only: true,
            max_estimated_rows: 1000,
            safe_ddl: false,
        });
        assert_eq!(r.level, RiskLevel::Medium);
    }

    #[test]
    fn cascade_not_fired_without_delete_stmt() {
        // has_delete_stmt=false → cascade_children ignored
        let r = evaluate(&RiskInput {
            operation: Operation::ExecuteDml,
            findings: &no_findings(),
            schema_status: SchemaStatus::Ready,
            tables: &[TableRiskInfo {
                name: "users".into(),
                estimated_rows: 500,
                has_cascade_fk: false,
                cascade_targets: vec![],
                cascade_children: vec![CascadeChildInfo {
                    table_name: "orders".into(),
                    schema_name: Some("public".into()),
                    estimated_rows: 50000,
                    depth: 1,
                }],
                cascade_children_truncated: false,
            }],
            statement_count: 1,
            has_dml: true,
            has_delete_stmt: false,
            allow_read_only: true,
            max_estimated_rows: 1000,
            safe_ddl: false,
        });
        // Without has_delete_stmt, cascade_children should be ignored → Low
        assert_eq!(r.level, RiskLevel::Low);
        assert!(
            !r.factors
                .iter()
                .any(|f| matches!(f, RiskFactor::CascadeDelete { .. }))
        );
    }

    #[test]
    fn cascade_truncated_escalates_to_high() {
        let r = evaluate(&RiskInput {
            operation: Operation::ExecuteDml,
            findings: &no_findings(),
            schema_status: SchemaStatus::Ready,
            tables: &[TableRiskInfo {
                name: "users".into(),
                estimated_rows: 100,
                has_cascade_fk: false,
                cascade_targets: vec![],
                cascade_children: vec![CascadeChildInfo {
                    table_name: "orders".into(),
                    schema_name: Some("public".into()),
                    estimated_rows: 50, // small child
                    depth: 1,
                }],
                cascade_children_truncated: true, // but truncated!
            }],
            statement_count: 1,
            has_dml: true,
            has_delete_stmt: true,
            allow_read_only: true,
            max_estimated_rows: 1000,
            safe_ddl: false,
        });
        // base_level=Medium (small rows), but truncated → escalation to High
        assert_eq!(r.level, RiskLevel::High);
    }

    #[test]
    fn deprecated_has_cascade_fk_does_not_fire() {
        // has_cascade_fk=true but cascade_children empty → no CascadeDelete factor
        let r = evaluate(&RiskInput {
            operation: Operation::ExecuteDml,
            findings: &no_findings(),
            schema_status: SchemaStatus::Ready,
            tables: &[TableRiskInfo {
                name: "orders".into(),
                estimated_rows: 50000,
                has_cascade_fk: true,
                cascade_targets: vec!["users".into()],
                cascade_children: vec![],
                cascade_children_truncated: false,
            }],
            statement_count: 1,
            has_dml: true,
            has_delete_stmt: true,
            allow_read_only: true,
            max_estimated_rows: 1000,
            safe_ddl: false,
        });
        // LargeTable fires, but CascadeDelete does NOT
        assert!(
            r.factors
                .iter()
                .any(|f| matches!(f, RiskFactor::LargeTable { .. }))
        );
        assert!(
            !r.factors
                .iter()
                .any(|f| matches!(f, RiskFactor::CascadeDelete { .. }))
        );
    }
}
