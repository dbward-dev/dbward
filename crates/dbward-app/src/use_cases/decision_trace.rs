use serde::{Deserialize, Serialize};

/// Immutable snapshot of the decision-making process at request creation time.
/// Stored as JSON in `requests.decision_trace_json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionTrace {
    pub version: u16,
    pub classification: Classification,
    pub sql_review: SqlReview,
    pub risk: Risk,
    pub workflow: WorkflowMatch,
    pub decision: Decision,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Classification {
    pub resolved_operation: OperationKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    ExecuteSelect,
    ExecuteDml,
    MigrateUp,
    MigrateDown,
    MigrateStatus,
}

impl From<dbward_domain::values::Operation> for OperationKind {
    fn from(op: dbward_domain::values::Operation) -> Self {
        match op {
            dbward_domain::values::Operation::ExecuteSelect => Self::ExecuteSelect,
            dbward_domain::values::Operation::ExecuteDml => Self::ExecuteDml,
            dbward_domain::values::Operation::MigrateUp => Self::MigrateUp,
            dbward_domain::values::Operation::MigrateDown => Self::MigrateDown,
            dbward_domain::values::Operation::MigrateStatus => Self::MigrateStatus,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlReview {
    pub findings_count: usize,
    #[serde(default)]
    pub parse_failed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Risk {
    pub level: RiskLevel,
    pub factors: Vec<String>,
    pub schema_status: SchemaStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
    Unknown,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaStatus {
    Ready,
    NotSynced,
    Failed,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowMatch {
    pub matched: Option<WorkflowRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowRef {
    pub id: String,
    pub database: String,
    pub environment: String,
    pub step_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub outcome: Outcome,
    pub reasons: Vec<DecisionReason>,
    pub auto_approve_threshold: Option<RiskLevel>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    AutoApproved,
    NeedsApproval,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionReason {
    EmptySteps,
    RiskBelowThreshold,
    BreakGlass,
    AutoApproveDisabled,
    RiskAboveThreshold,
    NoAutoApproveRule,
    RiskUnavailable,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_roundtrip() {
        let trace = DecisionTrace {
            version: 1,
            classification: Classification {
                resolved_operation: OperationKind::ExecuteSelect,
            },
            sql_review: SqlReview {
                findings_count: 0,
                parse_failed: false,
            },
            risk: Risk {
                level: RiskLevel::Low,
                factors: vec!["ReadOnly".into()],
                schema_status: SchemaStatus::Ready,
            },
            workflow: WorkflowMatch {
                matched: Some(WorkflowRef {
                    id: "wf-1".into(),
                    database: "*".into(),
                    environment: "development".into(),
                    step_count: 0,
                }),
            },
            decision: Decision {
                outcome: Outcome::AutoApproved,
                reasons: vec![DecisionReason::EmptySteps],
                auto_approve_threshold: None,
            },
        };
        let json = serde_json::to_string(&trace).unwrap();
        let parsed: DecisionTrace = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.decision.outcome, Outcome::AutoApproved);
    }

    #[test]
    fn parse_failed_trace() {
        let trace = DecisionTrace {
            version: 1,
            classification: Classification {
                resolved_operation: OperationKind::ExecuteDml,
            },
            sql_review: SqlReview {
                findings_count: 0,
                parse_failed: true,
            },
            risk: Risk {
                level: RiskLevel::Unavailable,
                factors: vec![],
                schema_status: SchemaStatus::Unavailable,
            },
            workflow: WorkflowMatch { matched: None },
            decision: Decision {
                outcome: Outcome::NeedsApproval,
                reasons: vec![DecisionReason::RiskUnavailable],
                auto_approve_threshold: Some(RiskLevel::Medium),
            },
        };
        let json = serde_json::to_string(&trace).unwrap();
        assert!(json.contains("\"parse_failed\":true"));
        assert!(json.contains("\"unavailable\""));
    }
}
