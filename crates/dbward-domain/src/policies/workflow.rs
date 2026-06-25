use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::services::risk_scorer::RiskLevel;
use crate::values::{DatabaseName, Environment, Operation, Selector};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowStepMode {
    All,
    Any,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproverGroup {
    pub selector: Selector,
    pub min: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStep {
    pub approvers: Vec<ApproverGroup>,
    pub mode: WorkflowStepMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutoApproveMode {
    Always,
    RiskBased,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoApproveSettings {
    pub mode: AutoApproveMode,
    pub max_risk_level: Option<RiskLevel>,
    pub allow_read_only: bool,
    pub allow_safe_ddl: bool,
    pub max_estimated_rows: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workflow {
    pub id: String,
    pub database: DatabaseName,
    pub environment: Environment,
    #[serde(default)]
    pub operations: Vec<Operation>,
    #[serde(default)]
    pub auto_approve: Option<AutoApproveSettings>,
    #[serde(default)]
    pub steps: Vec<WorkflowStep>,
    #[serde(default)]
    pub require_reason: bool,
    #[serde(default)]
    pub allow_self_approve: bool,
    #[serde(default)]
    pub allow_same_approver_across_steps: bool,
    /// Whether to run EXPLAIN dry-run for requests matching this workflow.
    #[serde(default = "default_true_fn")]
    pub explain: bool,
    /// How long a request can stay pending before expiring.
    pub pending_ttl_secs: Option<u64>,
    /// Per-workflow statement execution timeout override.
    pub statement_timeout_secs: Option<u64>,
    /// How long after approval the request remains valid for dispatch.
    pub approval_ttl_secs: Option<u64>,
    #[serde(default)]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub updated_at: Option<DateTime<Utc>>,
}

fn default_true_fn() -> bool {
    true
}
impl Workflow {
    /// Check if the given operations list matches this workflow.
    /// Empty operations = matches all.
    pub fn matches_operation(&self, op: Operation) -> bool {
        self.operations.is_empty() || self.operations.contains(&op)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_workflow(operations: Vec<Operation>, steps: Vec<WorkflowStep>) -> Workflow {
        Workflow {
            id: "w1".into(),
            database: DatabaseName::wildcard(),
            environment: Environment::wildcard(),
            operations,
            auto_approve: None,
            steps,
            require_reason: false,
            allow_self_approve: false,
            allow_same_approver_across_steps: false,
            explain: true,
            pending_ttl_secs: None,
            statement_timeout_secs: None,
            approval_ttl_secs: None,
            created_at: None,
            updated_at: None,
        }
    }

    #[test]
    fn matches_operation_empty_means_all() {
        let w = make_workflow(vec![], vec![]);
        assert!(w.matches_operation(Operation::ExecuteDml));
        assert!(w.matches_operation(Operation::ExecuteSelect));
    }

    #[test]
    fn matches_operation_specific() {
        let w = make_workflow(vec![Operation::ExecuteDml], vec![]);
        assert!(w.matches_operation(Operation::ExecuteDml));
        assert!(!w.matches_operation(Operation::ExecuteSelect));
    }

    #[test]
    fn workflow_deserialize_minimal() {
        let json = r#"{"id":"w1","database":"*","environment":"*"}"#;
        let wf: Workflow = serde_json::from_str(json).unwrap();
        assert_eq!(wf.id, "w1");
        assert!(wf.steps.is_empty());
        assert!(wf.auto_approve.is_none());
        assert!(!wf.require_reason);
        assert!(wf.operations.is_empty());
        assert!(!wf.allow_self_approve);
    }

    #[test]
    fn workflow_deserialize_with_auto_approve() {
        let json = r#"{"id":"w1","database":"*","environment":"*","auto_approve":{"mode":"always","max_risk_level":null,"allow_read_only":true,"allow_safe_ddl":true,"max_estimated_rows":1000}}"#;
        let wf: Workflow = serde_json::from_str(json).unwrap();
        let aa = wf.auto_approve.unwrap();
        assert_eq!(aa.mode, AutoApproveMode::Always);
        assert!(aa.max_risk_level.is_none());
    }
}
