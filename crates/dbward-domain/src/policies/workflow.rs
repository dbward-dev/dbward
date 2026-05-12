use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workflow {
    pub id: String,
    pub database: DatabaseName,
    pub environment: Environment,
    pub operations: Vec<Operation>,
    pub steps: Vec<WorkflowStep>,
    pub skip_approval_for: Vec<Selector>,
    pub require_reason: bool,
    pub allow_self_approve: bool,
    pub allow_same_approver_across_steps: bool,
    /// How long a request can stay pending before expiring.
    pub pending_ttl_secs: Option<u64>,
    /// How long after approval the request remains valid for dispatch.
    pub approval_ttl_secs: Option<u64>,
    #[serde(default)]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub updated_at: Option<DateTime<Utc>>,
}

impl Workflow {
    /// A workflow with no steps means auto-approval.
    pub fn is_auto_approve(&self) -> bool {
        self.steps.is_empty()
    }

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
            steps,
            skip_approval_for: vec![],
            require_reason: false,
            allow_self_approve: false,
            allow_same_approver_across_steps: false,
            pending_ttl_secs: None,
            approval_ttl_secs: None,
            created_at: None,
            updated_at: None,
        }
    }

    #[test]
    fn auto_approve_when_no_steps() {
        let w = make_workflow(vec![], vec![]);
        assert!(w.is_auto_approve());
    }

    #[test]
    fn not_auto_approve_with_steps() {
        let step = WorkflowStep {
            approvers: vec![ApproverGroup {
                selector: Selector::Role("admin".to_string()),
                min: 1,
            }],
            mode: WorkflowStepMode::All,
        };
        let w = make_workflow(vec![], vec![step]);
        assert!(!w.is_auto_approve());
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
}
