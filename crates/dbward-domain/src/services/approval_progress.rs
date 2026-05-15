use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::entities::{Approval, ApprovalAction};
use crate::policies::workflow::{WorkflowStep, WorkflowStepMode};
use crate::services::workflow_matcher::{find_current_step, is_step_satisfied};
use crate::values::Selector;

#[derive(Debug, Clone, Serialize)]
pub struct ApprovalProgress {
    pub current_step: u32,
    pub total_steps: u32,
    pub steps: Vec<StepProgress>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StepProgress {
    pub index: u32,
    pub mode: WorkflowStepMode,
    pub satisfied: bool,
    pub approvers_required: Vec<ApproverRequirement>,
    pub approvals: Vec<ApprovalRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApproverRequirement {
    pub selector: Selector,
    pub min: u32,
    pub current: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApprovalRecord {
    pub user: String,
    pub action: ApprovalAction,
    pub at: DateTime<Utc>,
    pub comment: Option<String>,
}

pub fn build_progress(steps: &[WorkflowStep], approvals: &[Approval]) -> ApprovalProgress {
    let current_step = find_current_step(steps, approvals);
    let total_steps = steps.len() as u32;

    let step_progresses = steps
        .iter()
        .enumerate()
        .map(|(i, step)| {
            let idx = i as u32;
            let step_approvals: Vec<&Approval> =
                approvals.iter().filter(|a| a.step_index == idx).collect();
            let satisfied = is_step_satisfied(step, idx, approvals);

            StepProgress {
                index: idx,
                mode: step.mode,
                satisfied,
                approvers_required: step
                    .approvers
                    .iter()
                    .map(|ag| {
                        let count = step_approvals
                            .iter()
                            .filter(|a| {
                                a.action == ApprovalAction::Approve
                                    && a.matched_selector == ag.selector.to_string()
                            })
                            .count() as u32;
                        ApproverRequirement {
                            selector: ag.selector.clone(),
                            min: ag.min,
                            current: count,
                        }
                    })
                    .collect(),
                approvals: step_approvals
                    .iter()
                    .map(|a| ApprovalRecord {
                        user: a.actor_id.clone(),
                        action: a.action,
                        at: a.created_at,
                        comment: a.comment.clone(),
                    })
                    .collect(),
            }
        })
        .collect();

    ApprovalProgress {
        current_step,
        total_steps,
        steps: step_progresses,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policies::workflow::ApproverGroup;

    fn make_step(role: &str, min: u32, mode: WorkflowStepMode) -> WorkflowStep {
        WorkflowStep {
            approvers: vec![ApproverGroup {
                selector: Selector::Role(role.to_string()),
                min,
            }],
            mode,
        }
    }

    fn make_approval(step: u32, actor: &str, selector: &str) -> Approval {
        Approval {
            id: format!("a-{step}-{actor}"),
            request_id: "r1".into(),
            action: ApprovalAction::Approve,
            actor_id: actor.into(),
            matched_selector: selector.into(),
            step_index: step,
            comment: None,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn empty_steps() {
        let progress = build_progress(&[], &[]);
        assert_eq!(progress.current_step, 0);
        assert_eq!(progress.total_steps, 0);
        assert!(progress.steps.is_empty());
    }

    #[test]
    fn single_step_no_approvals() {
        let steps = vec![make_step("dba", 1, WorkflowStepMode::Any)];
        let progress = build_progress(&steps, &[]);
        assert_eq!(progress.current_step, 0);
        assert_eq!(progress.total_steps, 1);
        assert!(!progress.steps[0].satisfied);
        assert_eq!(progress.steps[0].approvers_required[0].current, 0);
    }

    #[test]
    fn single_step_satisfied() {
        let steps = vec![make_step("dba", 1, WorkflowStepMode::Any)];
        let approvals = vec![make_approval(0, "bob", "role:dba")];
        let progress = build_progress(&steps, &approvals);
        assert_eq!(progress.current_step, 1);
        assert!(progress.steps[0].satisfied);
        assert_eq!(progress.steps[0].approvers_required[0].current, 1);
        assert_eq!(progress.steps[0].approvals.len(), 1);
        assert_eq!(progress.steps[0].approvals[0].user, "bob");
    }

    #[test]
    fn multi_step_partial() {
        let steps = vec![
            make_step("dba", 1, WorkflowStepMode::Any),
            make_step("cto", 1, WorkflowStepMode::Any),
        ];
        let approvals = vec![make_approval(0, "bob", "role:dba")];
        let progress = build_progress(&steps, &approvals);
        assert_eq!(progress.current_step, 1);
        assert_eq!(progress.total_steps, 2);
        assert!(progress.steps[0].satisfied);
        assert!(!progress.steps[1].satisfied);
    }
}
