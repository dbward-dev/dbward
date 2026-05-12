use crate::policies::Workflow;
use crate::values::{DatabaseName, Environment, Operation};

/// Result of workflow evaluation for a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalDecision {
    /// No workflow matched → pending (fail-closed).
    Pending,
    /// Workflow matched, steps exist → pending with workflow.
    PendingWithWorkflow,
    /// Workflow matched, skip_approval_for matched or steps empty → auto_approved.
    AutoApproved,
}

/// 4-stage workflow lookup.
/// Priority: (db, env) > (*, env) > (db, *) > (*, *)
/// Within same scope: exact operations match > empty operations (catchall)
pub fn find_matching_workflow<'a>(
    workflows: &'a [Workflow],
    database: &DatabaseName,
    environment: &Environment,
    operation: Operation,
) -> Option<&'a Workflow> {
    let candidates: Vec<&Workflow> = workflows
        .iter()
        .filter(|w| w.matches_operation(operation))
        .filter(|w| matches_scope(&w.database, database) && matches_scope_env(&w.environment, environment))
        .collect();

    if candidates.is_empty() {
        return None;
    }

    // Sort by specificity: exact db+env > partial wildcard > full wildcard
    // Then by operations: specific > catchall
    candidates
        .into_iter()
        .max_by_key(|w| specificity_score(w, database, environment, operation))
}

/// Evaluate the matched workflow to determine approval decision.
pub fn evaluate(
    workflow: Option<&Workflow>,
    role_names: &[String],
    user_groups: &[String],
    user_id: &str,
    is_requester: bool,
) -> ApprovalDecision {
    let workflow = match workflow {
        None => return ApprovalDecision::Pending,
        Some(w) => w,
    };

    if workflow.is_auto_approve() {
        return ApprovalDecision::AutoApproved;
    }

    // Check skip_approval_for
    for selector in &workflow.skip_approval_for {
        if selector.matches(role_names, user_groups, user_id, is_requester) {
            return ApprovalDecision::AutoApproved;
        }
    }

    ApprovalDecision::PendingWithWorkflow
}

fn matches_scope(policy_db: &DatabaseName, request_db: &DatabaseName) -> bool {
    policy_db.is_wildcard() || policy_db == request_db
}

fn matches_scope_env(policy_env: &Environment, request_env: &Environment) -> bool {
    policy_env.is_wildcard() || policy_env == request_env
}

fn specificity_score(w: &Workflow, db: &DatabaseName, env: &Environment, op: Operation) -> u8 {
    let mut score = 0u8;
    // env match: exact=4, wildcard=0 (higher priority than db per design)
    if !w.environment.is_wildcard() && &w.environment == env {
        score += 4;
    }
    // db match: exact=2, wildcard=0
    if !w.database.is_wildcard() && &w.database == db {
        score += 2;
    }
    // operations: specific=1, catchall=0
    if !w.operations.is_empty() && w.operations.contains(&op) {
        score += 1;
    }
    score
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policies::{ApproverGroup, WorkflowStep, WorkflowStepMode};
    use crate::values::Selector;

    fn wf(db: &str, env: &str, ops: Vec<Operation>, steps: Vec<WorkflowStep>, skip: Vec<Selector>) -> Workflow {
        Workflow {
            id: format!("{db}:{env}"),
            database: DatabaseName::new(db).unwrap(),
            environment: Environment::new(env).unwrap(),
            operations: ops,
            steps,
            skip_approval_for: skip,
            require_reason: false,
            allow_self_approve: false,
            allow_same_approver_across_steps: false,
            pending_ttl_secs: None,
            approval_ttl_secs: None,
            created_at: None,
            updated_at: None,
        }
    }

    fn step() -> WorkflowStep {
        WorkflowStep {
            approvers: vec![ApproverGroup {
                selector: Selector::Role("admin".to_string()),
                min: 1,
            }],
            mode: WorkflowStepMode::All,
        }
    }

    #[test]
    fn no_workflow_returns_pending() {
        let decision = evaluate(None, &[], &[], "alice", true);
        assert_eq!(decision, ApprovalDecision::Pending);
    }

    #[test]
    fn empty_steps_returns_auto_approved() {
        let w = wf("*", "*", vec![], vec![], vec![]);
        let decision = evaluate(Some(&w), &[], &[], "alice", true);
        assert_eq!(decision, ApprovalDecision::AutoApproved);
    }

    #[test]
    fn steps_present_returns_pending_with_workflow() {
        let w = wf("*", "*", vec![], vec![step()], vec![]);
        let decision = evaluate(Some(&w), &[], &[], "alice", true);
        assert_eq!(decision, ApprovalDecision::PendingWithWorkflow);
    }

    #[test]
    fn skip_approval_for_matches() {
        let w = wf("*", "*", vec![], vec![step()], vec![Selector::Role("admin".to_string())]);
        let decision = evaluate(Some(&w), &["admin".to_string()], &[], "alice", true);
        assert_eq!(decision, ApprovalDecision::AutoApproved);
    }

    #[test]
    fn skip_approval_for_no_match() {
        let w = wf("*", "*", vec![], vec![step()], vec![Selector::Role("admin".to_string())]);
        let decision = evaluate(Some(&w), &["developer".to_string()], &[], "alice", true);
        assert_eq!(decision, ApprovalDecision::PendingWithWorkflow);
    }

    #[test]
    fn exact_db_env_wins_over_wildcard() {
        let workflows = vec![
            wf("*", "*", vec![], vec![], vec![]),
            wf("app", "production", vec![], vec![step()], vec![]),
        ];
        let db = DatabaseName::new("app").unwrap();
        let env = Environment::new("production").unwrap();
        let matched = find_matching_workflow(&workflows, &db, &env, Operation::ExecuteDml).unwrap();
        assert_eq!(matched.id, "app:production");
    }

    #[test]
    fn wildcard_db_exact_env_wins_over_exact_db_wildcard_env() {
        let workflows = vec![
            wf("app", "*", vec![], vec![], vec![]),
            wf("*", "production", vec![], vec![step()], vec![]),
        ];
        let db = DatabaseName::new("app").unwrap();
        let env = Environment::new("production").unwrap();
        let matched = find_matching_workflow(&workflows, &db, &env, Operation::ExecuteDml).unwrap();
        // (*, production) wins over (app, *) per design: env > db
        assert_eq!(matched.id, "*:production");
    }

    #[test]
    fn specific_operations_wins_over_catchall() {
        let workflows = vec![
            wf("app", "production", vec![], vec![], vec![]),
            wf("app", "production", vec![Operation::ExecuteDml], vec![step()], vec![]),
        ];
        let db = DatabaseName::new("app").unwrap();
        let env = Environment::new("production").unwrap();
        let matched = find_matching_workflow(&workflows, &db, &env, Operation::ExecuteDml).unwrap();
        assert!(!matched.steps.is_empty());
    }

    #[test]
    fn no_match_returns_none() {
        let workflows = vec![
            wf("other", "production", vec![], vec![step()], vec![]),
        ];
        let db = DatabaseName::new("app").unwrap();
        let env = Environment::new("production").unwrap();
        assert!(find_matching_workflow(&workflows, &db, &env, Operation::ExecuteDml).is_none());
    }

    #[test]
    fn wildcard_env_matches() {
        let workflows = vec![
            wf("app", "*", vec![], vec![step()], vec![]),
        ];
        let db = DatabaseName::new("app").unwrap();
        let env = Environment::new("staging").unwrap();
        let matched = find_matching_workflow(&workflows, &db, &env, Operation::ExecuteSelect);
        assert!(matched.is_some());
    }
}

// --- Step progression logic ---

use crate::entities::{Approval, ApprovalAction};
use crate::policies::workflow::{WorkflowStep, WorkflowStepMode};

/// Find the first step that is not yet fully satisfied.
pub fn find_current_step(steps: &[WorkflowStep], approvals: &[Approval]) -> u32 {
    for (i, step) in steps.iter().enumerate() {
        if !is_step_satisfied(step, i as u32, approvals) {
            return i as u32;
        }
    }
    steps.len() as u32
}

/// Check if a single step is satisfied based on its mode and approver group minimums.
pub fn is_step_satisfied(step: &WorkflowStep, step_index: u32, approvals: &[Approval]) -> bool {
    let step_approvals: Vec<&Approval> = approvals.iter()
        .filter(|a| a.step_index == step_index && a.action == ApprovalAction::Approve)
        .collect();

    // Admin override satisfies the entire step
    if step_approvals.iter().any(|a| a.matched_selector == "admin_override") {
        return true;
    }

    match step.mode {
        WorkflowStepMode::All => {
            step.approvers.iter().all(|ag| {
                let count = step_approvals.iter()
                    .filter(|a| a.matched_selector == ag.selector.to_string())
                    .count() as u32;
                count >= ag.min
            })
        }
        WorkflowStepMode::Any => {
            step.approvers.iter().any(|ag| {
                let count = step_approvals.iter()
                    .filter(|a| a.matched_selector == ag.selector.to_string())
                    .count() as u32;
                count >= ag.min
            })
        }
    }
}

/// Check if all steps are satisfied.
pub fn all_steps_satisfied(steps: &[WorkflowStep], approvals: &[Approval]) -> bool {
    // Admin override satisfies ALL steps
    if approvals.iter().any(|a| a.action == ApprovalAction::Approve && a.matched_selector == "admin_override") {
        return true;
    }
    steps.iter().enumerate().all(|(i, step)| is_step_satisfied(step, i as u32, approvals))
}

#[cfg(test)]
mod step_tests {
    use super::*;
    use crate::policies::workflow::ApproverGroup;
    use crate::values::Selector;
    use chrono::Utc;

    fn make_approval(step: u32, selector: &str) -> Approval {
        Approval {
            id: format!("a-{step}"),
            request_id: "r1".into(),
            action: ApprovalAction::Approve,
            actor_id: "bob".into(),
            matched_selector: selector.into(),
            step_index: step,
            comment: None,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn empty_steps_returns_zero() {
        assert_eq!(find_current_step(&[], &[]), 0);
    }

    #[test]
    fn single_step_unsatisfied() {
        let steps = vec![WorkflowStep {
            approvers: vec![ApproverGroup { selector: Selector::Role("dba".into()), min: 1 }],
            mode: WorkflowStepMode::Any,
        }];
        assert_eq!(find_current_step(&steps, &[]), 0);
    }

    #[test]
    fn single_step_satisfied() {
        let steps = vec![WorkflowStep {
            approvers: vec![ApproverGroup { selector: Selector::Role("dba".into()), min: 1 }],
            mode: WorkflowStepMode::Any,
        }];
        let approvals = vec![make_approval(0, "role:dba")];
        assert_eq!(find_current_step(&steps, &approvals), 1);
    }

    #[test]
    fn multi_step_partial() {
        let steps = vec![
            WorkflowStep {
                approvers: vec![ApproverGroup { selector: Selector::Role("dba".into()), min: 1 }],
                mode: WorkflowStepMode::Any,
            },
            WorkflowStep {
                approvers: vec![ApproverGroup { selector: Selector::Role("cto".into()), min: 1 }],
                mode: WorkflowStepMode::Any,
            },
        ];
        let approvals = vec![make_approval(0, "role:dba")];
        assert_eq!(find_current_step(&steps, &approvals), 1);
        assert!(!all_steps_satisfied(&steps, &approvals));
    }

    #[test]
    fn mode_all_requires_every_group() {
        let steps = vec![WorkflowStep {
            approvers: vec![
                ApproverGroup { selector: Selector::Role("dba".into()), min: 1 },
                ApproverGroup { selector: Selector::Role("security".into()), min: 1 },
            ],
            mode: WorkflowStepMode::All,
        }];
        let partial = vec![make_approval(0, "role:dba")];
        assert!(!is_step_satisfied(&steps[0], 0, &partial));

        let full = vec![make_approval(0, "role:dba"), make_approval(0, "role:security")];
        assert!(is_step_satisfied(&steps[0], 0, &full));
    }
}
