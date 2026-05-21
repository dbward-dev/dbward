use crate::policies::Workflow;
use crate::values::{DatabaseName, Environment, Operation};

/// Result of workflow evaluation for a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalDecision {
    /// No workflow matched → pending (fail-closed).
    Pending,
    /// Workflow requires human approval.
    NeedsApproval,
    /// Auto-approved with explicit reason.
    AutoApproved { reason: AutoApproveReason },
}

/// Why a request was auto-approved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutoApproveReason {
    /// Workflow has no approval steps.
    EmptySteps,
    /// Risk level is below threshold.
    RiskBased,
}

impl ApprovalDecision {
    /// Returns true if the request needs human approval.
    pub fn needs_approval(&self) -> bool {
        matches!(self, Self::Pending | Self::NeedsApproval)
    }
}

pub use super::risk_scorer::RiskLevel;

/// Scoped auto-approve entry. Matched by (database, environment) specificity.
#[derive(Debug, Clone)]
pub struct AutoApproveEntry {
    pub database: DatabaseName,
    pub environment: Environment,
    /// Maximum risk level that can be auto-approved.
    /// `None` means auto-approve is disabled for this scope.
    pub max_risk_level: Option<RiskLevel>,
    pub allow_safe_ddl: bool,
    pub allow_read_only: bool,
    pub max_estimated_rows: u64,
}

impl AutoApproveEntry {
    /// Whether auto-approve is enabled for this entry.
    pub fn is_enabled(&self) -> bool {
        self.max_risk_level.is_some()
    }
}

/// Find the most specific auto_approve entry for a given (database, environment).
/// Priority: (db, env) > (*, env) > (db, *) > (*, *)
/// Returns None if no entry matches (equivalent to auto-approve disabled).
pub fn find_auto_approve<'a>(
    entries: &'a [AutoApproveEntry],
    database: &DatabaseName,
    environment: &Environment,
) -> Option<&'a AutoApproveEntry> {
    let candidates: Vec<&AutoApproveEntry> = entries
        .iter()
        .filter(|e| {
            matches_scope(&e.database, database) && matches_scope_env(&e.environment, environment)
        })
        .collect();

    if candidates.is_empty() {
        return None;
    }

    candidates
        .into_iter()
        .max_by_key(|e| scope_specificity(&e.database, &e.environment, database, environment))
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
        .filter(|w| {
            matches_scope(&w.database, database) && matches_scope_env(&w.environment, environment)
        })
        .collect();

    if candidates.is_empty() {
        return None;
    }

    candidates
        .into_iter()
        .max_by_key(|w| specificity_score(w, database, environment, operation))
}

/// Evaluate the matched workflow to determine approval decision.
pub fn evaluate(
    workflow: Option<&Workflow>,
    risk_level: Option<RiskLevel>,
    auto_approve_entry: Option<&AutoApproveEntry>,
) -> ApprovalDecision {
    let workflow = match workflow {
        None => return ApprovalDecision::Pending,
        Some(w) => w,
    };

    // stepsなし = short-circuit to auto-approve (auto_approve not consulted)
    if workflow.is_auto_approve() {
        return ApprovalDecision::AutoApproved {
            reason: AutoApproveReason::EmptySteps,
        };
    }

    // Risk-based auto-approve
    if let Some(entry) = auto_approve_entry {
        if let Some(max_level) = entry.max_risk_level {
            if let Some(level) = risk_level {
                // Unknown is never auto-approved even with risk = "high"
                if level != RiskLevel::Unknown && level <= max_level {
                    return ApprovalDecision::AutoApproved {
                        reason: AutoApproveReason::RiskBased,
                    };
                }
            }
        }
    }

    ApprovalDecision::NeedsApproval
}

fn matches_scope(policy_db: &DatabaseName, request_db: &DatabaseName) -> bool {
    policy_db.is_wildcard() || policy_db == request_db
}

fn matches_scope_env(policy_env: &Environment, request_env: &Environment) -> bool {
    policy_env.is_wildcard() || policy_env == request_env
}

fn scope_specificity(
    policy_db: &DatabaseName,
    policy_env: &Environment,
    request_db: &DatabaseName,
    request_env: &Environment,
) -> u8 {
    let mut score = 0u8;
    if !policy_env.is_wildcard() && policy_env == request_env {
        score += 4;
    }
    if !policy_db.is_wildcard() && policy_db == request_db {
        score += 2;
    }
    score
}

fn specificity_score(w: &Workflow, db: &DatabaseName, env: &Environment, op: Operation) -> u8 {
    let mut score = scope_specificity(&w.database, &w.environment, db, env);
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

    fn wf(db: &str, env: &str, ops: Vec<Operation>, steps: Vec<WorkflowStep>) -> Workflow {
        Workflow {
            id: format!("{db}:{env}"),
            database: DatabaseName::new(db).unwrap(),
            environment: Environment::new(env).unwrap(),
            operations: ops,
            steps,
            require_reason: false,
            allow_self_approve: false,
            allow_same_approver_across_steps: false,
            pending_ttl_secs: None,
            statement_timeout_secs: None,
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

    fn entry(db: &str, env: &str, max: Option<RiskLevel>) -> AutoApproveEntry {
        AutoApproveEntry {
            database: DatabaseName::new(db).unwrap(),
            environment: Environment::new(env).unwrap(),
            max_risk_level: max,
            allow_safe_ddl: true,
            allow_read_only: true,
            max_estimated_rows: 1000,
        }
    }

    #[test]
    fn no_workflow_returns_pending() {
        let decision = evaluate(None, None, None);
        assert_eq!(decision, ApprovalDecision::Pending);
    }

    #[test]
    fn empty_steps_returns_auto_approved() {
        let w = wf("*", "*", vec![], vec![]);
        let decision = evaluate(Some(&w), None, None);
        assert!(matches!(decision, ApprovalDecision::AutoApproved { .. }));
    }

    #[test]
    fn steps_present_no_auto_approve_returns_needs_approval() {
        let w = wf("*", "*", vec![], vec![step()]);
        let decision = evaluate(Some(&w), None, None);
        assert_eq!(decision, ApprovalDecision::NeedsApproval);
    }

    #[test]
    fn risk_based_auto_approve_low() {
        let w = wf("*", "*", vec![], vec![step()]);
        let e = entry("*", "*", Some(RiskLevel::Low));
        let decision = evaluate(Some(&w), Some(RiskLevel::Low), Some(&e));
        assert!(matches!(
            decision,
            ApprovalDecision::AutoApproved {
                reason: AutoApproveReason::RiskBased
            }
        ));
    }

    #[test]
    fn risk_above_threshold_needs_approval() {
        let w = wf("*", "*", vec![], vec![step()]);
        let e = entry("*", "*", Some(RiskLevel::Low));
        let decision = evaluate(Some(&w), Some(RiskLevel::Medium), Some(&e));
        assert_eq!(decision, ApprovalDecision::NeedsApproval);
    }

    #[test]
    fn unknown_risk_never_auto_approved() {
        let w = wf("*", "*", vec![], vec![step()]);
        let e = entry("*", "*", Some(RiskLevel::High));
        let decision = evaluate(Some(&w), Some(RiskLevel::Unknown), Some(&e));
        assert_eq!(decision, ApprovalDecision::NeedsApproval);
    }

    #[test]
    fn auto_approve_disabled_entry() {
        let w = wf("*", "*", vec![], vec![step()]);
        let e = entry("*", "*", None); // risk = "none"
        let decision = evaluate(Some(&w), Some(RiskLevel::Low), Some(&e));
        assert_eq!(decision, ApprovalDecision::NeedsApproval);
    }

    #[test]
    fn exact_db_env_wins_over_wildcard() {
        let workflows = vec![
            wf("*", "*", vec![], vec![]),
            wf("app", "production", vec![], vec![step()]),
        ];
        let db = DatabaseName::new("app").unwrap();
        let env = Environment::new("production").unwrap();
        let matched = find_matching_workflow(&workflows, &db, &env, Operation::ExecuteDml).unwrap();
        assert_eq!(matched.id, "app:production");
    }

    #[test]
    fn wildcard_db_exact_env_wins_over_exact_db_wildcard_env() {
        let workflows = vec![
            wf("app", "*", vec![], vec![]),
            wf("*", "production", vec![], vec![step()]),
        ];
        let db = DatabaseName::new("app").unwrap();
        let env = Environment::new("production").unwrap();
        let matched = find_matching_workflow(&workflows, &db, &env, Operation::ExecuteDml).unwrap();
        assert_eq!(matched.id, "*:production");
    }

    #[test]
    fn specific_operations_wins_over_catchall() {
        let workflows = vec![
            wf("app", "production", vec![], vec![]),
            wf(
                "app",
                "production",
                vec![Operation::ExecuteDml],
                vec![step()],
            ),
        ];
        let db = DatabaseName::new("app").unwrap();
        let env = Environment::new("production").unwrap();
        let matched = find_matching_workflow(&workflows, &db, &env, Operation::ExecuteDml).unwrap();
        assert!(!matched.steps.is_empty());
    }

    #[test]
    fn no_match_returns_none() {
        let workflows = vec![wf("other", "production", vec![], vec![step()])];
        let db = DatabaseName::new("app").unwrap();
        let env = Environment::new("production").unwrap();
        assert!(find_matching_workflow(&workflows, &db, &env, Operation::ExecuteDml).is_none());
    }

    #[test]
    fn wildcard_env_matches() {
        let workflows = vec![wf("app", "*", vec![], vec![step()])];
        let db = DatabaseName::new("app").unwrap();
        let env = Environment::new("staging").unwrap();
        let matched = find_matching_workflow(&workflows, &db, &env, Operation::ExecuteSelect);
        assert!(matched.is_some());
    }

    #[test]
    fn find_auto_approve_specificity() {
        let entries = vec![
            entry("*", "*", Some(RiskLevel::Low)),
            entry("*", "production", None),
            entry("app", "production", Some(RiskLevel::Medium)),
        ];
        let db = DatabaseName::new("app").unwrap();
        let env = Environment::new("production").unwrap();
        let found = find_auto_approve(&entries, &db, &env).unwrap();
        // (app, production) = score 6, most specific
        assert_eq!(found.max_risk_level, Some(RiskLevel::Medium));
    }

    #[test]
    fn find_auto_approve_env_wins_over_db() {
        let entries = vec![
            entry("app", "*", Some(RiskLevel::High)),
            entry("*", "production", None),
        ];
        let db = DatabaseName::new("app").unwrap();
        let env = Environment::new("production").unwrap();
        let found = find_auto_approve(&entries, &db, &env).unwrap();
        // (*, production) = score 4 vs (app, *) = score 2
        assert_eq!(found.max_risk_level, None);
    }

    #[test]
    fn find_auto_approve_no_match() {
        let entries = vec![entry("other", "staging", Some(RiskLevel::Low))];
        let db = DatabaseName::new("app").unwrap();
        let env = Environment::new("production").unwrap();
        assert!(find_auto_approve(&entries, &db, &env).is_none());
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
    let step_approvals: Vec<&Approval> = approvals
        .iter()
        .filter(|a| a.step_index == step_index && a.action == ApprovalAction::Approve)
        .collect();

    // Admin override satisfies the entire step
    if step_approvals
        .iter()
        .any(|a| a.matched_selector == "admin_override")
    {
        return true;
    }

    match step.mode {
        WorkflowStepMode::All => step.approvers.iter().all(|ag| {
            let count = step_approvals
                .iter()
                .filter(|a| a.matched_selector == ag.selector.to_string())
                .count() as u32;
            count >= ag.min
        }),
        WorkflowStepMode::Any => step.approvers.iter().any(|ag| {
            let count = step_approvals
                .iter()
                .filter(|a| a.matched_selector == ag.selector.to_string())
                .count() as u32;
            count >= ag.min
        }),
    }
}

/// Check if all steps are satisfied.
pub fn all_steps_satisfied(steps: &[WorkflowStep], approvals: &[Approval]) -> bool {
    steps
        .iter()
        .enumerate()
        .all(|(i, step)| is_step_satisfied(step, i as u32, approvals))
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
            approvers: vec![ApproverGroup {
                selector: Selector::Role("dba".into()),
                min: 1,
            }],
            mode: WorkflowStepMode::Any,
        }];
        assert_eq!(find_current_step(&steps, &[]), 0);
    }

    #[test]
    fn single_step_satisfied() {
        let steps = vec![WorkflowStep {
            approvers: vec![ApproverGroup {
                selector: Selector::Role("dba".into()),
                min: 1,
            }],
            mode: WorkflowStepMode::Any,
        }];
        let approvals = vec![make_approval(0, "role:dba")];
        assert_eq!(find_current_step(&steps, &approvals), 1);
    }

    #[test]
    fn multi_step_partial() {
        let steps = vec![
            WorkflowStep {
                approvers: vec![ApproverGroup {
                    selector: Selector::Role("dba".into()),
                    min: 1,
                }],
                mode: WorkflowStepMode::Any,
            },
            WorkflowStep {
                approvers: vec![ApproverGroup {
                    selector: Selector::Role("cto".into()),
                    min: 1,
                }],
                mode: WorkflowStepMode::Any,
            },
        ];
        let approvals = vec![make_approval(0, "role:dba")];
        assert_eq!(find_current_step(&steps, &approvals), 1);
        assert!(!all_steps_satisfied(&steps, &approvals));
    }

    #[test]
    #[allow(clippy::useless_vec)]
    fn mode_all_requires_every_group() {
        let steps = vec![WorkflowStep {
            approvers: vec![
                ApproverGroup {
                    selector: Selector::Role("dba".into()),
                    min: 1,
                },
                ApproverGroup {
                    selector: Selector::Role("security".into()),
                    min: 1,
                },
            ],
            mode: WorkflowStepMode::All,
        }];
        let partial = vec![make_approval(0, "role:dba")];
        assert!(!is_step_satisfied(&steps[0], 0, &partial));

        let full = vec![
            make_approval(0, "role:dba"),
            make_approval(0, "role:security"),
        ];
        assert!(is_step_satisfied(&steps[0], 0, &full));
    }
}
