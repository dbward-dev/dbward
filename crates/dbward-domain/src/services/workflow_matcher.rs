use crate::policies::Workflow;
use crate::policies::workflow::AutoApproveMode;
use crate::values::{DatabaseName, Environment, Operation};

/// Result of workflow evaluation for a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalDecision {
    /// Workflow requires human approval.
    NeedsApproval,
    /// Auto-approved with explicit reason.
    AutoApproved { reason: AutoApproveReason },
}

/// Why a request was auto-approved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutoApproveReason {
    /// Workflow has mode = "always".
    Always,
    /// Risk level is below threshold.
    RiskBased,
}

impl ApprovalDecision {
    /// Returns true if the request needs human approval.
    pub fn needs_approval(&self) -> bool {
        matches!(self, Self::NeedsApproval)
    }
}

pub use super::risk_scorer::RiskLevel;

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
pub fn evaluate(workflow: &Workflow, risk_level: Option<RiskLevel>) -> ApprovalDecision {
    // Always mode → unconditional auto-approve
    if let Some(ref aa) = workflow.auto_approve {
        match aa.mode {
            AutoApproveMode::Always => {
                return ApprovalDecision::AutoApproved {
                    reason: AutoApproveReason::Always,
                };
            }
            AutoApproveMode::RiskBased => {
                if let Some(max_level) = aa.max_risk_level
                    && let Some(level) = risk_level
                    && level != RiskLevel::Unknown
                    && level <= max_level
                {
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
    use crate::policies::workflow::{AutoApproveMode, AutoApproveSettings};
    use crate::policies::{ApproverGroup, WorkflowStep, WorkflowStepMode};
    use crate::values::Selector;

    fn wf(db: &str, env: &str, ops: Vec<Operation>, steps: Vec<WorkflowStep>) -> Workflow {
        Workflow {
            id: format!("{db}:{env}"),
            database: DatabaseName::new(db).unwrap(),
            environment: Environment::new(env).unwrap(),
            operations: ops,
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

    fn wf_with_aa(
        db: &str,
        env: &str,
        aa: AutoApproveSettings,
        steps: Vec<WorkflowStep>,
    ) -> Workflow {
        let mut w = wf(db, env, vec![], steps);
        w.auto_approve = Some(aa);
        w
    }

    fn aa_always() -> AutoApproveSettings {
        AutoApproveSettings {
            mode: AutoApproveMode::Always,
            max_risk_level: None,
            allow_read_only: true,
            allow_safe_ddl: true,
            max_estimated_rows: 1000,
        }
    }

    fn aa_risk(level: RiskLevel) -> AutoApproveSettings {
        AutoApproveSettings {
            mode: AutoApproveMode::RiskBased,
            max_risk_level: Some(level),
            allow_read_only: true,
            allow_safe_ddl: true,
            max_estimated_rows: 1000,
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
    fn always_mode_returns_auto_approved() {
        let w = wf_with_aa("*", "*", aa_always(), vec![]);
        let decision = evaluate(&w, None);
        assert_eq!(
            decision,
            ApprovalDecision::AutoApproved {
                reason: AutoApproveReason::Always
            }
        );
    }

    #[test]
    fn no_auto_approve_returns_needs_approval() {
        let w = wf("*", "*", vec![], vec![step()]);
        let decision = evaluate(&w, None);
        assert_eq!(decision, ApprovalDecision::NeedsApproval);
    }

    #[test]
    fn risk_based_auto_approve_low() {
        let w = wf_with_aa("*", "*", aa_risk(RiskLevel::Low), vec![step()]);
        let decision = evaluate(&w, Some(RiskLevel::Low));
        assert_eq!(
            decision,
            ApprovalDecision::AutoApproved {
                reason: AutoApproveReason::RiskBased
            }
        );
    }

    #[test]
    fn risk_above_threshold_needs_approval() {
        let w = wf_with_aa("*", "*", aa_risk(RiskLevel::Low), vec![step()]);
        let decision = evaluate(&w, Some(RiskLevel::Medium));
        assert_eq!(decision, ApprovalDecision::NeedsApproval);
    }

    #[test]
    fn unknown_risk_never_auto_approved() {
        let w = wf_with_aa("*", "*", aa_risk(RiskLevel::High), vec![step()]);
        let decision = evaluate(&w, Some(RiskLevel::Unknown));
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
}

// --- Step progression logic ---

use crate::entities::{Approval, ApprovalAction};
use crate::policies::workflow::{ApproverGroup, WorkflowStep, WorkflowStepMode};

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

/// Return unsatisfied approver groups with their remaining count.
/// For mode=all: groups where current < min.
/// For mode=any: all groups if none are satisfied, empty if any is satisfied.
pub fn unsatisfied_groups<'a>(
    step: &'a WorkflowStep,
    step_index: u32,
    approvals: &[Approval],
) -> Vec<(&'a ApproverGroup, u32)> {
    let step_approvals: Vec<&Approval> = approvals
        .iter()
        .filter(|a| a.step_index == step_index && a.action == ApprovalAction::Approve)
        .collect();

    match step.mode {
        WorkflowStepMode::All => step
            .approvers
            .iter()
            .filter_map(|ag| {
                let count = step_approvals
                    .iter()
                    .filter(|a| a.matched_selector == ag.selector.to_string())
                    .count() as u32;
                if count < ag.min {
                    Some((ag, ag.min - count))
                } else {
                    None
                }
            })
            .collect(),
        WorkflowStepMode::Any => {
            let any_satisfied = step.approvers.iter().any(|ag| {
                let count = step_approvals
                    .iter()
                    .filter(|a| a.matched_selector == ag.selector.to_string())
                    .count() as u32;
                count >= ag.min
            });
            if any_satisfied {
                vec![]
            } else {
                step.approvers
                    .iter()
                    .map(|ag| {
                        let count = step_approvals
                            .iter()
                            .filter(|a| a.matched_selector == ag.selector.to_string())
                            .count() as u32;
                        (ag, ag.min - count)
                    })
                    .collect()
            }
        }
    }
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

    #[test]
    fn unsatisfied_groups_mode_all_partial() {
        let step = WorkflowStep {
            approvers: vec![
                ApproverGroup {
                    selector: Selector::Role("dba".into()),
                    min: 1,
                },
                ApproverGroup {
                    selector: Selector::Role("cto".into()),
                    min: 1,
                },
            ],
            mode: WorkflowStepMode::All,
        };
        let partial = vec![make_approval(0, "role:dba")];
        let result = unsatisfied_groups(&step, 0, &partial);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0.selector.to_string(), "role:cto");
        assert_eq!(result[0].1, 1);
    }

    #[test]
    fn unsatisfied_groups_mode_all_fully_satisfied() {
        let step = WorkflowStep {
            approvers: vec![ApproverGroup {
                selector: Selector::Role("dba".into()),
                min: 1,
            }],
            mode: WorkflowStepMode::All,
        };
        let approvals = vec![make_approval(0, "role:dba")];
        assert!(unsatisfied_groups(&step, 0, &approvals).is_empty());
    }

    #[test]
    fn unsatisfied_groups_mode_any_one_satisfied() {
        let step = WorkflowStep {
            approvers: vec![
                ApproverGroup {
                    selector: Selector::Role("dba".into()),
                    min: 1,
                },
                ApproverGroup {
                    selector: Selector::Role("cto".into()),
                    min: 1,
                },
            ],
            mode: WorkflowStepMode::Any,
        };
        let approvals = vec![make_approval(0, "role:dba")];
        assert!(unsatisfied_groups(&step, 0, &approvals).is_empty());
    }

    #[test]
    fn unsatisfied_groups_mode_any_none_satisfied() {
        let step = WorkflowStep {
            approvers: vec![
                ApproverGroup {
                    selector: Selector::Role("dba".into()),
                    min: 1,
                },
                ApproverGroup {
                    selector: Selector::Role("cto".into()),
                    min: 1,
                },
            ],
            mode: WorkflowStepMode::Any,
        };
        let result = unsatisfied_groups(&step, 0, &[]);
        assert_eq!(result.len(), 2);
    }
}
