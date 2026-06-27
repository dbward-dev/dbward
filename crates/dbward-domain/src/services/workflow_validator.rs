use std::collections::{HashMap, HashSet};

use crate::policies::workflow::{WorkflowStep, WorkflowStepMode};
use crate::values::Selector;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Debug, Clone)]
pub struct Issue {
    pub severity: Severity,
    pub step_index: Option<usize>,
    pub message: String,
}

/// Validate workflow steps for logical consistency.
/// Called by both `sync_config` (reject on Error) and `doctor` (report all).
pub fn validate_steps(
    steps: &[WorkflowStep],
    allow_same_approver_across_steps: bool,
) -> Vec<Issue> {
    let mut issues = vec![];

    for (i, step) in steps.iter().enumerate() {
        validate_step(&mut issues, i, step);
    }

    if !allow_same_approver_across_steps {
        check_cross_step_deadlock(&mut issues, steps);
    }

    issues
}

fn validate_step(issues: &mut Vec<Issue>, i: usize, step: &WorkflowStep) {
    for ag in &step.approvers {
        if ag.min == 0 {
            issues.push(Issue {
                severity: Severity::Error,
                step_index: Some(i),
                message: format!(
                    "step[{i}]: approver '{}' has min=0 (must be >= 1)",
                    ag.selector
                ),
            });
        }

        if matches!(ag.selector, Selector::Requester) {
            issues.push(Issue {
                severity: Severity::Error,
                step_index: Some(i),
                message: format!("step[{i}]: 'requester' cannot be used as approver selector"),
            });
        }

        // A specific user can only approve once per step → min > 1 is unsatisfiable
        if matches!(ag.selector, Selector::User(_)) && ag.min > 1 {
            issues.push(Issue {
                severity: Severity::Error,
                step_index: Some(i),
                message: format!(
                    "step[{i}]: approver '{}' has min={} but a single user can only approve once per step",
                    ag.selector, ag.min
                ),
            });
        }
    }

    // Duplicate selectors within same step (not a deadlock but confusing config)
    let mut seen = HashSet::new();
    for ag in &step.approvers {
        let key = ag.selector.to_string();
        if !seen.insert(key.clone()) {
            issues.push(Issue {
                severity: Severity::Warning,
                step_index: Some(i),
                message: format!(
                    "step[{i}]: duplicate selector '{key}' (approvals collapse onto same counter)"
                ),
            });
        }
    }

    // Empty approvers
    if step.approvers.is_empty() {
        let msg = match step.mode {
            WorkflowStepMode::Any => {
                format!("step[{i}]: empty approvers with mode=any (permanently unsatisfiable)")
            }
            WorkflowStepMode::All => {
                format!(
                    "step[{i}]: empty approvers with mode=all (vacuously satisfied — use no steps for auto-approve)"
                )
            }
        };
        issues.push(Issue {
            severity: Severity::Error,
            step_index: Some(i),
            message: msg,
        });
    }
}

fn check_cross_step_deadlock(issues: &mut Vec<Issue>, steps: &[WorkflowStep]) {
    // user:X in multiple steps → guaranteed deadlock (Error)
    let mut user_steps: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, step) in steps.iter().enumerate() {
        let mut seen_in_step = HashSet::new();
        for ag in &step.approvers {
            if let Selector::User(ref u) = ag.selector
                && seen_in_step.insert(u.as_str())
            {
                user_steps.entry(u.as_str()).or_default().push(i);
            }
        }
    }
    for (user, step_indices) in &user_steps {
        if step_indices.len() > 1 {
            issues.push(Issue {
                severity: Severity::Error,
                step_index: None,
                message: format!(
                    "user '{user}' appears in steps {step_indices:?} with allow_same_approver_across_steps=false (guaranteed deadlock)"
                ),
            });
        }
    }

    // role/group in multiple steps → potential deadlock (Warning)
    let mut selector_steps: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, step) in steps.iter().enumerate() {
        let mut seen_in_step = HashSet::new();
        for ag in &step.approvers {
            match &ag.selector {
                Selector::Role(_) | Selector::Group(_) => {
                    let key = ag.selector.to_string();
                    if seen_in_step.insert(key.clone()) {
                        selector_steps.entry(key).or_default().push(i);
                    }
                }
                _ => {}
            }
        }
    }
    for (sel, step_indices) in &selector_steps {
        if step_indices.len() > 1 {
            issues.push(Issue {
                severity: Severity::Warning,
                step_index: None,
                message: format!(
                    "'{sel}' appears in steps {step_indices:?} with allow_same_approver_across_steps=false (deadlock if only one member exists)"
                ),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policies::workflow::ApproverGroup;

    fn ag(selector: Selector, min: u32) -> ApproverGroup {
        ApproverGroup { selector, min }
    }

    fn step(approvers: Vec<ApproverGroup>, mode: WorkflowStepMode) -> WorkflowStep {
        WorkflowStep { approvers, mode }
    }

    #[test]
    fn min_zero_is_error() {
        let steps = vec![step(
            vec![ag(Selector::Role("dba".into()), 0)],
            WorkflowStepMode::All,
        )];
        let issues = validate_steps(&steps, false);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].severity, Severity::Error);
        assert!(issues[0].message.contains("min=0"));
    }

    #[test]
    fn duplicate_selector_is_warning() {
        let steps = vec![step(
            vec![
                ag(Selector::Role("dba".into()), 1),
                ag(Selector::Role("dba".into()), 2),
            ],
            WorkflowStepMode::All,
        )];
        let issues = validate_steps(&steps, false);
        assert!(
            issues
                .iter()
                .any(|i| i.severity == Severity::Warning && i.message.contains("duplicate"))
        );
    }

    #[test]
    fn requester_as_approver_is_error() {
        let steps = vec![step(
            vec![ag(Selector::Requester, 1)],
            WorkflowStepMode::All,
        )];
        let issues = validate_steps(&steps, false);
        assert!(
            issues
                .iter()
                .any(|i| i.severity == Severity::Error && i.message.contains("requester"))
        );
    }

    #[test]
    fn empty_approvers_any_is_error() {
        let steps = vec![step(vec![], WorkflowStepMode::Any)];
        let issues = validate_steps(&steps, false);
        assert!(
            issues
                .iter()
                .any(|i| i.severity == Severity::Error && i.message.contains("empty approvers"))
        );
    }

    #[test]
    fn empty_approvers_all_is_error() {
        let steps = vec![step(vec![], WorkflowStepMode::All)];
        let issues = validate_steps(&steps, false);
        assert!(
            issues
                .iter()
                .any(|i| i.severity == Severity::Error && i.message.contains("empty approvers"))
        );
    }

    #[test]
    fn user_cross_step_deadlock_is_error() {
        let steps = vec![
            step(
                vec![ag(Selector::User("alice".into()), 1)],
                WorkflowStepMode::All,
            ),
            step(
                vec![ag(Selector::User("alice".into()), 1)],
                WorkflowStepMode::All,
            ),
        ];
        let issues = validate_steps(&steps, false);
        assert!(issues.iter().any(|i| i.severity == Severity::Error && i.message.contains("guaranteed deadlock")));
    }

    #[test]
    fn user_cross_step_allowed_when_flag_true() {
        let steps = vec![
            step(
                vec![ag(Selector::User("alice".into()), 1)],
                WorkflowStepMode::All,
            ),
            step(
                vec![ag(Selector::User("alice".into()), 1)],
                WorkflowStepMode::All,
            ),
        ];
        let issues = validate_steps(&steps, true);
        assert!(issues.iter().all(|i| !i.message.contains("deadlock")));
    }

    #[test]
    fn role_cross_step_is_warning() {
        let steps = vec![
            step(
                vec![ag(Selector::Role("dba".into()), 1)],
                WorkflowStepMode::All,
            ),
            step(
                vec![ag(Selector::Role("dba".into()), 1)],
                WorkflowStepMode::All,
            ),
        ];
        let issues = validate_steps(&steps, false);
        assert!(
            issues
                .iter()
                .any(|i| i.severity == Severity::Warning && i.message.contains("role:dba"))
        );
    }

    #[test]
    fn group_cross_step_is_warning() {
        let steps = vec![
            step(
                vec![ag(Selector::Group("team".into()), 1)],
                WorkflowStepMode::All,
            ),
            step(
                vec![ag(Selector::Group("team".into()), 1)],
                WorkflowStepMode::All,
            ),
        ];
        let issues = validate_steps(&steps, false);
        assert!(
            issues
                .iter()
                .any(|i| i.severity == Severity::Warning && i.message.contains("group:team"))
        );
    }

    #[test]
    fn user_min_greater_than_one_is_error() {
        let steps = vec![step(
            vec![ag(Selector::User("alice".into()), 2)],
            WorkflowStepMode::All,
        )];
        let issues = validate_steps(&steps, false);
        assert!(
            issues
                .iter()
                .any(|i| i.severity == Severity::Error && i.message.contains("min=2"))
        );
    }

    #[test]
    fn valid_workflow_has_no_issues() {
        let steps = vec![
            step(
                vec![
                    ag(Selector::Role("dba".into()), 1),
                    ag(Selector::Role("security".into()), 1),
                ],
                WorkflowStepMode::All,
            ),
            step(
                vec![ag(Selector::User("cto".into()), 1)],
                WorkflowStepMode::Any,
            ),
        ];
        let issues = validate_steps(&steps, false);
        assert!(issues.is_empty());
    }
}
