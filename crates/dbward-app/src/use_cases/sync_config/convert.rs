use dbward_domain::policies::{ApproverGroup, Workflow, WorkflowStep, WorkflowStepMode};
use dbward_domain::values::{DatabaseName, Environment, Operation, Selector};

use crate::error::AppError;

pub(super) fn parse_workflow(id: &str, wf: &super::WorkflowInput) -> Result<Workflow, AppError> {
    let db = if wf.database == "*" {
        DatabaseName::wildcard()
    } else {
        DatabaseName::new(&wf.database)
            .map_err(|e| AppError::Validation(format!("workflow db: {e}")))?
    };
    let env = if wf.environment == "*" {
        Environment::wildcard()
    } else {
        Environment::new(&wf.environment)
            .map_err(|e| AppError::Validation(format!("workflow env: {e}")))?
    };

    let mut operations: Vec<Operation> = Vec::new();
    for op_str in &wf.operations {
        let op = op_str
            .parse::<Operation>()
            .map_err(|e| AppError::Validation(format!("workflow {id}: {e}")))?;
        operations.push(op);
    }

    let mut steps: Vec<WorkflowStep> = Vec::new();
    for s in &wf.steps {
        let mode = match s.mode.as_str() {
            "any" => WorkflowStepMode::Any,
            "all" => WorkflowStepMode::All,
            other => {
                return Err(AppError::Validation(format!(
                    "workflow step: unknown mode '{other}' (expected 'any' or 'all')"
                )));
            }
        };
        let mut approvers = Vec::new();
        for a in &s.approvers {
            let selector = match a.selector_type.as_str() {
                "role" => Selector::Role(a.value.clone()),
                "group" => Selector::Group(a.value.clone()),
                "user" => Selector::User(a.value.clone()),
                other => {
                    return Err(AppError::Validation(format!(
                        "workflow step: unknown selector_type '{other}'"
                    )));
                }
            };
            approvers.push(ApproverGroup {
                selector,
                min: a.min,
            });
        }
        if approvers.is_empty() {
            return Err(AppError::Validation(format!(
                "workflow {}/{}: step has no valid approvers",
                wf.database, wf.environment
            )));
        }
        steps.push(WorkflowStep { approvers, mode });
    }

    Ok(Workflow {
        id: id.to_string(),
        database: db,
        environment: env,
        operations,
        steps,
        require_reason: wf.require_reason,
        allow_self_approve: wf.allow_self_approve,
        allow_same_approver_across_steps: wf.allow_same_approver_across_steps,
        explain: wf.explain,
        pending_ttl_secs: wf.pending_ttl_secs,
        statement_timeout_secs: wf.statement_timeout_secs,
        approval_ttl_secs: None,
        created_at: None,
        updated_at: None,
    })
}
