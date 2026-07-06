use dbward_config::server;
use dbward_domain::policies::{
    ApproverGroup, AutoApproveMode, AutoApproveSettings, Workflow, WorkflowStep, WorkflowStepMode,
};
use dbward_domain::services::workflow_validator;
use dbward_domain::values::{DatabaseName, Environment, Operation, Selector};

use super::{
    ApproverInput, DatabaseInput, ExecutionPolicyInput, GroupInput, NotificationPolicyInput,
    ResultPolicyInput, RoleInput, WebhookInput, WorkflowInput, WorkflowStepInput,
};
use crate::error::AppError;

fn convert_auto_approve_def(
    def: &Option<server::AutoApproveDef>,
) -> Result<Option<String>, AppError> {
    let Some(d) = def else { return Ok(None) };
    let settings = match d {
        server::AutoApproveDef::Always => AutoApproveSettings {
            mode: AutoApproveMode::Always,
            max_risk_level: None,
            allow_read_only: true,
            allow_safe_ddl: true,
            max_estimated_rows: 1000,
        },
        server::AutoApproveDef::RiskBased {
            risk,
            allow_read_only,
            allow_safe_ddl,
            max_estimated_rows,
        } => {
            use dbward_domain::services::risk_scorer::RiskLevel;
            let max_risk_level = match risk.as_str() {
                "low" => Some(RiskLevel::Low),
                "medium" => Some(RiskLevel::Medium),
                "high" => Some(RiskLevel::High),
                other => {
                    return Err(AppError::Internal(format!(
                        "invalid auto_approve risk '{other}' (should be caught by config validation)"
                    )));
                }
            };
            AutoApproveSettings {
                mode: AutoApproveMode::RiskBased,
                max_risk_level,
                allow_read_only: *allow_read_only,
                allow_safe_ddl: *allow_safe_ddl,
                max_estimated_rows: *max_estimated_rows,
            }
        }
    };
    serde_json::to_string(&settings)
        .map(Some)
        .map_err(|e| AppError::Internal(format!("serialize auto_approve: {e}")))
}

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

    // Validate steps for logical consistency
    if !steps.is_empty() {
        let issues =
            workflow_validator::validate_steps(&steps, wf.allow_same_approver_across_steps);
        for issue in &issues {
            match issue.severity {
                workflow_validator::Severity::Error => {
                    return Err(AppError::Validation(format!(
                        "workflow {}/{}: {}",
                        wf.database, wf.environment, issue.message
                    )));
                }
                workflow_validator::Severity::Warning => {
                    tracing::warn!(
                        workflow = %format!("{}/{}", wf.database, wf.environment),
                        "{}",
                        issue.message
                    );
                }
            }
        }
    }

    let auto_approve: Option<AutoApproveSettings> = wf
        .auto_approve_json
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map_err(|e| AppError::Internal(format!("parse auto_approve_json: {e}")))?;

    Ok(Workflow {
        id: id.to_string(),
        database: db,
        environment: env,
        operations,
        auto_approve,
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

pub fn databases_from_config(defs: &[server::DatabaseDef]) -> Vec<DatabaseInput> {
    defs.iter()
        .map(|d| DatabaseInput {
            name: d.name.clone(),
            environments: d.environments.clone(),
        })
        .collect()
}

pub fn groups_from_config(defs: &[server::GroupConfig]) -> Vec<GroupInput> {
    defs.iter()
        .map(|g| GroupInput {
            name: g.name.clone(),
        })
        .collect()
}

pub fn roles_from_config(defs: &[server::RoleConfig]) -> Vec<RoleInput> {
    defs.iter()
        .map(|r| RoleInput {
            name: r.name.clone(),
            permissions: r.permissions.clone(),
            databases: r.databases.clone(),
            environments: r.environments.clone(),
        })
        .collect()
}

pub fn webhooks_from_config(defs: &[server::WebhookDef]) -> Vec<WebhookInput> {
    defs.iter()
        .map(|wh| WebhookInput {
            id: wh.id.clone(),
            url: wh.url.clone(),
            events: wh.events.clone(),
            format: wh.format.clone(),
            secret: wh.secret.clone(),
        })
        .collect()
}

pub fn workflows_from_config(
    defs: &[server::WorkflowDef],
) -> Result<Vec<WorkflowInput>, crate::error::AppError> {
    defs.iter()
        .map(|wf| {
            let steps = wf
                .steps
                .iter()
                .enumerate()
                .map(|(step_idx, step_val)| {
                    let mode = step_val
                        .get("mode")
                        .and_then(|m| m.as_str())
                        .unwrap_or("all")
                        .to_string();
                    let approvers = step_val
                        .get("approvers")
                        .and_then(|a| a.as_array())
                        .map(|arr| {
                            arr.iter()
                                .enumerate()
                                .map(|(a_idx, a)| {
                                    let min =
                                        a.get("min").and_then(|m| m.as_u64()).unwrap_or(1) as u32;
                                    let (selector_type, value) = if let Some(role) =
                                        a.get("role").and_then(|r| r.as_str())
                                    {
                                        ("role", role)
                                    } else if let Some(group) =
                                        a.get("group").and_then(|g| g.as_str())
                                    {
                                        ("group", group)
                                    } else if let Some(user) =
                                        a.get("user").and_then(|u| u.as_str())
                                    {
                                        ("user", user)
                                    } else {
                                        return Err(crate::error::AppError::Validation(format!(
                                            "workflow '{}' step[{}].approvers[{}]: missing role/group/user selector",
                                            wf.database, step_idx, a_idx
                                        )));
                                    };
                                    Ok(ApproverInput {
                                        selector_type: selector_type.to_string(),
                                        value: value.to_string(),
                                        min,
                                    })
                                })
                                .collect::<Result<Vec<_>, _>>()
                        })
                        .transpose()?
                        .unwrap_or_default();
                    Ok(WorkflowStepInput { mode, approvers })
                })
                .collect::<Result<Vec<_>, crate::error::AppError>>()?;

            Ok(WorkflowInput {
                database: wf.database.clone(),
                environment: wf.environment.clone(),
                operations: wf.operations.clone(),
                auto_approve_json: convert_auto_approve_def(&wf.auto_approve)?,
                steps,
                require_reason: wf.require_reason,
                allow_self_approve: wf.allow_self_approve,
                allow_same_approver_across_steps: wf.allow_same_approver_across_steps,
                explain: wf.explain,
                pending_ttl_secs: wf.pending_ttl_secs,
                statement_timeout_secs: wf.statement_timeout_secs,
            })
        })
        .collect()
}

pub fn execution_policies_from_config(
    defs: &[server::ExecutionPolicyDef],
) -> Vec<ExecutionPolicyInput> {
    defs.iter()
        .map(|ep| ExecutionPolicyInput {
            database: ep.database.clone(),
            environment: ep.environment.clone(),
            max_executions: ep.max_executions,
            execution_window_secs: ep.execution_window_secs,
            retry_on_failure: ep.retry_on_failure,
            statement_timeout_secs: ep.statement_timeout_secs,
            max_statement_timeout_secs: ep.max_statement_timeout_secs,
            max_rows: ep.max_rows,
            migration_lease_duration_secs: ep.migration_lease_duration_secs,
            migration_statement_timeout_secs: ep.migration_statement_timeout_secs,
        })
        .collect()
}

pub fn sql_review_from_config(
    entries: &[server::SqlReviewEntry],
) -> Result<Vec<super::SqlReviewInput>, String> {
    use dbward_domain::services::sql_reviewer::{ReviewRules, RuleAction};

    fn parse_action(s: &str) -> Result<RuleAction, String> {
        match s {
            "block" => Ok(RuleAction::Block),
            "warn" => Ok(RuleAction::Warn),
            "off" => Ok(RuleAction::Off),
            _ => Err(format!("invalid rule action '{s}'")),
        }
    }

    entries
        .iter()
        .enumerate()
        .map(|(i, e)| {
            Ok(super::SqlReviewInput {
                database: e.database.clone(),
                environment: e.environment.clone(),
                rules: ReviewRules {
                    no_where_delete: parse_action(&e.no_where_delete)
                        .map_err(|err| format!("sql_review[{i}].no_where_delete: {err}"))?,
                    no_where_update: parse_action(&e.no_where_update)
                        .map_err(|err| format!("sql_review[{i}].no_where_update: {err}"))?,
                    drop_table: parse_action(&e.drop_table)
                        .map_err(|err| format!("sql_review[{i}].drop_table: {err}"))?,
                    drop_column: parse_action(&e.drop_column)
                        .map_err(|err| format!("sql_review[{i}].drop_column: {err}"))?,
                    not_null_without_default: parse_action(&e.not_null_without_default).map_err(
                        |err| format!("sql_review[{i}].not_null_without_default: {err}"),
                    )?,
                    create_index_not_concurrently: parse_action(&e.create_index_not_concurrently)
                        .map_err(|err| {
                        format!("sql_review[{i}].create_index_not_concurrently: {err}")
                    })?,
                    alter_column_type: parse_action(&e.alter_column_type)
                        .map_err(|err| format!("sql_review[{i}].alter_column_type: {err}"))?,
                    truncate: parse_action(&e.truncate)
                        .map_err(|err| format!("sql_review[{i}].truncate: {err}"))?,
                    mixed_ddl_dml: parse_action(&e.mixed_ddl_dml)
                        .map_err(|err| format!("sql_review[{i}].mixed_ddl_dml: {err}"))?,
                    large_in_list: parse_action(&e.large_in_list)
                        .map_err(|err| format!("sql_review[{i}].large_in_list: {err}"))?,
                },
            })
        })
        .collect()
}

pub fn result_policies_from_config(defs: &[server::ResultPolicyDef]) -> Vec<ResultPolicyInput> {
    defs.iter()
        .map(|rp| ResultPolicyInput {
            database: rp.database.clone(),
            environment: rp.environment.clone(),
            retention_days: rp.retention_days,
            delivery_mode: rp.delivery_mode.clone(),
            access: rp.access.clone(),
        })
        .collect()
}

pub fn notification_policies_from_config(
    defs: &[server::NotificationPolicyDef],
) -> Vec<NotificationPolicyInput> {
    defs.iter()
        .map(|np| NotificationPolicyInput {
            database: np.database.clone(),
            environment: np.environment.clone(),
            webhooks: np.webhooks.clone(),
            events: np.events.clone(),
        })
        .collect()
}
