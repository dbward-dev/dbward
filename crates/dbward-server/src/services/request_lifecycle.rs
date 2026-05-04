use serde_json::json;

use crate::authz::{self, Action, Resource};
use crate::token::TokenSigner;

pub(crate) fn compute_next_step(
    steps: &[serde_json::Value],
    current_step_index: usize,
) -> Option<serde_json::Value> {
    steps.get(current_step_index).map(|step| {
        json!({
            "index": current_step_index,
            "approvers": step["approvers"]
        })
    })
}

pub(crate) struct ApproveResult {
    pub response: serde_json::Value,
    pub notif_hooks: Vec<crate::webhook::WebhookConfig>,
    pub webhook_event: Option<crate::webhook::WebhookEvent>,
}

pub(crate) async fn approve_request_inner(
    sqlite: &tokio::sync::Mutex<rusqlite::Connection>,
    token_signer: &TokenSigner,
    id: &str,
    approver: &crate::state::AuthUser,
    body_val: &serde_json::Value,
) -> Result<ApproveResult, crate::api_error::ApiError> {
    let mut conn = sqlite.lock().await;

    let ctx = crate::db::request_repo::get_request_context(&conn, id)
        .map_err(|_| crate::api_error::ApiError::not_found("request not found"))?;
    let (req_user, status, operation, environment, database_name, detail, workflow_snapshot_json) = (
        ctx.created_by,
        ctx.status,
        ctx.operation,
        ctx.environment,
        ctx.database_name,
        ctx.detail,
        ctx.workflow_snapshot_json,
    );

    if status != "pending" {
        return Err(crate::api_error::ApiError::conflict(format!(
            "request is already {status}"
        )));
    }

    // Parse workflow steps from snapshot
    let steps: Vec<crate::server_config::WorkflowStep> = workflow_snapshot_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();

    if steps.is_empty() {
        authz::authorize_sync(
            approver,
            Action::ApproveRequest,
            Resource::ApprovalStep {
                requester_id: req_user.clone(),
                allowed_roles: Vec::new(),
            },
        )?;
        let now = chrono::Utc::now().to_rfc3339();
        let tx = conn
            .transaction()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        crate::db::request_repo::mark_approved(&tx, id, &now)
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        crate::db::request_repo::insert_approval(
            &tx,
            id,
            "approve",
            &approver.user,
            0,
            approver.effective_permission(),
            &now,
        )
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.commit()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

        let token = token_signer.issue(id, &operation, &environment, &database_name, &detail);
        let notif_hooks =
            crate::db::policy_repo::get_notification_webhooks(&conn, &database_name, &environment);
        return Ok(ApproveResult {
            response: json!({"id": id, "status": "approved", "approved_by": approver.user, "execution_token": token}),
            notif_hooks,
            webhook_event: Some(crate::webhook::WebhookEvent {
                event: "request_approved".into(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                request_id: id.into(),
                status: "approved".into(),
                requester: req_user,
                actor: approver.user.clone(),
                actor_role: Some(approver.effective_permission().into()),
                operation,
                environment,
                detail,
                database: database_name,
                reason: None,
                next_step: None,
                cli_command: Some(format!("dbward resume {}", id)),
            }),
        });
    }

    // Read existing approvals
    let existing_approvals: Vec<(i64, String, String)> = {
        let mut stmt = conn.prepare(
            "SELECT step_index, actor_id, actor_role FROM approvals WHERE request_id = ?1 AND action = 'approve'"
        ).map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        stmt.query_map(rusqlite::params![id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?
        .filter_map(|r| r.ok())
        .collect()
    };

    // Calculate current step index (first unsatisfied step)
    let current_step = steps
        .iter()
        .enumerate()
        .find_map(|(i, step)| {
            if !is_step_satisfied(step, &existing_approvals, i as i64) {
                Some(i)
            } else {
                None
            }
        })
        .unwrap_or(steps.len());

    if current_step >= steps.len() {
        return Err(crate::api_error::ApiError::conflict(
            "all steps already satisfied",
        ));
    }

    let step = &steps[current_step];

    authz::authorize_sync(
        approver,
        Action::ApproveRequest,
        Resource::ApprovalStep {
            requester_id: req_user.clone(),
            allowed_roles: step
                .approvers
                .iter()
                .map(|group| group.role.clone())
                .collect(),
        },
    )?;

    // Determine approver's role
    let as_role = body_val
        .get("as_role")
        .and_then(|v| v.as_str())
        .map(String::from);
    let actor_role = if let Some(ref role) = as_role {
        if !approver.has_role(role) {
            return Err(crate::api_error::ApiError::forbidden(format!(
                "you do not have role '{role}'"
            )));
        }
        if !step.approvers.iter().any(|g| g.role == *role) {
            return Err(crate::api_error::ApiError::forbidden(format!(
                "role '{role}' is not an approver for current step"
            )));
        }
        role.clone()
    } else {
        let found = step.approvers.iter().find_map(|g| {
            if approver.has_role(&g.role) {
                Some(g.role.clone())
            } else {
                None
            }
        });
        found
            .or_else(|| {
                if approver.effective_permission() == "admin" {
                    step.approvers.first().map(|g| g.role.clone())
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                crate::api_error::ApiError::forbidden(
                    "you do not have a matching role for this step",
                )
            })?
    };

    if step.require_distinct_actors {
        // Distinct actors: same user cannot approve same step at all
        if existing_approvals
            .iter()
            .any(|(si, aid, _)| *si == current_step as i64 && aid == &approver.user)
        {
            return Err(crate::api_error::ApiError::conflict(
                "you already approved this step",
            ));
        }
    } else {
        // Non-distinct: same user cannot approve same step with the same role (prevent exact duplicates)
        if existing_approvals.iter().any(|(si, aid, role)| {
            *si == current_step as i64 && aid == &approver.user && role == &actor_role
        }) {
            return Err(crate::api_error::ApiError::conflict(
                "you already approved this step with this role",
            ));
        }
    }

    let now = chrono::Utc::now().to_rfc3339();
    let tx = conn
        .transaction()
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
    crate::db::request_repo::insert_approval(
        &tx,
        id,
        "approve",
        &approver.user,
        current_step as i64,
        &actor_role,
        &now,
    )
    .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

    let mut updated_approvals = existing_approvals.clone();
    updated_approvals.push((
        current_step as i64,
        approver.user.clone(),
        actor_role.clone(),
    ));

    let step_now_satisfied = is_step_satisfied(step, &updated_approvals, current_step as i64);
    let all_satisfied = step_now_satisfied
        && steps
            .iter()
            .enumerate()
            .all(|(i, s)| is_step_satisfied(s, &updated_approvals, i as i64));

    if all_satisfied {
        crate::db::request_repo::mark_approved(&tx, id, &now)
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.commit()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

        let token = token_signer.issue(id, &operation, &environment, &database_name, &detail);
        let notif_hooks =
            crate::db::policy_repo::get_notification_webhooks(&conn, &database_name, &environment);
        Ok(ApproveResult {
            response: json!({"id": id, "status": "approved", "approved_by": approver.user, "execution_token": token}),
            notif_hooks,
            webhook_event: Some(crate::webhook::WebhookEvent {
                event: "request_approved".into(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                request_id: id.into(),
                status: "approved".into(),
                requester: req_user,
                actor: approver.user.clone(),
                actor_role: Some(actor_role.clone()),
                operation,
                environment,
                detail,
                database: database_name,
                reason: None,
                next_step: None,
                cli_command: Some(format!("dbward resume {}", id)),
            }),
        })
    } else {
        crate::db::request_repo::touch_updated_at(&tx, id, &now)
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.commit()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

        let notif_hooks =
            crate::db::policy_repo::get_notification_webhooks(&conn, &database_name, &environment);

        let new_current = steps
            .iter()
            .enumerate()
            .find_map(|(i, s)| {
                if !is_step_satisfied(s, &updated_approvals, i as i64) {
                    Some(i)
                } else {
                    None
                }
            })
            .unwrap_or(steps.len());

        let webhook_event = if step_now_satisfied {
            let steps_json_val: Vec<serde_json::Value> = workflow_snapshot_json
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default();
            let next_step = compute_next_step(&steps_json_val, new_current);
            Some(crate::webhook::WebhookEvent {
                event: "step_approved".into(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                request_id: id.into(),
                status: "pending".into(),
                requester: req_user,
                actor: approver.user.clone(),
                actor_role: Some(actor_role.clone()),
                operation: operation.clone(),
                environment: environment.clone(),
                detail: detail.clone(),
                database: database_name.clone(),
                reason: None,
                next_step,
                cli_command: Some(format!("dbward approve {}", id)),
            })
        } else {
            None
        };

        Ok(ApproveResult {
            response: json!({
                "id": id, "status": "pending",
                "step_completed": current_step, "current_step": new_current,
                "total_steps": steps.len(),
                "message": format!("Step {}/{} approved. Waiting for further approvals.", current_step + 1, steps.len()),
            }),
            notif_hooks,
            webhook_event,
        })
    }
}

pub(crate) fn is_step_satisfied(
    step: &crate::server_config::WorkflowStep,
    approvals: &[(i64, String, String)],
    step_index: i64,
) -> bool {
    let step_approvals: Vec<&(i64, String, String)> = approvals
        .iter()
        .filter(|(si, _, _)| *si == step_index)
        .collect();

    match step.mode.as_str() {
        "any" => step.approvers.iter().any(|g| {
            step_approvals
                .iter()
                .filter(|(_, _, role)| role == &g.role)
                .count()
                >= g.min as usize
        }),
        _ => step.approvers.iter().all(|g| {
            step_approvals
                .iter()
                .filter(|(_, _, role)| role == &g.role)
                .count()
                >= g.min as usize
        }),
    }
}
