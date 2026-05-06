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

pub(crate) fn approver_key(group: &crate::server_config::ApproverGroup) -> Option<String> {
    group
        .role
        .as_ref()
        .map(|role| format!("role:{role}"))
        .or_else(|| group.group.as_ref().map(|grp| format!("group:{grp}")))
}

pub(crate) fn step_allowed_roles_groups(
    step: &crate::server_config::WorkflowStep,
) -> (Vec<String>, Vec<String>) {
    (
        step.approvers
            .iter()
            .filter_map(|group| group.role.clone())
            .collect(),
        step.approvers
            .iter()
            .filter_map(|group| group.group.clone())
            .collect(),
    )
}

pub(crate) async fn approve_request_inner(
    sqlite: &tokio::sync::Mutex<rusqlite::Connection>,
    token_signer: &TokenSigner,
    id: &str,
    approver: &crate::state::AuthUser,
    body_val: &serde_json::Value,
) -> Result<ApproveResult, crate::api_error::ApiError> {
    let mut conn = sqlite.lock().await;
    let comment = body_val
        .get("comment")
        .and_then(|v| v.as_str())
        .filter(|v| !v.is_empty());

    let ctx = crate::db::request_repo::get_request_context(&conn, id)
        .map_err(|_| crate::api_error::ApiError::not_found("request not found"))?;
    let (
        req_user,
        status,
        operation,
        environment,
        database_name,
        detail,
        workflow_id,
        workflow_snapshot_json,
    ) = (
        ctx.created_by,
        ctx.status,
        ctx.operation,
        ctx.environment,
        ctx.database_name,
        ctx.detail,
        ctx.workflow_id,
        ctx.workflow_snapshot_json,
    );

    if status != "pending" {
        return Err(
            crate::api_error::ApiError::conflict(format!("request is already {status}"))
                .with_code("request_approve_wrong_status"),
        );
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
                allowed_groups: vec![],
            },
        )?;
        let now = chrono::Utc::now().to_rfc3339();
        let tx = conn
            .transaction()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        if !crate::db::request_repo::mark_approved_dispatched(&tx, id, &now)
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?
        {
            return Err(crate::api_error::ApiError::conflict(
                "request state changed during approval",
            )
            .with_code("request_approve_wrong_status"));
        }
        crate::db::request_repo::insert_approval(
            &tx,
            id,
            "approve",
            &approver.user,
            0,
            approver.effective_permission(),
            comment,
            &now,
        )
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;
        tx.commit()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

        let token = token_signer.issue(id, &operation, &environment, &database_name, &detail);
        let notif_hooks =
            crate::db::policy_repo::get_notification_webhooks(&conn, &database_name, &environment);
        return Ok(ApproveResult {
            response: json!({"id": id, "status": "dispatched", "approved_by": approver.user, "step_completed": 0, "current_step": 0, "total_steps": 0, "message": "Approved and dispatched.", "execution_token": token}),
            notif_hooks,
            webhook_event: Some(crate::webhook::WebhookEvent {
                event: "request_approved".into(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                request_id: id.into(),
                status: "dispatched".into(),
                requester: req_user,
                actor: approver.user.clone(),
                actor_role: Some(approver.effective_permission().into()),
                operation,
                environment,
                detail,
                database: database_name,
                reason: None,
                next_step: None,
                cli_command: Some(format!("dbward request resume {}", id)),
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
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?
    };

    // Check cross-step distinct approver constraint
    let allow_same = workflow_id
        .as_deref()
        .and_then(|workflow_id| {
            conn.query_row(
                "SELECT allow_same_approver_across_steps FROM workflows WHERE id = ?1",
                rusqlite::params![workflow_id],
                |row| row.get::<_, bool>(0),
            )
            .ok()
        })
        .unwrap_or(false);

    if !allow_same
        && existing_approvals
            .iter()
            .any(|(_, aid, _)| aid == &approver.user)
    {
        return Err(crate::api_error::ApiError::forbidden(
            "you already approved a previous step of this request",
        )
        .with_code("same_approver_across_steps"));
    }

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
        return Err(
            crate::api_error::ApiError::conflict("all steps already satisfied")
                .with_code("all_steps_already_satisfied"),
        );
    }

    let step = &steps[current_step];

    let (allowed_roles, allowed_groups) = step_allowed_roles_groups(step);
    authz::authorize_sync(
        approver,
        Action::ApproveRequest,
        Resource::ApprovalStep {
            requester_id: req_user.clone(),
            allowed_roles,
            allowed_groups,
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
            ))
            .with_code("as_role_not_held"));
        }
        if !step
            .approvers
            .iter()
            .any(|g| g.role.as_deref() == Some(role))
        {
            return Err(crate::api_error::ApiError::forbidden(format!(
                "role '{role}' is not an approver for current step"
            ))
            .with_code("as_role_not_allowed_for_step"));
        }
        format!("role:{role}")
    } else {
        let found = step.approvers.iter().find_map(|g| {
            if let Some(ref r) = g.role
                && approver.has_role(r)
            {
                return Some(format!("role:{r}"));
            }
            if let Some(ref grp) = g.group
                && approver.groups.contains(grp)
            {
                return Some(format!("group:{grp}"));
            }
            None
        });
        found.ok_or_else(|| {
            crate::api_error::ApiError::forbidden(
                "you do not have a matching role or group for this step",
            )
            .with_code("no_matching_approver_role")
        })?
    };

    if step.require_distinct_actors {
        // Distinct actors: same user cannot approve same step at all
        if existing_approvals
            .iter()
            .any(|(si, aid, _)| *si == current_step as i64 && aid == &approver.user)
        {
            return Err(
                crate::api_error::ApiError::conflict("you already approved this step")
                    .with_code("already_approved_step"),
            );
        }
    } else {
        // Non-distinct: same user cannot approve same step with the same role (prevent exact duplicates)
        if existing_approvals.iter().any(|(si, aid, role)| {
            *si == current_step as i64 && aid == &approver.user && role == &actor_role
        }) {
            return Err(crate::api_error::ApiError::conflict(
                "you already approved this step with this role",
            )
            .with_code("already_approved_role"));
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
        comment,
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
        if !crate::db::request_repo::mark_approved_dispatched(&tx, id, &now)
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?
        {
            return Err(crate::api_error::ApiError::conflict(
                "request state changed during approval",
            )
            .with_code("request_approve_wrong_status"));
        }
        tx.commit()
            .map_err(|e| crate::api_error::ApiError::internal(e.to_string()))?;

        let token = token_signer.issue(id, &operation, &environment, &database_name, &detail);
        let notif_hooks =
            crate::db::policy_repo::get_notification_webhooks(&conn, &database_name, &environment);
        Ok(ApproveResult {
            response: json!({"id": id, "status": "dispatched", "approved_by": approver.user, "step_completed": current_step, "current_step": steps.len(), "total_steps": steps.len(), "message": format!("Step {}/{} approved. All steps complete; request dispatched.", current_step + 1, steps.len()), "execution_token": token}),
            notif_hooks,
            webhook_event: Some(crate::webhook::WebhookEvent {
                event: "request_approved".into(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                request_id: id.into(),
                status: "dispatched".into(),
                requester: req_user,
                actor: approver.user.clone(),
                actor_role: Some(actor_role.clone()),
                operation,
                environment,
                detail,
                database: database_name,
                reason: None,
                next_step: None,
                cli_command: Some(format!("dbward request resume {}", id)),
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
                cli_command: Some(format!("dbward request approve {}", id)),
            })
        } else {
            None
        };

        Ok(ApproveResult {
            response: json!({
                "id": id, "status": "pending",
                "approved_by": approver.user,
                "step_completed": current_step, "current_step": new_current,
                "total_steps": steps.len(),
                "message": format!("Step {}/{} approved. Waiting for further approvals.", current_step + 1, steps.len()),
                "execution_token": null,
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
            approver_key(g).is_some_and(|key| {
                step_approvals
                    .iter()
                    .filter(|(_, _, role)| *role == key)
                    .count()
                    >= g.min as usize
            })
        }),
        _ => step.approvers.iter().all(|g| {
            approver_key(g).is_some_and(|key| {
                step_approvals
                    .iter()
                    .filter(|(_, _, role)| *role == key)
                    .count()
                    >= g.min as usize
            })
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::db::request_repo::NewRequest;
    use crate::state::{AppState, ResultChannels};
    use crate::token::TokenSigner;
    use rusqlite::Connection;
    use std::sync::Arc;

    fn test_state() -> AppState {
        let conn = Connection::open_in_memory().unwrap();
        db::init(&conn).unwrap();
        AppState {
            sqlite: Arc::new(tokio::sync::Mutex::new(conn)),
            token_signer: Arc::new(TokenSigner::generate()),
            webhooks: Arc::new(crate::webhook::WebhookDispatcher::empty()),
            metrics: Arc::new(crate::Metrics::new()),
            oidc: None,
            auth_mode: "token".to_string(),
            policy: Arc::new(Default::default()),
            result_channels: Arc::new(ResultChannels::new()),
            retention: Default::default(),
            request_notifier: Arc::new(crate::state::RequestNotifier::new()),
            result_store: None,
            draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            break_glass_roles: crate::server_config::default_break_glass_roles(),
        }
    }

    fn approver(user: &str, roles: &[&str], groups: &[&str]) -> crate::state::AuthUser {
        crate::state::AuthUser {
            token_id: format!("oidc:{user}"),
            user: user.into(),
            roles: roles.iter().map(|role| (*role).to_string()).collect(),
            groups: groups.iter().map(|group| (*group).to_string()).collect(),
            subject_type: "user".into(),
        }
    }

    async fn insert_pending_request(state: &AppState, id: &str, workflow_snapshot_json: &str) {
        let conn = state.sqlite.lock().await;
        db::request_repo::insert_request(
            &conn,
            &NewRequest {
                id,
                created_by: "alice",
                operation: "execute_query",
                environment: "production",
                database_name: "app",
                detail: "SELECT 1",
                status: "pending",
                emergency: false,
                reason: None,
                workflow_id: Some("wf"),
                workflow_snapshot_json: Some(workflow_snapshot_json),
                share_with_json: None,
            },
            "2026-01-01T00:00:00Z",
        )
        .unwrap();
    }

    async fn insert_workflow(
        state: &AppState,
        id: &str,
        allow_same_approver_across_steps: bool,
        database: &str,
        environment: &str,
    ) {
        let conn = state.sqlite.lock().await;
        conn.execute(
            "INSERT INTO workflows (id, database_name, environment, operations_json, steps_json, require_reason, allow_same_approver_across_steps, source, created_at, updated_at)
             VALUES (?1, ?2, ?3, '[]', '[]', 0, ?4, 'api', 't1', 't1')",
            rusqlite::params![
                id,
                database,
                environment,
                allow_same_approver_across_steps
            ],
        )
        .unwrap();
    }

    #[tokio::test]
    async fn group_approval_records_group_selector() {
        crate::authz::warmup().await.unwrap();
        let state = test_state();
        let request_id = "8c5e16c4-4f9d-4d8f-b983-d4cd6dfd4411";
        insert_pending_request(
            &state,
            request_id,
            r#"[{"type":"approval","mode":"all","approvers":[{"group":"prod-approvers","min":1}],"require_distinct_actors":true}]"#,
        )
        .await;

        let result = approve_request_inner(
            &state.sqlite,
            state.token_signer.as_ref(),
            request_id,
            &approver("bob", &["team-a"], &["prod-approvers"]),
            &json!({}),
        )
        .await
        .unwrap();

        assert_eq!(result.response["status"], "dispatched");

        let conn = state.sqlite.lock().await;
        let rows = db::request_repo::get_approvals(&conn, request_id).unwrap();
        assert_eq!(rows, vec![(0, "bob".into(), "group:prod-approvers".into())]);
    }

    #[test]
    fn is_step_satisfied_distinguishes_role_and_group_with_same_name() {
        let step = crate::server_config::WorkflowStep {
            step_type: "approval".into(),
            mode: "all".into(),
            approvers: vec![
                crate::server_config::ApproverGroup {
                    role: Some("ops".into()),
                    group: None,
                    min: 1,
                },
                crate::server_config::ApproverGroup {
                    role: None,
                    group: Some("ops".into()),
                    min: 1,
                },
            ],
            require_distinct_actors: true,
        };

        assert!(!is_step_satisfied(
            &step,
            &[(0, "bob".into(), "group:ops".into())],
            0,
        ));
        assert!(is_step_satisfied(
            &step,
            &[
                (0, "bob".into(), "group:ops".into()),
                (0, "carol".into(), "role:ops".into()),
            ],
            0,
        ));
    }

    #[tokio::test]
    async fn same_approver_across_steps_returns_specific_error() {
        crate::authz::warmup().await.unwrap();
        let state = test_state();
        let request_id = "7416f20b-ecdc-4efb-8c84-a14ca553a4e5";
        insert_workflow(&state, "wf", false, "app", "production").await;
        insert_pending_request(
            &state,
            request_id,
            r#"[{"type":"approval","mode":"all","approvers":[{"role":"team-lead","min":1}],"require_distinct_actors":true},{"type":"approval","mode":"all","approvers":[{"role":"dba","min":1}],"require_distinct_actors":true}]"#,
        )
        .await;

        approve_request_inner(
            &state.sqlite,
            state.token_signer.as_ref(),
            request_id,
            &approver("bob", &["team-lead", "dba"], &[]),
            &json!({}),
        )
        .await
        .unwrap();

        let err = match approve_request_inner(
            &state.sqlite,
            state.token_signer.as_ref(),
            request_id,
            &approver("bob", &["team-lead", "dba"], &[]),
            &json!({}),
        )
        .await
        {
            Ok(_) => panic!("expected same approver to be rejected on second step"),
            Err(err) => err,
        };

        assert_eq!(err.status, axum::http::StatusCode::FORBIDDEN);
        assert_eq!(err.code.as_deref(), Some("same_approver_across_steps"));
        assert_eq!(
            err.error,
            "you already approved a previous step of this request"
        );
    }

    #[tokio::test]
    async fn allow_same_approver_uses_request_workflow_id_not_wildcard_lookup() {
        crate::authz::warmup().await.unwrap();
        let state = test_state();
        let request_id = "a4f7053f-b867-4d4d-9c4a-f65c4ba0acd7";
        insert_workflow(&state, "wf", true, "app", "production").await;
        insert_workflow(&state, "conflicting", false, "app", "*").await;
        insert_pending_request(
            &state,
            request_id,
            r#"[{"type":"approval","mode":"all","approvers":[{"role":"admin","min":1}],"require_distinct_actors":true},{"type":"approval","mode":"all","approvers":[{"role":"admin","min":1}],"require_distinct_actors":true}]"#,
        )
        .await;

        let first = approve_request_inner(
            &state.sqlite,
            state.token_signer.as_ref(),
            request_id,
            &approver("admin-1", &["admin"], &[]),
            &json!({}),
        )
        .await
        .unwrap();
        assert_eq!(first.response["status"], "pending");

        let second = approve_request_inner(
            &state.sqlite,
            state.token_signer.as_ref(),
            request_id,
            &approver("admin-1", &["admin"], &[]),
            &json!({}),
        )
        .await
        .unwrap();
        assert_eq!(second.response["status"], "dispatched");
    }
}
