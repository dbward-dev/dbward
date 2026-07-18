use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission, ResourceContext};
use dbward_domain::entities::{Approval, ApprovalAction, RequestStatus};
use dbward_domain::policies::workflow::Workflow;
use dbward_domain::services::status_machine::{
    self, EventMetadata, RequestTrigger, TransitionContext,
};
use dbward_domain::services::{approval_checker, workflow_matcher};

use crate::error::{AppError, AuthzError};
use crate::ports::*;

pub struct ApproveRequest {
    pub authorizer: Arc<dyn Authorizer>,
    pub request_reader: Arc<dyn RequestReader>,
    pub approval_repo: Arc<dyn ApprovalRepo>,
    pub uow: Arc<dyn UnitOfWork>,
    pub notifier: Arc<dyn Notifier>,
    pub clock: Arc<dyn Clock>,
    pub id_gen: Arc<dyn IdGenerator>,
}

pub struct ApproveRequestInput {
    pub request_id: String,
    pub comment: Option<String>,
    pub selector: Option<String>,
}

pub struct ApproveRequestOutput {
    pub id: String,
    pub status: RequestStatus,
    pub approved_by: String,
    pub matched_selector: String,
    pub step_completed: u32,
    pub current_step: u32,
    pub total_steps: u32,
}

impl ApproveRequest {
    pub fn execute(
        &self,
        input: ApproveRequestInput,
        user: &AuthUser,
        ctx: &dbward_domain::entities::AuditContext,
    ) -> Result<ApproveRequestOutput, AppError> {
        // 0. Input validation
        if let Some(ref c) = input.comment
            && c.len() > 1024
        {
            return Err(AppError::Validation(
                "comment too long (max 1024 bytes)".into(),
            ));
        }

        // 1. Get request
        let request = self
            .request_reader
            .get(&input.request_id)?
            .ok_or_else(|| AppError::NotFound("request not found".into()))?;

        // 2. Status check
        if request.status != RequestStatus::Pending {
            return Err(AppError::Conflict(format!(
                "request is {}, expected pending",
                request.status.as_str()
            )));
        }

        // 2b. Expiry check (enforce even if background job hasn't run yet)
        let now = self.clock.now();
        if let Some(expires_at) = request.expires_at
            && now >= expires_at
        {
            return Err(AppError::Gone(
                    "request has expired. Hint: set pending_ttl_secs in your workflow configuration to increase the approval window".into(),
                ));
        }

        // 3. Parse workflow snapshot (fail-closed: all pending requests have a workflow)
        let workflow: Workflow = request
            .workflow_snapshot_json
            .as_deref()
            .map(|json| {
                serde_json::from_str(json)
                    .map_err(|e| AppError::Internal(format!("corrupt workflow snapshot: {e}")))
            })
            .transpose()?
            .ok_or_else(|| AppError::Conflict("request has no approval workflow".into()))?;

        // 4. Get existing approvals
        let approvals = self.approval_repo.get_approvals(&request.id)?;

        // 5. Determine current step
        let current_step_index = workflow_matcher::find_current_step(&workflow.steps, &approvals);
        let total_steps = workflow.steps.len() as u32;

        if current_step_index >= total_steps {
            return Err(AppError::Conflict("all steps already satisfied".into()));
        }

        let step = &workflow.steps[current_step_index as usize];

        // 6. Authorization: fully delegated to Authorizer
        let previous_approver_ids: Vec<String> = approvals
            .iter()
            .filter(|a| a.step_index < current_step_index && a.action == ApprovalAction::Approve)
            .map(|a| a.actor_id.clone())
            .collect();

        self.authorizer
            .authorize_approval(
                user,
                &request.database,
                &request.environment,
                &ResourceContext::ApprovalStep {
                    requester_id: request.requester.clone(),
                    step_index: current_step_index,
                    approvers: step.approvers.clone(),
                    allow_self_approve: workflow.allow_self_approve,
                    allow_same_approver_across_steps: workflow.allow_same_approver_across_steps,
                    previous_approver_ids: previous_approver_ids.clone(),
                },
            )
            .map_err(AppError::Forbidden)?;

        // 9. Check distinct actors within same step (fast-fail before TX)
        let already_approved_this_step = approvals.iter().any(|a| {
            a.step_index == current_step_index
                && a.actor_id == user.subject_id
                && a.action == ApprovalAction::Approve
        });
        if already_approved_this_step {
            return Err(AppError::Conflict("already approved this step".into()));
        }

        // Pre-generate approval ID before entering TX
        let approval_id = self.id_gen.generate();

        // Atomic: approval + in-TX recheck + optional status change + audit (Phase 2b)
        let request_id = request.id.clone();
        let request_db = request.database.clone();
        let request_env = request.environment.clone();
        let request_requester = request.requester.clone();
        let request_op = request.operation;
        let wf_allow_self = workflow.allow_self_approve;
        let wf_allow_cross = workflow.allow_same_approver_across_steps;
        let wf_steps = workflow.steps.clone();
        let user_id = user.subject_id.clone();
        let user_type = user.subject_type;
        let user_roles: Vec<String> = user.roles.iter().map(|r| r.name.clone()).collect();
        let user_groups = user.groups.clone();
        let audit_ctx = ctx.clone();
        let comment_clone = input.comment.clone();
        let requested_selector = input.selector.clone();

        let clock = self.clock.clone();

        let tx_result = crate::ports::transaction::uow_execute(self.uow.as_ref(), |tx| {
            // Acquire authoritative time INSIDE the TX (after lock is held).
            // Prevents stale clock if BEGIN IMMEDIATE waited on busy_timeout.
            let now = clock.now();

            // Re-check status + expiry inside TX (authoritative)
            let state = tx.get_request_state(&request_id)?;
            let (status, expires_at) =
                state.ok_or_else(|| AppError::NotFound("request not found".into()))?;
            if status != RequestStatus::Pending {
                return Err(AppError::Conflict(format!(
                    "request is {}, expected pending",
                    status.as_str()
                )));
            }
            if let Some(ea) = expires_at
                && now >= ea
            {
                return Err(AppError::Gone("request has expired".into()));
            }

            // Re-fetch approvals inside TX
            let approvals = tx.get_approvals(&request_id)?;
            let current_step_index = workflow_matcher::find_current_step(&wf_steps, &approvals);
            let total_steps = wf_steps.len() as u32;

            if current_step_index >= total_steps {
                return Err(AppError::Conflict("all steps already satisfied".into()));
            }

            let step = &wf_steps[current_step_index as usize];

            // Re-check approvability
            let previous_approver_ids: Vec<String> = approvals
                .iter()
                .filter(|a| {
                    a.step_index < current_step_index && a.action == ApprovalAction::Approve
                })
                .map(|a| a.actor_id.clone())
                .collect();

            if !approval_checker::is_approvable_by_attrs(
                &user_id,
                &user_roles,
                &user_groups,
                step.approvers.as_slice(),
                &request_requester,
                &previous_approver_ids,
                wf_allow_self,
                wf_allow_cross,
            ) {
                return Err(AppError::Forbidden(AuthzError::Forbidden {
                    permission: Permission::RequestView,
                    reason: "not eligible to approve this step (recheck)".into(),
                }));
            }

            // Re-check already approved this step
            let already = approvals.iter().any(|a| {
                a.step_index == current_step_index
                    && a.actor_id == user_id
                    && a.action == ApprovalAction::Approve
            });
            if already {
                return Err(AppError::Conflict("already approved this step".into()));
            }

            // Find matched selector (Phase 2a: selector choice)
            let all_matched = approval_checker::matched_selectors_by_attrs(
                &user_roles,
                &user_groups,
                &user_id,
                &step.approvers,
            );

            let matched_selector = if let Some(ref requested) = requested_selector {
                // User explicitly specified a selector
                if !all_matched.contains(requested) {
                    return Err(AppError::Validation(format!(
                        "you do not match selector '{requested}'"
                    )));
                }
                // Check if that selector is already satisfied
                let count = approvals
                    .iter()
                    .filter(|a| {
                        a.step_index == current_step_index
                            && a.action == ApprovalAction::Approve
                            && a.matched_selector == *requested
                    })
                    .count() as u32;
                let required = step
                    .approvers
                    .iter()
                    .find(|ag| ag.selector.to_string() == *requested)
                    .map(|ag| ag.min)
                    .unwrap_or(1);
                if count >= required {
                    return Err(AppError::Conflict(format!(
                        "selector '{}' is already satisfied for this step ({}/{})",
                        requested, count, required
                    )));
                }
                requested.clone()
            } else {
                // Auto-select
                match all_matched.len() {
                    0 => {
                        return Err(AppError::Forbidden(AuthzError::Forbidden {
                            permission: Permission::RequestView,
                            reason: "not eligible to approve this step".into(),
                        }));
                    }
                    _ => {
                        // Filter to unsatisfied only
                        let unsatisfied: Vec<String> = all_matched
                            .iter()
                            .filter(|sel| {
                                let count = approvals
                                    .iter()
                                    .filter(|a| {
                                        a.step_index == current_step_index
                                            && a.action == ApprovalAction::Approve
                                            && &a.matched_selector == *sel
                                    })
                                    .count() as u32;
                                let required = step
                                    .approvers
                                    .iter()
                                    .find(|ag| ag.selector.to_string() == **sel)
                                    .map(|ag| ag.min)
                                    .unwrap_or(1);
                                count < required
                            })
                            .cloned()
                            .collect();

                        match unsatisfied.len() {
                            0 => {
                                return Err(AppError::Conflict(
                                    "all approver groups you match are already satisfied".into(),
                                ));
                            }
                            1 => unsatisfied.into_iter().next().expect("len==1"),
                            _ => {
                                return Err(AppError::Validation(format!(
                                    "ambiguous: you match multiple unsatisfied approver groups: {}. Specify 'selector' parameter to choose.",
                                    unsatisfied.join(", ")
                                )));
                            }
                        }
                    }
                }
            };

            // Build approval
            let approval = Approval {
                id: approval_id.clone(),
                request_id: request_id.clone(),
                action: ApprovalAction::Approve,
                actor_id: user_id.clone(),
                matched_selector: matched_selector.clone(),
                step_index: current_step_index,
                comment: comment_clone.clone(),
                created_at: now,
            };

            // Check satisfaction
            let mut all_approvals = approvals;
            all_approvals.push(approval.clone());
            let all_satisfied = workflow_matcher::all_steps_satisfied(&wf_steps, &all_approvals);

            let step_completed = if all_satisfied {
                total_steps
            } else {
                workflow_matcher::find_current_step(&wf_steps, &all_approvals)
            };

            let trigger = if all_satisfied {
                RequestTrigger::ApproveFinal
            } else {
                RequestTrigger::ApproveStep
            };

            let result = status_machine::transition(
                status,
                &trigger,
                TransitionContext {
                    request_id: request_id.clone(),
                    actor_id: user_id.clone(),
                    actor_type: user_type,
                    database: request_db.clone(),
                    environment: request_env.clone(),
                    operation: request_op,
                    timestamp: now,
                    metadata: if all_satisfied {
                        EventMetadata::Approved {
                            comment: comment_clone,
                            matched_selector: matched_selector.clone(),
                        }
                    } else {
                        EventMetadata::StepApproved {
                            step_index: current_step_index,
                            total_steps,
                            comment: comment_clone,
                            matched_selector: matched_selector.clone(),
                        }
                    },
                    requester_id: request_requester.clone(),
                    audit_context: audit_ctx,
                    auth_token_id: None,
                },
            )
            .map_err(|e| AppError::Conflict(e.to_string()))?;

            let new_status = result.status();
            let event = result.into_event();
            let audit_event = crate::services::audit_event_builder::build_audit_event(
                &event,
                now,
                crate::services::audit_event_builder::RedactionMode::default(),
                crate::services::audit_event_builder::noop_redact,
            );

            tx.insert_approval(&approval)?;
            if all_satisfied {
                let ok = tx.mark_approved(&request_id, now)?;
                if !ok {
                    return Err(AppError::Conflict(
                        "concurrent status change or expired".into(),
                    ));
                }
            }
            tx.record(&audit_event)?;

            Ok((
                new_status,
                matched_selector,
                step_completed,
                total_steps,
                event,
            ))
        })?;

        let (new_status, matched_selector, step_completed, total_steps, event) = tx_result;

        // Post-commit: best-effort notification
        self.notifier
            .dispatch(crate::services::audit_event_builder::build_webhook_event(
                &event,
            ));

        Ok(ApproveRequestOutput {
            id: request.id,
            status: new_status,
            approved_by: user.subject_id.clone(),
            matched_selector,
            step_completed,
            current_step: step_completed,
            total_steps,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use chrono::Utc;
    use dbward_domain::auth::{OwnershipScope, ResolvedRole, SubjectType};
    use dbward_domain::entities::Request;
    use dbward_domain::policies::workflow::{ApproverGroup, WorkflowStep, WorkflowStepMode};
    use dbward_domain::values::{DatabaseName, Environment, Operation, Selector};

    fn make_user(id: &str, roles: &[&str]) -> AuthUser {
        AuthUser {
            subject_id: id.to_string(),
            subject_type: SubjectType::User,
            roles: roles
                .iter()
                .map(|name| ResolvedRole {
                    name: name.to_string(),
                    permissions: [(Permission::RequestView, OwnershipScope::Own)]
                        .into_iter()
                        .collect(),
                    databases: vec![],
                    environments: vec![],
                })
                .collect(),
            groups: vec![],
            token_id: None,
        }
    }

    fn make_pending_request(workflow: &Workflow) -> Request {
        Request {
            id: "req-001".into(),
            requester: "alice".into(),
            database: DatabaseName::new("app").unwrap(),
            environment: Environment::new("production").unwrap(),
            operation: Operation::ExecuteDml,
            detail: "UPDATE users SET active = true".into(),
            status: RequestStatus::Pending,
            emergency: false,
            reason: None,
            idempotency_key: None,
            idempotency_fingerprint: None,
            metadata_json: "{}".into(),
            share_with: vec![],
            no_result_store: false,
            workflow_snapshot_json: Some(serde_json::to_string(workflow).unwrap()),
            decision_trace_json: None,
            execution_plan_json: None,
            cancel_reason: None,
            cancelled_by: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            resolved_at: None,
            expires_at: None,
        }
    }

    fn single_step_workflow() -> Workflow {
        Workflow {
            id: "wf-1".into(),
            database: DatabaseName::new("app").unwrap(),
            environment: Environment::new("production").unwrap(),
            operations: vec![],
            auto_approve: None,
            steps: vec![WorkflowStep {
                approvers: vec![ApproverGroup {
                    selector: Selector::Role("dba".into()),
                    min: 1,
                }],
                mode: WorkflowStepMode::Any,
            }],
            require_reason: false,
            allow_self_approve: false,
            allow_same_approver_across_steps: true,
            explain: true,
            pending_ttl_secs: None,
            statement_timeout_secs: None,
            approval_ttl_secs: None,
            created_at: None,
            updated_at: None,
        }
    }

    fn make_uc(reader: Arc<FakeRequestReader>, approval: Arc<FakeApprovalRepo>) -> ApproveRequest {
        ApproveRequest {
            authorizer: Arc::new(AllowAll),
            request_reader: reader,
            approval_repo: approval,
            uow: Arc::new(NoopUnitOfWork),
            notifier: Arc::new(NoopNotifier),
            clock: Arc::new(FixedClock::now_utc()),
            id_gen: Arc::new(FixedIdGen::new()),
        }
    }

    #[test]
    fn approve_single_step_marks_approved() {
        let wf = single_step_workflow();
        let reader = Arc::new(FakeRequestReader::with_request(make_pending_request(&wf)));
        let approval = Arc::new(FakeApprovalRepo::new());
        let uc = make_uc(reader, approval.clone());
        let user = make_user("bob", &["dba"]);

        let out = uc
            .execute(
                ApproveRequestInput {
                    request_id: "req-001".into(),
                    comment: None,
                    selector: None,
                },
                &user,
                &dbward_domain::entities::AuditContext::System,
            )
            .unwrap();
        assert_eq!(out.status, RequestStatus::Approved);
        assert_eq!(out.step_completed, 1);
        assert_eq!(out.current_step, 1);
        assert_eq!(out.total_steps, 1);
        assert_eq!(out.approved_by, "bob");
    }

    #[test]
    fn self_approve_blocked() {
        let wf = single_step_workflow();
        let reader = Arc::new(FakeRequestReader::with_request(make_pending_request(&wf)));
        let approval = Arc::new(FakeApprovalRepo::new());
        let uc = make_uc(reader, approval);
        let user = make_user("alice", &["dba"]); // alice is the requester

        let result = uc.execute(
            ApproveRequestInput {
                request_id: "req-001".into(),
                comment: None,
                selector: None,
            },
            &user,
            &dbward_domain::entities::AuditContext::System,
        );
        assert!(result.is_err());
    }

    #[test]
    fn wrong_status_returns_conflict() {
        let wf = single_step_workflow();
        let mut req = make_pending_request(&wf);
        req.status = RequestStatus::Approved;
        let reader = Arc::new(FakeRequestReader::with_request(req));
        let approval = Arc::new(FakeApprovalRepo::new());
        let uc = make_uc(reader, approval);
        let user = make_user("bob", &["dba"]);

        let result = uc.execute(
            ApproveRequestInput {
                request_id: "req-001".into(),
                comment: None,
                selector: None,
            },
            &user,
            &dbward_domain::entities::AuditContext::System,
        );
        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    #[test]
    fn not_found_returns_error() {
        let reader = Arc::new(FakeRequestReader::new());
        let approval = Arc::new(FakeApprovalRepo::new());
        let uc = make_uc(reader, approval);
        let user = make_user("bob", &["dba"]);

        let result = uc.execute(
            ApproveRequestInput {
                request_id: "nope".into(),
                comment: None,
                selector: None,
            },
            &user,
            &dbward_domain::entities::AuditContext::System,
        );
        assert!(matches!(result, Err(AppError::NotFound(_))));
    }

    #[test]
    fn expired_request_returns_gone() {
        let wf = single_step_workflow();
        let mut req = make_pending_request(&wf);
        req.expires_at = Some(Utc::now() - chrono::Duration::seconds(10));
        let reader = Arc::new(FakeRequestReader::with_request(req));
        let approval = Arc::new(FakeApprovalRepo::new());
        let uc = make_uc(reader, approval);
        let user = make_user("bob", &["dba"]);

        let result = uc.execute(
            ApproveRequestInput {
                request_id: "req-001".into(),
                comment: None,
                selector: None,
            },
            &user,
            &dbward_domain::entities::AuditContext::System,
        );
        assert!(matches!(result, Err(AppError::Gone(_))));
    }

    #[test]
    fn not_expired_request_proceeds() {
        let wf = single_step_workflow();
        let mut req = make_pending_request(&wf);
        req.expires_at = Some(Utc::now() + chrono::Duration::hours(1));
        let reader = Arc::new(FakeRequestReader::with_request(req));
        let approval = Arc::new(FakeApprovalRepo::new());
        let uc = make_uc(reader, approval);
        let user = make_user("bob", &["dba"]);

        let result = uc.execute(
            ApproveRequestInput {
                request_id: "req-001".into(),
                comment: None,
                selector: None,
            },
            &user,
            &dbward_domain::entities::AuditContext::System,
        );
        assert!(result.is_ok());
    }

    // --- Phase 2a: selector choice tests ---

    fn multi_group_workflow() -> Workflow {
        Workflow {
            id: "wf-1".into(),
            database: DatabaseName::new("app").unwrap(),
            environment: Environment::new("production").unwrap(),
            operations: vec![],
            auto_approve: None,
            steps: vec![WorkflowStep {
                approvers: vec![
                    ApproverGroup {
                        selector: Selector::Role("dba".into()),
                        min: 1,
                    },
                    ApproverGroup {
                        selector: Selector::Role("sre".into()),
                        min: 1,
                    },
                ],
                mode: WorkflowStepMode::All,
            }],
            require_reason: false,
            allow_self_approve: false,
            allow_same_approver_across_steps: true,
            explain: true,
            pending_ttl_secs: None,
            statement_timeout_secs: None,
            approval_ttl_secs: None,
            created_at: None,
            updated_at: None,
        }
    }

    fn make_user_multi(id: &str, roles: &[&str], groups: &[&str]) -> AuthUser {
        AuthUser {
            subject_id: id.to_string(),
            subject_type: SubjectType::User,
            roles: roles
                .iter()
                .map(|name| ResolvedRole {
                    name: name.to_string(),
                    permissions: [(Permission::RequestView, OwnershipScope::Own)]
                        .into_iter()
                        .collect(),
                    databases: vec![],
                    environments: vec![],
                })
                .collect(),
            groups: groups.iter().map(|g| g.to_string()).collect(),
            token_id: None,
        }
    }

    #[test]
    fn ambiguous_selector_returns_validation_error() {
        let wf = multi_group_workflow();
        let reader = Arc::new(FakeRequestReader::with_request(make_pending_request(&wf)));
        let approval = Arc::new(FakeApprovalRepo::new());
        let uc = make_uc(reader, approval);
        // User matches both role:dba and role:sre
        let user = make_user_multi("bob", &["dba", "sre"], &[]);

        let result = uc.execute(
            ApproveRequestInput {
                request_id: "req-001".into(),
                comment: None,
                selector: None,
            },
            &user,
            &dbward_domain::entities::AuditContext::System,
        );
        assert!(matches!(result, Err(AppError::Validation(msg)) if msg.contains("ambiguous")));
    }

    #[test]
    fn explicit_selector_succeeds() {
        let wf = multi_group_workflow();
        let reader = Arc::new(FakeRequestReader::with_request(make_pending_request(&wf)));
        let approval = Arc::new(FakeApprovalRepo::new());
        let uc = make_uc(reader, approval);
        let user = make_user_multi("bob", &["dba", "sre"], &[]);

        let result = uc.execute(
            ApproveRequestInput {
                request_id: "req-001".into(),
                comment: None,
                selector: Some("role:dba".into()),
            },
            &user,
            &dbward_domain::entities::AuditContext::System,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap().matched_selector, "role:dba");
    }

    #[test]
    fn explicit_selector_not_matched_returns_validation() {
        let wf = multi_group_workflow();
        let reader = Arc::new(FakeRequestReader::with_request(make_pending_request(&wf)));
        let approval = Arc::new(FakeApprovalRepo::new());
        let uc = make_uc(reader, approval);
        let user = make_user("bob", &["dba"]);

        let result = uc.execute(
            ApproveRequestInput {
                request_id: "req-001".into(),
                comment: None,
                selector: Some("role:sre".into()),
            },
            &user,
            &dbward_domain::entities::AuditContext::System,
        );
        assert!(matches!(result, Err(AppError::Validation(msg)) if msg.contains("do not match")));
    }

    #[test]
    fn no_match_returns_forbidden() {
        let wf = single_step_workflow(); // requires role:dba
        let reader = Arc::new(FakeRequestReader::with_request(make_pending_request(&wf)));
        let approval = Arc::new(FakeApprovalRepo::new());
        let uc = make_uc(reader, approval);
        let user = make_user("bob", &["developer"]); // no dba role

        let result = uc.execute(
            ApproveRequestInput {
                request_id: "req-001".into(),
                comment: None,
                selector: None,
            },
            &user,
            &dbward_domain::entities::AuditContext::System,
        );
        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }
}
