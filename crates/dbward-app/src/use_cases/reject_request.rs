use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission};
use dbward_domain::entities::{Approval, ApprovalAction, RequestStatus};
use dbward_domain::policies::workflow::Workflow;
use dbward_domain::services::status_machine::{
    self, EventMetadata, RequestTrigger, TransitionContext,
};

use crate::error::{AppError, AuthzError};
use crate::ports::*;
use crate::services::audit_event_builder;
use crate::services::audit_event_builder::build_webhook_event;

pub struct RejectRequest {
    pub authorizer: Arc<dyn Authorizer>,
    pub request_reader: Arc<dyn RequestReader>,
    pub approval_repo: Arc<dyn ApprovalRepo>,
    pub uow: Arc<dyn UnitOfWork>,
    pub notifier: Arc<dyn Notifier>,
    pub clock: Arc<dyn Clock>,
    pub id_gen: Arc<dyn IdGenerator>,
}

pub struct RejectRequestInput {
    pub request_id: String,
    pub comment: Option<String>,
}

pub struct RejectRequestOutput {
    pub id: String,
    pub status: RequestStatus,
}

impl RejectRequest {
    pub fn execute(
        &self,
        input: RejectRequestInput,
        user: &AuthUser,
        ctx: &dbward_domain::entities::AuditContext,
    ) -> Result<RejectRequestOutput, AppError> {
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

        // 2. Authorization: requester can self-reject, or approvers can reject
        let is_requester = user.subject_id == request.requester;

        // Parse workflow and approvals (needed for both authz and record)
        let workflow: Option<Workflow> = request
            .workflow_snapshot_json
            .as_deref()
            .map(|json| {
                serde_json::from_str(json)
                    .map_err(|e| AppError::Internal(format!("corrupt workflow snapshot: {e}")))
            })
            .transpose()?;
        let approvals = self.approval_repo.get_approvals(&request.id)?;
        let current_step_index = workflow
            .as_ref()
            .map(|wf| {
                dbward_domain::services::workflow_matcher::find_current_step(&wf.steps, &approvals)
            })
            .unwrap_or(0);

        if !is_requester {
            let wf = workflow
                .as_ref()
                .ok_or_else(|| AppError::Conflict("request has no workflow snapshot".into()))?;

            if current_step_index >= wf.steps.len() as u32 {
                return Err(AppError::Conflict("all steps already satisfied".into()));
            }

            let step = &wf.steps[current_step_index as usize];

            // Reject requires matching any approver selector in the current step
            let role_names: Vec<String> = user.roles.iter().map(|r| r.name.clone()).collect();
            let is_eligible = step.approvers.iter().any(|ag| {
                ag.selector
                    .matches(&role_names, &user.groups, &user.subject_id, false)
            });

            if !is_eligible {
                return Err(AppError::Forbidden(AuthzError::Forbidden {
                    permission: Permission::RequestApprove,
                    reason: "not eligible to reject this step".into(),
                }));
            }
        }

        // 4. Determine matched_selector for the rejection record
        let matched_selector = if is_requester {
            "requester".to_string()
        } else {
            let wf = workflow
                .as_ref()
                .expect("workflow validated in !is_requester branch");
            if current_step_index < wf.steps.len() as u32 {
                let role_names: Vec<String> = user.roles.iter().map(|r| r.name.clone()).collect();
                wf.steps[current_step_index as usize]
                    .approvers
                    .iter()
                    .find(|ag| {
                        ag.selector
                            .matches(&role_names, &user.groups, &user.subject_id, false)
                    })
                    .map(|ag| ag.selector.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            } else {
                "unknown".to_string()
            }
        };

        // 5. Expiry check
        let now = self.clock.now();
        if let Some(expires_at) = request.expires_at
            && now >= expires_at
        {
            return Err(AppError::Gone(
                    "request has expired. Hint: set pending_ttl_secs in your workflow configuration to increase the approval window".into(),
                ));
        }

        // 6. Transition via status_machine
        let result = status_machine::transition(
            request.status,
            &RequestTrigger::Reject,
            TransitionContext {
                request_id: request.id.clone(),
                actor_id: user.subject_id.clone(),
                actor_type: user.subject_type,
                database: request.database.clone(),
                environment: request.environment.clone(),
                operation: request.operation,
                timestamp: now,
                metadata: EventMetadata::Rejected {
                    comment: input.comment.clone(),
                },
                requester_id: request.requester.clone(),
                audit_context: ctx.clone(),
            },
        )
        .map_err(|e| AppError::Conflict(e.to_string()))?;

        let approval = Approval {
            id: self.id_gen.generate(),
            request_id: request.id.clone(),
            action: ApprovalAction::Reject,
            actor_id: user.subject_id.clone(),
            matched_selector,
            step_index: current_step_index,
            comment: input.comment,
            created_at: now,
        };

        let event = result.into_event();
        let audit_event = audit_event_builder::build_audit_event(
            &event,
            now,
            audit_event_builder::RedactionMode::default(),
            audit_event_builder::noop_redact,
        );

        // Atomic: approval + status change + audit
        let request_id = request.id.clone();
        self.uow.execute(Box::new(move |tx| {
            tx.insert_approval(&approval)?;
            let ok = tx.mark_rejected(&request_id, now)?;
            if !ok {
                return Err(AppError::Conflict("concurrent status change".into()));
            }
            tx.record(&audit_event)?;
            Ok(())
        }))?;

        // Post-commit: best-effort notification
        self.notifier.dispatch(build_webhook_event(&event));

        Ok(RejectRequestOutput {
            id: request.id,
            status: RequestStatus::Rejected,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use chrono::Utc;
    use dbward_domain::auth::SubjectType;
    use dbward_domain::entities::Request;
    use dbward_domain::policies::workflow::{ApproverGroup, WorkflowStep, WorkflowStepMode};
    use dbward_domain::values::{DatabaseName, Environment, Operation, Selector};

    fn make_pending_request() -> Request {
        let wf = dbward_domain::policies::Workflow {
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
        };
        Request {
            id: "req-001".into(),
            requester: "alice".into(),
            database: DatabaseName::new("app").unwrap(),
            environment: Environment::new("production").unwrap(),
            operation: Operation::ExecuteDml,
            detail: "DELETE FROM users".into(),
            status: RequestStatus::Pending,
            emergency: false,
            reason: None,
            idempotency_key: None,
            idempotency_fingerprint: None,
            metadata_json: "{}".into(),
            share_with: vec![],
            no_result_store: false,
            workflow_snapshot_json: Some(serde_json::to_string(&wf).unwrap()),
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

    #[test]
    fn requester_can_reject_own_request() {
        let reader = Arc::new(FakeRequestReader::with_request(make_pending_request()));
        let approval = Arc::new(FakeApprovalRepo::new());
        let uc = RejectRequest {
            authorizer: Arc::new(AllowAll),
            request_reader: reader,
            approval_repo: approval.clone(),
            uow: Arc::new(NoopUnitOfWork),
            notifier: Arc::new(NoopNotifier),
            clock: Arc::new(FixedClock::now_utc()),
            id_gen: Arc::new(FixedIdGen::new()),
        };
        let user = AuthUser {
            subject_id: "alice".into(),
            subject_type: SubjectType::User,
            roles: vec![],
            groups: vec![],
            token_id: None,
        };

        let out = uc
            .execute(
                RejectRequestInput {
                    request_id: "req-001".into(),
                    comment: None,
                },
                &user,
                &dbward_domain::entities::AuditContext::System,
            )
            .unwrap();
        assert_eq!(out.status, RequestStatus::Rejected);
    }

    #[test]
    fn wrong_status_returns_conflict() {
        let mut req = make_pending_request();
        req.status = RequestStatus::Approved;
        let reader = Arc::new(FakeRequestReader::with_request(req));
        let approval = Arc::new(FakeApprovalRepo::new());
        let uc = RejectRequest {
            authorizer: Arc::new(AllowAll),
            request_reader: reader,
            approval_repo: approval,
            uow: Arc::new(NoopUnitOfWork),
            notifier: Arc::new(NoopNotifier),
            clock: Arc::new(FixedClock::now_utc()),
            id_gen: Arc::new(FixedIdGen::new()),
        };
        let user = AuthUser {
            subject_id: "alice".into(),
            subject_type: SubjectType::User,
            roles: vec![],
            groups: vec![],
            token_id: None,
        };

        assert!(matches!(
            uc.execute(
                RejectRequestInput {
                    request_id: "req-001".into(),
                    comment: None
                },
                &user,
                &dbward_domain::entities::AuditContext::System,
            ),
            Err(AppError::Conflict(_))
        ));
    }
}
