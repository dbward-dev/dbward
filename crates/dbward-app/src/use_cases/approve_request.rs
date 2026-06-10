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
    pub event_dispatcher: Arc<dyn EventDispatcher>,
    pub clock: Arc<dyn Clock>,
    pub id_gen: Arc<dyn IdGenerator>,
}

pub struct ApproveRequestInput {
    pub request_id: String,
    pub comment: Option<String>,
}

pub struct ApproveRequestOutput {
    pub id: String,
    pub status: RequestStatus,
    pub approved_by: String,
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
            .and_then(|json| serde_json::from_str(json).ok())
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

        // 6. Authorization: scoped permission + approval_checker
        let previous_approver_ids: Vec<String> = approvals
            .iter()
            .filter(|a| a.step_index < current_step_index && a.action == ApprovalAction::Approve)
            .map(|a| a.actor_id.clone())
            .collect();

        // Check if user is a workflow approver for this step (ADR-002: approver designation = permission grant)
        let role_names: Vec<String> = user.roles.iter().map(|r| r.name.clone()).collect();
        let is_designated_approver = step.approvers.iter().any(|ag| {
            ag.selector
                .matches(&role_names, &user.groups, &user.subject_id, false)
        });

        if !is_designated_approver {
            self.authorizer
                .authorize_scoped(
                    user,
                    Permission::RequestApprove,
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
        }

        // 7. Domain-level approvability check (redundant with Authorizer but explicit)

        if !approval_checker::is_approvable_by(
            user,
            &step.approvers,
            &request.requester,
            &previous_approver_ids,
            workflow.allow_self_approve,
            workflow.allow_same_approver_across_steps,
        ) {
            return Err(AppError::Forbidden(AuthzError::Forbidden {
                permission: Permission::RequestApprove,
                reason: "not eligible to approve this step".into(),
            }));
        }

        // 8. Find which selector the user matches
        let matched_selector = find_matched_selector(user, &step.approvers);

        // 9. Check distinct actors within same step
        let already_approved_this_step = approvals.iter().any(|a| {
            a.step_index == current_step_index
                && a.actor_id == user.subject_id
                && a.action == ApprovalAction::Approve
        });
        if already_approved_this_step {
            return Err(AppError::Conflict("already approved this step".into()));
        }

        // 10. Insert approval
        let comment = input.comment.clone();
        let approval = Approval {
            id: self.id_gen.generate(),
            request_id: request.id.clone(),
            action: ApprovalAction::Approve,
            actor_id: user.subject_id.clone(),
            matched_selector,
            step_index: current_step_index,
            comment: input.comment,
            created_at: now,
        };

        // 11. Check if step (and all steps) are now satisfied
        let mut all_approvals = approvals;
        all_approvals.push(approval.clone());

        let all_satisfied = workflow_matcher::all_steps_satisfied(&workflow.steps, &all_approvals);

        let step_completed = if all_satisfied {
            total_steps
        } else {
            workflow_matcher::find_current_step(&workflow.steps, &all_approvals)
        };

        let trigger = if all_satisfied {
            RequestTrigger::ApproveFinal
        } else {
            RequestTrigger::ApproveStep
        };

        let result = status_machine::transition(
            request.status,
            &trigger,
            TransitionContext {
                request_id: request.id.clone(),
                actor_id: user.subject_id.clone(),
                actor_type: user.subject_type,
                database: request.database.clone(),
                environment: request.environment.clone(),
                operation: request.operation,
                timestamp: now,
                metadata: if all_satisfied {
                    EventMetadata::Approved {
                        comment: comment.clone(),
                    }
                } else {
                    EventMetadata::StepApproved {
                        step_index: current_step_index,
                        total_steps,
                        comment,
                    }
                },
                requester_id: request.requester.clone(),
                audit_context: ctx.clone(),
            },
        )
        .map_err(|e| AppError::Conflict(e.to_string()))?;

        let new_status = result.status();

        if all_satisfied {
            let ok = self
                .approval_repo
                .approve_and_mark_approved(&approval, &request.id, now)?;
            if !ok {
                return Err(AppError::Conflict("concurrent status change".into()));
            }
        } else {
            self.approval_repo.insert_approval(&approval)?;
        }

        result.commit(&*self.event_dispatcher);

        Ok(ApproveRequestOutput {
            id: request.id,
            status: new_status,
            approved_by: user.subject_id.clone(),
            step_completed,
            current_step: step_completed,
            total_steps,
        })
    }
}

/// Find which selector the user matches in the approver groups.
fn find_matched_selector(
    user: &AuthUser,
    approvers: &[dbward_domain::policies::workflow::ApproverGroup],
) -> String {
    let role_names: Vec<String> = user.roles.iter().map(|r| r.name.clone()).collect();
    for ag in approvers {
        if ag
            .selector
            .matches(&role_names, &user.groups, &user.subject_id, false)
        {
            return ag.selector.to_string();
        }
    }
    if user.roles.iter().any(|r| {
        r.permissions
            .contains(&dbward_domain::auth::Permission::All)
    }) {
        return "admin_override".to_string();
    }
    "unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use chrono::Utc;
    use dbward_domain::auth::{ResolvedRole, SubjectType};
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
                    permissions: [Permission::RequestApprove].into_iter().collect(),
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
            metadata_json: "{}".into(),
            share_with: vec![],
            no_store: false,
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
            event_dispatcher: Arc::new(NoopDispatcher),
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
        assert!(*approval.marked_approved.lock().unwrap());
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
            },
            &user,
            &dbward_domain::entities::AuditContext::System,
        );
        assert!(result.is_ok());
    }
}
