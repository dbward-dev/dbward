use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission, ResourceContext};
use dbward_domain::entities::{Approval, ApprovalAction, RequestStatus};
use dbward_domain::policies::workflow::Workflow;
use dbward_domain::services::status_machine::{
    self, EventMetadata, RequestTrigger, TransitionContext,
};

#[allow(unused_imports)]
use crate::error::{AppError, AuthzError};
use crate::ports::*;

pub struct RejectRequest {
    pub authorizer: Arc<dyn Authorizer>,
    pub request_repo: Arc<dyn RequestRepo>,
    pub event_dispatcher: Arc<dyn EventDispatcher>,
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
    ) -> Result<RejectRequestOutput, AppError> {
        // 0. Input validation
        if let Some(ref c) = input.comment {
            if c.len() > 1024 {
                return Err(AppError::Validation(
                    "comment too long (max 1024 bytes)".into(),
                ));
            }
        }

        // 1. Get request
        let request = self
            .request_repo
            .get(&input.request_id)?
            .ok_or_else(|| AppError::NotFound("request not found".into()))?;

        // 2. Authorization: requester can self-reject, or approvers can reject
        let is_requester = user.subject_id == request.requester;

        // Parse workflow and approvals (needed for both authz and record)
        let workflow: Option<Workflow> = request
            .workflow_snapshot_json
            .as_deref()
            .and_then(|json| serde_json::from_str(json).ok());
        let approvals = self.request_repo.get_approvals(&request.id)?;
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
            let previous_approver_ids: Vec<String> = approvals
                .iter()
                .filter(|a| {
                    a.step_index < current_step_index && a.action == ApprovalAction::Approve
                })
                .map(|a| a.actor_id.clone())
                .collect();

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
                        allow_self_approve: true, // rejection always allowed for approvers
                        allow_same_approver_across_steps: true,
                        previous_approver_ids,
                    },
                )
                .map_err(AppError::Forbidden)?;
        }

        // 4. Determine matched_selector for the rejection record
        let matched_selector = if is_requester {
            "requester".to_string()
        } else {
            let wf = workflow.as_ref().unwrap();
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
                    .unwrap_or_else(|| "admin".to_string())
            } else {
                "admin".to_string()
            }
        };

        // 5. Expiry check
        let now = self.clock.now();
        if let Some(expires_at) = request.expires_at {
            if now >= expires_at {
                return Err(AppError::Gone(
                    "request has expired. Hint: set pending_ttl_secs in your workflow configuration to increase the approval window".into(),
                ));
            }
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

        let ok = self
            .request_repo
            .reject_and_record(&request.id, &approval, now)?;
        if !ok {
            return Err(AppError::Conflict("concurrent status change".into()));
        }

        result.commit(&*self.event_dispatcher);

        Ok(RejectRequestOutput {
            id: request.id,
            status: RequestStatus::Rejected,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbward_domain::services::status_machine::{EventDispatcher, TransitionEvent};
    struct NoopDispatcher;
    impl EventDispatcher for NoopDispatcher {
        fn dispatch(&self, _: TransitionEvent) {}
    }
    use chrono::{DateTime, Utc};
    use dbward_domain::auth::SubjectType;
    use dbward_domain::entities::Request;
    use dbward_domain::policies::workflow::{ApproverGroup, WorkflowStep, WorkflowStepMode};
    use dbward_domain::values::{DatabaseName, Environment, Operation, Selector};
    use std::sync::Mutex;

    struct AllowAll;
    impl Authorizer for AllowAll {
        fn authorize_scoped(
            &self,
            _: &AuthUser,
            _: Permission,
            _: &DatabaseName,
            _: &Environment,
            _: &ResourceContext,
        ) -> Result<(), AuthzError> {
            Ok(())
        }
        fn authorize_global(&self, _: &AuthUser, _: Permission) -> Result<(), AuthzError> {
            Ok(())
        }
    }
    struct FakeClock;
    impl Clock for FakeClock {
        fn now(&self) -> DateTime<Utc> {
            Utc::now()
        }
    }
    struct FakeIdGen;
    impl IdGenerator for FakeIdGen {
        fn generate(&self) -> String {
            "rej-001".into()
        }
    }

    struct FakeRepo {
        request: Mutex<Option<Request>>,
        rejected: Mutex<bool>,
    }
    impl RequestRepo for FakeRepo {
        fn insert(&self, _: &Request) -> Result<(), AppError> {
            Ok(())
        }
        fn get(&self, _: &str) -> Result<Option<Request>, AppError> {
            Ok(self.request.lock().unwrap().clone())
        }
        fn list(
            &self,
            _: u32,
            _: u32,
            _: Option<&str>,
            _: Option<&str>,
        ) -> Result<(Vec<Request>, u32), AppError> {
            Ok((vec![], 0))
        }
        fn find_by_idempotency_key(&self, _: &str) -> Result<Option<Request>, AppError> {
            Ok(None)
        }
        fn list_visible_to_user(
            &self,
            _: &str,
            _: &[String],
            _: &[String],
            _: Option<&str>,
            _: u32,
            _: u32,
        ) -> Result<(Vec<Request>, u32), AppError> {
            Ok((vec![], 0))
        }
        fn list_pending_for_user(
            &self,
            _: &str,
            _: &[String],
            _: &[String],
            _: u32,
            _: u32,
        ) -> Result<(Vec<Request>, u32), AppError> {
            Ok((vec![], 0))
        }
        fn insert_approval(&self, _: &Approval) -> Result<(), AppError> {
            Ok(())
        }
        fn get_approvals(&self, _: &str) -> Result<Vec<Approval>, AppError> {
            Ok(vec![])
        }
        fn count_executions(&self, _: &str) -> Result<u32, AppError> {
            Ok(0)
        }
        fn mark_approved(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn approve_and_mark_approved(
            &self,
            _: &Approval,
            _: &str,
            _: DateTime<Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_rejected(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
            *self.rejected.lock().unwrap() = true;
            Ok(true)
        }
        fn reject_and_record(
            &self,
            _: &str,
            _: &Approval,
            _: DateTime<Utc>,
        ) -> Result<bool, AppError> {
            *self.rejected.lock().unwrap() = true;
            Ok(true)
        }
        fn mark_cancelled(
            &self,
            _: &str,
            _: &str,
            _: Option<&str>,
            _: DateTime<Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_dispatched(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn create_and_dispatch(&self, _: &Request) -> Result<(), AppError> {
            Ok(())
        }
        fn mark_running(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_executed(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_failed(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn cancel_all_for_user(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<u32, AppError> {
            Ok(0)
        }
        fn find_expired_approved(&self, _: &str) -> Result<Vec<String>, AppError> {
            Ok(vec![])
        }
        fn find_expired_pending(&self, _: &str) -> Result<Vec<String>, AppError> {
            Ok(vec![])
        }
        fn find_dispatched_older_than(&self, _: &str) -> Result<Vec<String>, AppError> {
            Ok(vec![])
        }
        fn mark_expired(&self, _: &str, _: &str) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_expired_and_record(
            &self,
            _: &str,
            _: &dbward_domain::entities::AuditEvent,
            _: &str,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_approved_from_dispatched(&self, _: &str, _: &str) -> Result<bool, AppError> {
            Ok(true)
        }
        fn purge_old_requests(&self, _: &str) -> Result<u32, AppError> {
            Ok(0)
        }
        fn count_by_status(&self, _: &str) -> Result<u32, AppError> {
            Ok(0)
        }
        fn wal_checkpoint(&self) -> Result<(), AppError> {
            Ok(())
        }
        fn list_results_for_user(
            &self,
            _: &str,
            _: &[String],
            _: &[String],
            _: u32,
        ) -> Result<Vec<crate::ports::repos::StoredResultEntry>, AppError> {
            Ok(vec![])
        }
        fn is_pending_approver(
            &self,
            _: &str,
            _: &str,
            _: &[String],
            _: &[String],
        ) -> Result<bool, AppError> {
            Ok(false)
        }
    }

    fn make_pending_request() -> Request {
        let wf = Workflow {
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
            skip_approval_for: vec![],
            require_reason: false,
            allow_self_approve: false,
            allow_same_approver_across_steps: true,
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
            metadata_json: "{}".into(),
            share_with: vec![],
            no_store: false,
            workflow_snapshot_json: Some(serde_json::to_string(&wf).unwrap()),
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
        let repo = Arc::new(FakeRepo {
            request: Mutex::new(Some(make_pending_request())),
            rejected: Mutex::new(false),
        });
        let uc = RejectRequest {
            authorizer: Arc::new(AllowAll),
            request_repo: repo.clone(),
            event_dispatcher: Arc::new(NoopDispatcher),
            clock: Arc::new(FakeClock),
            id_gen: Arc::new(FakeIdGen),
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
            )
            .unwrap();
        assert_eq!(out.status, RequestStatus::Rejected);
        assert!(*repo.rejected.lock().unwrap());
    }

    #[test]
    fn wrong_status_returns_conflict() {
        let mut req = make_pending_request();
        req.status = RequestStatus::Approved;
        let repo = Arc::new(FakeRepo {
            request: Mutex::new(Some(req)),
            rejected: Mutex::new(false),
        });
        let uc = RejectRequest {
            authorizer: Arc::new(AllowAll),
            request_repo: repo.clone(),
            event_dispatcher: Arc::new(NoopDispatcher),
            clock: Arc::new(FakeClock),
            id_gen: Arc::new(FakeIdGen),
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
                &user
            ),
            Err(AppError::Conflict(_))
        ));
    }
}
