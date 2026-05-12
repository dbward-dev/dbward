use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission, ResourceContext};
use dbward_domain::entities::RequestStatus;
use dbward_domain::services::status_machine::{self, EventMetadata, RequestTrigger, TransitionContext};

use crate::error::AppError;
use crate::ports::*;

pub struct DispatchRequest {
    pub authorizer: Arc<dyn Authorizer>,
    pub policy: Arc<dyn PolicyEvaluator>,
    pub request_repo: Arc<dyn RequestRepo>,
    pub result_channel: Arc<dyn ResultChannel>,
    pub event_dispatcher: Arc<dyn EventDispatcher>,
    pub policy_repo: Arc<dyn PolicyRepo>,
    pub clock: Arc<dyn Clock>,
}

pub struct DispatchRequestInput {
    pub request_id: String,
}

pub struct DispatchRequestOutput {
    pub id: String,
    pub status: RequestStatus,
}

impl DispatchRequest {
    pub fn execute(&self, input: DispatchRequestInput, user: &AuthUser) -> Result<DispatchRequestOutput, AppError> {
        // 1. Get request
        let request = self.request_repo.get(&input.request_id)?
            .ok_or_else(|| AppError::NotFound("request not found".into()))?;

        // 2. Authorization: requester or admin (scoped)
        self.authorizer.authorize_scoped(
            user,
            Permission::RequestDispatch,
            &request.database,
            &request.environment,
            &ResourceContext::Request { requester_id: request.requester.clone() },
        ).map_err(AppError::Forbidden)?;

        // 3. Status check via status_machine
        let now = self.clock.now();
        let result = status_machine::transition(
            request.status,
            &RequestTrigger::Dispatch,
            TransitionContext {
                request_id: request.id.clone(),
                actor_id: user.subject_id.clone(),
                actor_type: user.subject_type,
                database: request.database.clone(),
                environment: request.environment.clone(),
                operation: request.operation,
                timestamp: now,
                metadata: EventMetadata::Dispatched,
            },
        ).map_err(|e| AppError::Conflict(e.to_string()))?;

        // 4. Approval TTL check (based on resolved_at = when approval was granted)
        if let Some(resolved_at) = request.resolved_at {
            if let Some(wf_json) = &request.workflow_snapshot_json {
                if let Ok(wf) = serde_json::from_str::<dbward_domain::policies::Workflow>(wf_json) {
                    if let Some(ttl) = wf.approval_ttl_secs {
                        let elapsed = (self.clock.now() - resolved_at).num_seconds() as u64;
                        if elapsed > ttl {
                            return Err(AppError::Gone("approval expired".into()));
                        }
                    }
                }
            }
        }

        // 5. Re-execution policy check (only for re-dispatch from terminal states)
        if matches!(request.status, RequestStatus::Executed | RequestStatus::Failed | RequestStatus::ExecutionLost) {
            let exec_policy = self.policy.get_execution_policy(&request.database, &request.environment);
            let exec_count = self.request_repo.count_executions(&request.id)?;

            // Execution window check
            if let Some(resolved_at) = request.resolved_at {
                let elapsed = (self.clock.now() - resolved_at).num_seconds() as u64;
                if elapsed > exec_policy.execution_window_secs {
                    return Err(AppError::Gone("execution window expired".into()));
                }
            }

            if exec_count >= exec_policy.max_executions {
                return Err(AppError::Conflict("max executions reached".into()));
            }

            if !exec_policy.retry_on_failure && request.status == RequestStatus::Failed {
                return Err(AppError::Conflict("retry on failure disabled".into()));
            }
        }

        // 6. Mark dispatched
        let ok = self.request_repo.mark_dispatched(&request.id, now)?;
        if !ok {
            return Err(AppError::Conflict("concurrent status change".into()));
        }

        // Pre-create result slot so subscribers can wait before agent completes
        // M-21: Skip streaming slot if policy says StoreOnly
        let delivery_mode = self.policy_repo.find_result_policy(&request.database, &request.environment)
            .ok()
            .flatten()
            .map(|p| p.delivery_mode)
            .unwrap_or_default();
        if delivery_mode != dbward_domain::policies::DeliveryMode::StoreOnly {
            self.result_channel.create_slot(&request.id);
        }

        result.commit(&*self.event_dispatcher);

        Ok(DispatchRequestOutput {
            id: request.id,
            status: RequestStatus::Dispatched,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbward_domain::services::status_machine::{EventDispatcher, TransitionEvent};
    struct NoopDispatcher;
    impl EventDispatcher for NoopDispatcher { fn dispatch(&self, _: TransitionEvent) {} }
    use dbward_domain::auth::SubjectType;
    use dbward_domain::entities::Request;
    use dbward_domain::values::{DatabaseName, Environment, Operation};
    use chrono::{DateTime, Utc};
    use std::sync::Mutex;
    use crate::error::AuthzError;
    use async_trait::async_trait;

    struct AllowAll;
    impl Authorizer for AllowAll {
        fn authorize_scoped(&self, _: &AuthUser, _: Permission, _: &DatabaseName, _: &Environment, _: &ResourceContext) -> Result<(), AuthzError> { Ok(()) }
        fn authorize_global(&self, _: &AuthUser, _: Permission) -> Result<(), AuthzError> { Ok(()) }
    }
    struct FakeClock;
    impl Clock for FakeClock { fn now(&self) -> DateTime<Utc> { Utc::now() } }

    struct FakePolicy;
    impl PolicyEvaluator for FakePolicy {
        fn evaluate_workflow(&self, _: &DatabaseName, _: &Environment, _: Operation) -> Result<Option<dbward_domain::policies::Workflow>, AppError> { Ok(None) }
        fn get_execution_policy(&self, _: &DatabaseName, _: &Environment) -> dbward_domain::policies::ExecutionPolicy { Default::default() }
    }

    struct FakeResultChannel;
    #[async_trait]
    impl ResultChannel for FakeResultChannel {
        fn create_slot(&self, _: &str) {}
        async fn publish(&self, _: &str, _: dbward_domain::values::ResultSummary) {}
        async fn subscribe(&self, _: &str, _: u64) -> Result<Option<dbward_domain::values::ResultSummary>, AppError> { Ok(None) }
        async fn notify_all(&self) {}
    }

    struct FakePolicyRepo;
    impl PolicyRepo for FakePolicyRepo {
        fn create_workflow(&self, _: &dbward_domain::policies::Workflow) -> Result<(), AppError> { Ok(()) }
        fn get_workflow(&self, _: &str) -> Result<Option<dbward_domain::policies::Workflow>, AppError> { Ok(None) }
        fn list_workflows(&self) -> Result<Vec<dbward_domain::policies::Workflow>, AppError> { Ok(vec![]) }
        fn delete_workflow(&self, _: &str) -> Result<bool, AppError> { Ok(true) }
        fn count_workflows(&self) -> Result<u32, AppError> { Ok(0) }
        fn create_execution_policy(&self, _: &dbward_domain::policies::ExecutionPolicy) -> Result<(), AppError> { Ok(()) }
        fn get_execution_policy(&self, _: &str) -> Result<Option<dbward_domain::policies::ExecutionPolicy>, AppError> { Ok(None) }
        fn list_execution_policies(&self) -> Result<Vec<dbward_domain::policies::ExecutionPolicy>, AppError> { Ok(vec![]) }
        fn delete_execution_policy(&self, _: &str) -> Result<bool, AppError> { Ok(true) }
        fn find_result_policy(&self, _: &DatabaseName, _: &Environment) -> Result<Option<dbward_domain::policies::ResultPolicy>, AppError> { Ok(None) }
        fn create_role(&self, _: &dbward_domain::auth::RoleDefinition) -> Result<(), AppError> { Ok(()) }
        fn list_roles(&self) -> Result<Vec<dbward_domain::auth::RoleDefinition>, AppError> { Ok(vec![]) }
        fn get_roles_by_names(&self, _: &[String]) -> Result<Vec<dbward_domain::auth::RoleDefinition>, AppError> { Ok(vec![]) }
        fn delete_role(&self, _: &str) -> Result<bool, AppError> { Ok(true) }
        fn count_roles(&self) -> Result<u32, AppError> { Ok(0) }
    }

    struct FakeRepo { request: Mutex<Option<Request>>, dispatched: Mutex<bool> }
    impl RequestRepo for FakeRepo {
        fn insert(&self, _: &Request) -> Result<(), AppError> { Ok(()) }
        fn get(&self, _: &str) -> Result<Option<Request>, AppError> { Ok(self.request.lock().unwrap().clone()) }
        fn list(&self, _: u32, _: u32, _: Option<&str>) -> Result<(Vec<Request>, u32), AppError> { Ok((vec![], 0)) }
        fn find_by_idempotency_key(&self, _: &str) -> Result<Option<Request>, AppError> { Ok(None) }
        fn insert_approval(&self, _: &dbward_domain::entities::Approval) -> Result<(), AppError> { Ok(()) }
        fn get_approvals(&self, _: &str) -> Result<Vec<dbward_domain::entities::Approval>, AppError> { Ok(vec![]) }
        fn count_executions(&self, _: &str) -> Result<u32, AppError> { Ok(0) }
        fn mark_approved(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> { Ok(true) }
        fn approve_and_mark_approved(&self, _: &dbward_domain::entities::Approval, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> { Ok(true) }
        fn mark_rejected(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> { Ok(true) }
        fn reject_and_record(&self, _: &str, _: &dbward_domain::entities::Approval, _: DateTime<Utc>) -> Result<bool, AppError> { Ok(true) }
        fn mark_cancelled(&self, _: &str, _: &str, _: Option<&str>, _: DateTime<Utc>) -> Result<bool, AppError> { Ok(true) }
        fn mark_dispatched(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> { *self.dispatched.lock().unwrap() = true; Ok(true) }
        fn create_and_dispatch(&self, _: &Request) -> Result<(), AppError> { Ok(()) }
        fn mark_running(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> { Ok(true) }
        fn mark_executed(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> { Ok(true) }
        fn mark_failed(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> { Ok(true) }
        fn cancel_all_for_user(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<u32, AppError> { Ok(0) }
        fn find_expired_approved(&self, _: &str) -> Result<Vec<String>, AppError> { Ok(vec![]) }
        fn find_expired_pending(&self, _: &str) -> Result<Vec<String>, AppError> { Ok(vec![]) }
        fn find_dispatched_older_than(&self, _: &str) -> Result<Vec<String>, AppError> { Ok(vec![]) }
        fn mark_expired(&self, _: &str, _: &str) -> Result<bool, AppError> { Ok(true) }
        fn mark_expired_and_record(&self, _: &str, _: &dbward_domain::entities::AuditEvent, _: &str) -> Result<bool, AppError> { Ok(true) }
        fn mark_approved_from_dispatched(&self, _: &str, _: &str) -> Result<bool, AppError> { Ok(true) }
        fn purge_old_requests(&self, _: &str) -> Result<u32, AppError> { Ok(0) }
        fn count_by_status(&self, _: &str) -> Result<u32, AppError> { Ok(0) }
        fn wal_checkpoint(&self) -> Result<(), AppError> { Ok(()) }
    }

    fn make_request(status: RequestStatus) -> Request {
        Request {
            id: "req-001".into(), requester: "alice".into(),
            database: DatabaseName::new("app").unwrap(), environment: Environment::new("production").unwrap(),
            operation: Operation::ExecuteDml, detail: "UPDATE x SET y=1".into(),
            status, emergency: false, reason: None,
            idempotency_key: None, metadata_json: "{}".into(), share_with: vec![],
            no_store: false, workflow_snapshot_json: None,
            cancel_reason: None, cancelled_by: None,
            created_at: Utc::now(), updated_at: Utc::now(), resolved_at: None, expires_at: None,
        }
    }

    #[test]
    fn dispatch_approved_succeeds() {
        let repo = Arc::new(FakeRepo { request: Mutex::new(Some(make_request(RequestStatus::Approved))), dispatched: Mutex::new(false) });
        let uc = DispatchRequest { authorizer: Arc::new(AllowAll), policy: Arc::new(FakePolicy), request_repo: repo.clone(), result_channel: Arc::new(FakeResultChannel), event_dispatcher: Arc::new(NoopDispatcher), policy_repo: Arc::new(FakePolicyRepo), clock: Arc::new(FakeClock) };
        let user = AuthUser { subject_id: "alice".into(), subject_type: SubjectType::User, roles: vec![], groups: vec![], token_id: None };

        let out = uc.execute(DispatchRequestInput { request_id: "req-001".into() }, &user).unwrap();
        assert_eq!(out.status, RequestStatus::Dispatched);
        assert!(*repo.dispatched.lock().unwrap());
    }

    #[test]
    fn dispatch_pending_fails() {
        let repo = Arc::new(FakeRepo { request: Mutex::new(Some(make_request(RequestStatus::Pending))), dispatched: Mutex::new(false) });
        let uc = DispatchRequest { authorizer: Arc::new(AllowAll), policy: Arc::new(FakePolicy), request_repo: repo.clone(), result_channel: Arc::new(FakeResultChannel), event_dispatcher: Arc::new(NoopDispatcher), policy_repo: Arc::new(FakePolicyRepo), clock: Arc::new(FakeClock) };
        let user = AuthUser { subject_id: "alice".into(), subject_type: SubjectType::User, roles: vec![], groups: vec![], token_id: None };

        assert!(matches!(uc.execute(DispatchRequestInput { request_id: "req-001".into() }, &user), Err(AppError::Conflict(_))));
    }

    #[test]
    fn dispatch_break_glass_succeeds() {
        let repo = Arc::new(FakeRepo { request: Mutex::new(Some(make_request(RequestStatus::BreakGlass))), dispatched: Mutex::new(false) });
        let uc = DispatchRequest { authorizer: Arc::new(AllowAll), policy: Arc::new(FakePolicy), request_repo: repo.clone(), result_channel: Arc::new(FakeResultChannel), event_dispatcher: Arc::new(NoopDispatcher), policy_repo: Arc::new(FakePolicyRepo), clock: Arc::new(FakeClock) };
        let user = AuthUser { subject_id: "alice".into(), subject_type: SubjectType::User, roles: vec![], groups: vec![], token_id: None };

        let out = uc.execute(DispatchRequestInput { request_id: "req-001".into() }, &user).unwrap();
        assert_eq!(out.status, RequestStatus::Dispatched);
    }
}
