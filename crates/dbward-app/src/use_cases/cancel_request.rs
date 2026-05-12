use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission, ResourceContext};
use dbward_domain::entities::RequestStatus;
use dbward_domain::services::status_machine::{self, EventMetadata, RequestTrigger, TransitionContext};

use crate::error::AppError;
use crate::ports::*;

pub struct CancelRequest {
    pub authorizer: Arc<dyn Authorizer>,
    pub request_repo: Arc<dyn RequestRepo>,
    pub event_dispatcher: Arc<dyn EventDispatcher>,
    pub clock: Arc<dyn Clock>,
}

pub struct CancelRequestInput {
    pub request_id: String,
    pub reason: Option<String>,
}

pub struct CancelRequestOutput {
    pub id: String,
    pub status: RequestStatus,
}

impl CancelRequest {
    pub fn execute(&self, input: CancelRequestInput, user: &AuthUser) -> Result<CancelRequestOutput, AppError> {
        if let Some(ref r) = input.reason {
            if r.len() > 1024 {
                return Err(AppError::Validation("reason too long (max 1024 bytes)".into()));
            }
        }

        let request = self.request_repo.get(&input.request_id)?
            .ok_or_else(|| AppError::NotFound("request not found".into()))?;

        self.authorizer.authorize_scoped(
            user, Permission::RequestCancel,
            &request.database, &request.environment,
            &ResourceContext::Request { requester_id: request.requester.clone() },
        ).map_err(AppError::Forbidden)?;

        let now = self.clock.now();
        let result = status_machine::transition(
            request.status,
            &RequestTrigger::Cancel,
            TransitionContext {
                request_id: request.id.clone(),
                actor_id: user.subject_id.clone(),
                actor_type: user.subject_type,
                database: request.database.clone(),
                environment: request.environment.clone(),
                operation: request.operation,
                timestamp: now,
                metadata: EventMetadata::Cancelled { reason: input.reason.clone() },
            },
        ).map_err(|e| AppError::Conflict(e.to_string()))?;

        let ok = self.request_repo.mark_cancelled(
            &request.id, &user.subject_id, input.reason.as_deref(), now,
        )?;
        if !ok {
            return Err(AppError::Conflict("concurrent status change".into()));
        }

        result.commit(&*self.event_dispatcher);

        Ok(CancelRequestOutput { id: request.id, status: RequestStatus::Cancelled })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbward_domain::auth::{SubjectType};
    use dbward_domain::services::status_machine::TransitionEvent;
    use dbward_domain::entities::Request;
    use dbward_domain::values::{DatabaseName, Environment, Operation};
    use chrono::{DateTime, Utc};
    use std::sync::Mutex;
    use crate::error::AuthzError;

    struct NoopDispatcher;
    impl EventDispatcher for NoopDispatcher { fn dispatch(&self, _: TransitionEvent) {} }
    struct AllowAll;
    impl Authorizer for AllowAll {
        fn authorize_scoped(&self, _: &AuthUser, _: Permission, _: &DatabaseName, _: &Environment, _: &ResourceContext) -> Result<(), AuthzError> { Ok(()) }
        fn authorize_global(&self, _: &AuthUser, _: Permission) -> Result<(), AuthzError> { Ok(()) }
    }
    struct DenyAll;
    impl Authorizer for DenyAll {
        fn authorize_scoped(&self, _: &AuthUser, p: Permission, _: &DatabaseName, _: &Environment, _: &ResourceContext) -> Result<(), AuthzError> {
            Err(AuthzError::Forbidden { permission: p, reason: "denied".into() })
        }
        fn authorize_global(&self, _: &AuthUser, p: Permission) -> Result<(), AuthzError> {
            Err(AuthzError::Forbidden { permission: p, reason: "denied".into() })
        }
    }
    struct FakeClock;
    impl Clock for FakeClock { fn now(&self) -> DateTime<Utc> { Utc::now() } }

    struct FakeRepo { request: Mutex<Option<Request>>, cancelled: Mutex<bool> }
    impl RequestRepo for FakeRepo {
        fn insert(&self, _: &Request) -> Result<(), AppError> { Ok(()) }
        fn get(&self, _: &str) -> Result<Option<Request>, AppError> { Ok(self.request.lock().unwrap().clone()) }
        fn list(&self, _: u32, _: u32) -> Result<(Vec<Request>, u32), AppError> { Ok((vec![], 0)) }
        fn find_by_idempotency_key(&self, _: &str) -> Result<Option<Request>, AppError> { Ok(None) }
        fn insert_approval(&self, _: &dbward_domain::entities::Approval) -> Result<(), AppError> { Ok(()) }
        fn get_approvals(&self, _: &str) -> Result<Vec<dbward_domain::entities::Approval>, AppError> { Ok(vec![]) }
        fn count_executions(&self, _: &str) -> Result<u32, AppError> { Ok(0) }
        fn mark_approved(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> { Ok(true) }
        fn approve_and_mark_approved(&self, _: &dbward_domain::entities::Approval, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> { Ok(true) }
        fn mark_rejected(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> { Ok(true) }
        fn reject_and_record(&self, _: &str, _: &dbward_domain::entities::Approval, _: DateTime<Utc>) -> Result<bool, AppError> { Ok(true) }
        fn mark_cancelled(&self, _: &str, _: &str, _: Option<&str>, _: DateTime<Utc>) -> Result<bool, AppError> { *self.cancelled.lock().unwrap() = true; Ok(true) }
        fn mark_dispatched(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> { Ok(true) }
        fn create_and_dispatch(&self, _: &Request) -> Result<(), AppError> { Ok(()) }
        fn mark_running(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> { Ok(true) }
        fn mark_executed(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> { Ok(true) }
        fn mark_failed(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> { Ok(true) }
        fn cancel_all_for_user(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<u32, AppError> { Ok(0) }
        fn find_expired_approved(&self, _: &str) -> Result<Vec<String>, AppError> { Ok(vec![]) }
        fn find_expired_pending(&self, _: &str) -> Result<Vec<String>, AppError> { Ok(vec![]) }
        fn find_stale_dispatched(&self, _: &str) -> Result<Vec<String>, AppError> { Ok(vec![]) }
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
    fn cancel_pending_succeeds() {
        let repo = Arc::new(FakeRepo { request: Mutex::new(Some(make_request(RequestStatus::Pending))), cancelled: Mutex::new(false) });
        let uc = CancelRequest { authorizer: Arc::new(AllowAll), request_repo: repo.clone(), event_dispatcher: Arc::new(NoopDispatcher), clock: Arc::new(FakeClock) };
        let user = AuthUser { subject_id: "alice".into(), subject_type: SubjectType::User, roles: vec![], groups: vec![], token_id: None };
        let out = uc.execute(CancelRequestInput { request_id: "req-001".into(), reason: Some("changed mind".into()) }, &user).unwrap();
        assert_eq!(out.status, RequestStatus::Cancelled);
        assert!(*repo.cancelled.lock().unwrap());
    }

    #[test]
    fn cancel_rejected_fails() {
        let repo = Arc::new(FakeRepo { request: Mutex::new(Some(make_request(RequestStatus::Rejected))), cancelled: Mutex::new(false) });
        let uc = CancelRequest { authorizer: Arc::new(AllowAll), request_repo: repo.clone(), event_dispatcher: Arc::new(NoopDispatcher), clock: Arc::new(FakeClock) };
        let user = AuthUser { subject_id: "alice".into(), subject_type: SubjectType::User, roles: vec![], groups: vec![], token_id: None };
        assert!(matches!(uc.execute(CancelRequestInput { request_id: "req-001".into(), reason: None }, &user), Err(AppError::Conflict(_))));
    }

    #[test]
    fn cancel_denied_by_authorizer() {
        let repo = Arc::new(FakeRepo { request: Mutex::new(Some(make_request(RequestStatus::Pending))), cancelled: Mutex::new(false) });
        let uc = CancelRequest { authorizer: Arc::new(DenyAll), request_repo: repo.clone(), event_dispatcher: Arc::new(NoopDispatcher), clock: Arc::new(FakeClock) };
        let user = AuthUser { subject_id: "bob".into(), subject_type: SubjectType::User, roles: vec![], groups: vec![], token_id: None };
        assert!(matches!(uc.execute(CancelRequestInput { request_id: "req-001".into(), reason: None }, &user), Err(AppError::Forbidden(_))));
    }
}
