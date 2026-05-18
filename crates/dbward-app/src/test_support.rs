#![allow(clippy::new_without_default)]
//! Shared test doubles for use case unit tests.

use std::sync::Mutex;

use chrono::{DateTime, Utc};

use dbward_domain::auth::{AuthUser, Permission, ResourceContext};
use dbward_domain::entities::*;
use dbward_domain::policies::Workflow;
use dbward_domain::services::status_machine::{EventDispatcher, TransitionEvent};
use dbward_domain::values::{DatabaseName, Environment, Operation};

use crate::error::{AppError, AuthzError};
use crate::ports::*;

// --- Authorizer ---

pub struct AllowAll;
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

pub struct DenyAll;
impl Authorizer for DenyAll {
    fn authorize_scoped(
        &self,
        _: &AuthUser,
        p: Permission,
        _: &DatabaseName,
        _: &Environment,
        _: &ResourceContext,
    ) -> Result<(), AuthzError> {
        Err(AuthzError::Forbidden {
            permission: p,
            reason: "denied".into(),
        })
    }
    fn authorize_global(&self, _: &AuthUser, p: Permission) -> Result<(), AuthzError> {
        Err(AuthzError::Forbidden {
            permission: p,
            reason: "denied".into(),
        })
    }
}

// --- Clock / IdGenerator ---

pub struct FixedClock(pub DateTime<Utc>);
impl FixedClock {
    pub fn now_utc() -> Self {
        Self(Utc::now())
    }
}
impl Clock for FixedClock {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}

pub struct FixedIdGen(pub Mutex<u32>);
impl FixedIdGen {
    pub fn new() -> Self {
        Self(Mutex::new(0))
    }
}
impl IdGenerator for FixedIdGen {
    fn generate(&self) -> String {
        let mut n = self.0.lock().unwrap();
        *n += 1;
        format!("test-id-{n:03}")
    }
}

// --- EventDispatcher ---

pub struct NoopDispatcher;
impl EventDispatcher for NoopDispatcher {
    fn dispatch(&self, _: TransitionEvent) {}
}

// --- AuditLogger ---

pub struct NoopAuditLogger;
impl crate::ports::AuditLogger for NoopAuditLogger {
    fn record(&self, _: &AuditEvent) -> Result<(), AppError> {
        Ok(())
    }
}

// --- RequestReader ---

pub struct FakeRequestReader {
    pub request: Mutex<Option<Request>>,
    pub requests: Mutex<Vec<Request>>,
    pub is_approver: bool,
}

impl FakeRequestReader {
    pub fn new() -> Self {
        Self {
            request: Mutex::new(None),
            requests: Mutex::new(vec![]),
            is_approver: false,
        }
    }

    pub fn with_request(req: Request) -> Self {
        Self {
            request: Mutex::new(Some(req)),
            requests: Mutex::new(vec![]),
            is_approver: false,
        }
    }
}

impl RequestReader for FakeRequestReader {
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
        let reqs = self.requests.lock().unwrap().clone();
        let total = reqs.len() as u32;
        Ok((reqs, total))
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
    fn is_pending_approver(
        &self,
        _: &str,
        _: &str,
        _: &[String],
        _: &[String],
    ) -> Result<bool, AppError> {
        Ok(self.is_approver)
    }
    fn count_executions(&self, _: &str) -> Result<u32, AppError> {
        Ok(0)
    }
    fn list_results_for_user(
        &self,
        _: &str,
        _: &[String],
        _: &[String],
        _: u32,
    ) -> Result<Vec<StoredResultEntry>, AppError> {
        Ok(vec![])
    }
    fn count_by_status(&self, _: &str) -> Result<u32, AppError> {
        Ok(0)
    }
    fn get_pending_approvers_for_requests(
        &self,
        _: &[&str],
    ) -> Result<std::collections::HashMap<String, (u32, Vec<String>)>, AppError> {
        Ok(std::collections::HashMap::new())
    }
}

// --- RequestWriter ---

pub struct FakeRequestWriter {
    pub written: Mutex<bool>,
}

impl FakeRequestWriter {
    pub fn new() -> Self {
        Self {
            written: Mutex::new(false),
        }
    }
}

impl RequestWriter for FakeRequestWriter {
    fn insert(&self, _: &Request) -> Result<(), AppError> {
        *self.written.lock().unwrap() = true;
        Ok(())
    }
    fn create_and_dispatch(&self, _: &Request) -> Result<(), AppError> {
        *self.written.lock().unwrap() = true;
        Ok(())
    }
    fn mark_approved(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
        Ok(true)
    }
    fn mark_rejected(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
        Ok(true)
    }
    fn mark_cancelled(
        &self,
        _: &str,
        _: &str,
        _: Option<&str>,
        _: DateTime<Utc>,
    ) -> Result<bool, AppError> {
        *self.written.lock().unwrap() = true;
        Ok(true)
    }
    fn mark_dispatched(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
        *self.written.lock().unwrap() = true;
        Ok(true)
    }
    fn mark_running(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
        Ok(true)
    }
    fn mark_executed(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
        Ok(true)
    }
    fn mark_failed(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
        Ok(true)
    }
    fn cancel_all_for_user(&self, _: &str, _: DateTime<Utc>) -> Result<u32, AppError> {
        Ok(0)
    }
    fn mark_approved_from_dispatched(&self, _: &str, _: &str) -> Result<bool, AppError> {
        Ok(true)
    }
}

// --- ApprovalRepo ---

pub struct FakeApprovalRepo {
    pub approvals: Mutex<Vec<Approval>>,
    pub marked_approved: Mutex<bool>,
}

impl FakeApprovalRepo {
    pub fn new() -> Self {
        Self {
            approvals: Mutex::new(vec![]),
            marked_approved: Mutex::new(false),
        }
    }
}

impl ApprovalRepo for FakeApprovalRepo {
    fn insert_approval(&self, a: &Approval) -> Result<(), AppError> {
        self.approvals.lock().unwrap().push(a.clone());
        Ok(())
    }
    fn get_approvals(&self, _: &str) -> Result<Vec<Approval>, AppError> {
        Ok(self.approvals.lock().unwrap().clone())
    }
    fn approve_and_mark_approved(
        &self,
        a: &Approval,
        _: &str,
        _: DateTime<Utc>,
    ) -> Result<bool, AppError> {
        self.approvals.lock().unwrap().push(a.clone());
        *self.marked_approved.lock().unwrap() = true;
        Ok(true)
    }
    fn reject_and_record(&self, _: &str, a: &Approval, _: DateTime<Utc>) -> Result<bool, AppError> {
        self.approvals.lock().unwrap().push(a.clone());
        Ok(true)
    }
}

// --- BackgroundTaskRepo ---

pub struct FakeBackgroundTaskRepo;
impl BackgroundTaskRepo for FakeBackgroundTaskRepo {
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
    fn mark_expired_and_record(&self, _: &str, _: &AuditEvent, _: &str) -> Result<bool, AppError> {
        Ok(true)
    }
    fn purge_old_requests(&self, _: &str) -> Result<u32, AppError> {
        Ok(0)
    }
}

// --- PolicyEvaluator ---

pub struct FakePolicyEvaluator;
impl PolicyEvaluator for FakePolicyEvaluator {
    fn evaluate_workflow(
        &self,
        _: &DatabaseName,
        _: &Environment,
        _: Operation,
    ) -> Result<Option<Workflow>, AppError> {
        Ok(Some(Workflow {
            id: "test-wf".into(),
            database: DatabaseName::wildcard(),
            environment: Environment::wildcard(),
            operations: vec![],
            steps: vec![],
            skip_approval_for: vec![],
            require_reason: false,
            allow_self_approve: false,
            allow_same_approver_across_steps: false,
            pending_ttl_secs: None,
            statement_timeout_secs: None,
            approval_ttl_secs: None,
            created_at: None,
            updated_at: None,
        }))
    }
    fn get_execution_policy(
        &self,
        _: &DatabaseName,
        _: &Environment,
    ) -> dbward_domain::policies::ExecutionPolicy {
        Default::default()
    }
}

// --- DatabaseRegistry ---

pub struct FakeDatabaseRegistry;
impl DatabaseRegistry for FakeDatabaseRegistry {
    fn register(&self, _: &DatabaseName, _: &Environment) -> Result<(), AppError> {
        Ok(())
    }
    fn exists(&self, _: &DatabaseName, _: &Environment) -> Result<bool, AppError> {
        Ok(true)
    }
    fn list(&self) -> Result<Vec<(DatabaseName, Environment)>, AppError> {
        Ok(vec![])
    }
}
