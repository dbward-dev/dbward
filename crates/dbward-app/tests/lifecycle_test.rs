#![allow(dead_code, unused_imports, unused_variables)]
//! Integration tests: UC chain verification with shared in-memory state.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};

use dbward_domain::auth::{AuthUser, Permission, ResolvedRole, ResourceContext, SubjectType};
use dbward_domain::entities::*;
use dbward_domain::policies::workflow::*;
use dbward_domain::policies::{ExecutionPolicy, ResultPolicy};
use dbward_domain::values::*;

use dbward_app::error::{AppError, AuthzError};
use dbward_app::ports::*;
use dbward_app::use_cases::{
    approve_request::{ApproveRequest, ApproveRequestInput},
    cancel_request::{CancelRequest, CancelRequestInput},
    create_request::{CreateRequest, CreateRequestInput, RequestChannel},
    reject_request::{RejectRequest, RejectRequestInput},
    resume_request::{ResumeRequest, ResumeRequestInput},
};

// --- Shared Fake Infrastructure ---

struct SharedRepo {
    requests: Mutex<Vec<Request>>,
    approvals: Mutex<Vec<Approval>>,
    audit_events: Mutex<Vec<AuditEvent>>,
}

impl SharedRepo {
    fn new() -> Self {
        Self {
            requests: Mutex::new(vec![]),
            approvals: Mutex::new(vec![]),
            audit_events: Mutex::new(vec![]),
        }
    }
}

impl RequestReader for SharedRepo {
    fn get(&self, id: &str) -> Result<Option<Request>, AppError> {
        Ok(self
            .requests
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.id == id)
            .cloned())
    }
    fn list(
        &self,
        _limit: u32,
        _offset: u32,
        _status: Option<&str>,
        _user: Option<&str>,
    ) -> Result<(Vec<Request>, u32), AppError> {
        let reqs = self.requests.lock().unwrap().clone();
        let total = reqs.len() as u32;
        Ok((reqs, total))
    }
    fn find_by_idempotency_key(
        &self,
        _requester: &str,
        key: &str,
    ) -> Result<Option<Request>, AppError> {
        Ok(self
            .requests
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.idempotency_key.as_deref() == Some(key))
            .cloned())
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
        Ok(false)
    }
    fn count_executions(&self, _: &str) -> Result<u32, AppError> {
        Ok(0)
    }
    fn count_completed_executions(&self, _: &str) -> Result<u32, AppError> {
        Ok(0)
    }
    fn find_stored_execution_ids(&self, _: &str) -> Result<Vec<String>, AppError> {
        Ok(vec![])
    }
    fn list_results_for_user(
        &self,
        _: &str,
        _: &[String],
        _: &[String],
        _: u32,
    ) -> Result<Vec<dbward_app::ports::repos::StoredResultEntry>, AppError> {
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

impl RequestWriter for SharedRepo {
    fn insert(&self, req: &Request) -> Result<(), AppError> {
        self.requests.lock().unwrap().push(req.clone());
        Ok(())
    }
    fn create_and_dispatch(&self, req: &Request) -> Result<(), AppError> {
        let mut reqs = self.requests.lock().unwrap();
        let mut r = req.clone();
        r.status = RequestStatus::Dispatched;
        reqs.push(r);
        Ok(())
    }
    fn mark_approved(&self, id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        let mut reqs = self.requests.lock().unwrap();
        if let Some(r) = reqs.iter_mut().find(|r| r.id == id) {
            r.status = RequestStatus::Approved;
            r.resolved_at = Some(now);
            r.updated_at = now;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn mark_rejected(&self, id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        let mut reqs = self.requests.lock().unwrap();
        if let Some(r) = reqs.iter_mut().find(|r| r.id == id) {
            r.status = RequestStatus::Rejected;
            r.updated_at = now;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn mark_cancelled(
        &self,
        id: &str,
        actor: &str,
        reason: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<bool, AppError> {
        let mut reqs = self.requests.lock().unwrap();
        if let Some(r) = reqs.iter_mut().find(|r| r.id == id) {
            r.status = RequestStatus::Cancelled;
            r.cancelled_by = Some(actor.to_string());
            r.cancel_reason = reason.map(|s| s.to_string());
            r.updated_at = now;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn mark_dispatched(&self, id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        let mut reqs = self.requests.lock().unwrap();
        if let Some(r) = reqs.iter_mut().find(|r| r.id == id) {
            r.status = RequestStatus::Dispatched;
            r.updated_at = now;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn mark_running(&self, id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        let mut reqs = self.requests.lock().unwrap();
        if let Some(r) = reqs.iter_mut().find(|r| r.id == id) {
            r.status = RequestStatus::Running;
            r.updated_at = now;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn mark_executed(&self, id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        let mut reqs = self.requests.lock().unwrap();
        if let Some(r) = reqs.iter_mut().find(|r| r.id == id) {
            r.status = RequestStatus::Executed;
            r.updated_at = now;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn mark_failed(&self, id: &str, now: DateTime<Utc>) -> Result<bool, AppError> {
        let mut reqs = self.requests.lock().unwrap();
        if let Some(r) = reqs.iter_mut().find(|r| r.id == id) {
            r.status = RequestStatus::Failed;
            r.updated_at = now;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn cancel_all_for_user(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: DateTime<Utc>,
        _: &dbward_domain::entities::AuditContext,
    ) -> Result<Vec<String>, AppError> {
        Ok(vec![])
    }
    fn mark_approved_from_dispatched(&self, _: &str, _: &str) -> Result<bool, AppError> {
        Ok(true)
    }
}

impl ApprovalRepo for SharedRepo {
    fn insert_approval(&self, a: &Approval) -> Result<(), AppError> {
        self.approvals.lock().unwrap().push(a.clone());
        Ok(())
    }
    fn get_approvals(&self, request_id: &str) -> Result<Vec<Approval>, AppError> {
        Ok(self
            .approvals
            .lock()
            .unwrap()
            .iter()
            .filter(|a| a.request_id == request_id)
            .cloned()
            .collect())
    }
    fn approve_and_mark_approved(
        &self,
        approval: &Approval,
        request_id: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, AppError> {
        self.approvals.lock().unwrap().push(approval.clone());
        let mut reqs = self.requests.lock().unwrap();
        if let Some(r) = reqs.iter_mut().find(|r| r.id == request_id) {
            r.status = RequestStatus::Approved;
            r.resolved_at = Some(now);
            r.updated_at = now;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn reject_and_record(
        &self,
        request_id: &str,
        approval: &Approval,
        now: DateTime<Utc>,
    ) -> Result<bool, AppError> {
        self.approvals.lock().unwrap().push(approval.clone());
        let mut reqs = self.requests.lock().unwrap();
        if let Some(r) = reqs.iter_mut().find(|r| r.id == request_id) {
            r.status = RequestStatus::Rejected;
            r.updated_at = now;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl BackgroundTaskRepo for SharedRepo {
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
    fn purge_old_requests(&self, _: &str) -> Result<u32, AppError> {
        Ok(0)
    }
}

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

struct FakePolicy {
    workflow: Option<Workflow>,
    exec_policy: ExecutionPolicy,
}
impl PolicyEvaluator for FakePolicy {
    fn evaluate_workflow(
        &self,
        _: &DatabaseName,
        _: &Environment,
        _: Operation,
    ) -> Result<Option<Workflow>, AppError> {
        Ok(self.workflow.clone())
    }
    fn get_execution_policy(
        &self,
        _: &DatabaseName,
        _: &Environment,
    ) -> Result<ExecutionPolicy, AppError> {
        Ok(self.exec_policy.clone())
    }
}

struct FakeDbRegistry;
impl DatabaseRegistry for FakeDbRegistry {
    fn register(&self, _: &DatabaseName, _: &Environment) -> Result<(), AppError> {
        Ok(())
    }
    fn exists_active(&self, _: &DatabaseName, _: &Environment) -> Result<bool, AppError> {
        Ok(true)
    }
    fn list_active(&self) -> Result<Vec<(DatabaseName, Environment)>, AppError> {
        Ok(vec![])
    }
}

struct FakeClock {
    now: Mutex<DateTime<Utc>>,
}
impl FakeClock {
    fn new() -> Self {
        Self {
            now: Mutex::new(Utc::now()),
        }
    }
    fn advance(&self, secs: i64) {
        let mut n = self.now.lock().unwrap();
        *n += Duration::seconds(secs);
    }
}
impl Clock for FakeClock {
    fn now(&self) -> DateTime<Utc> {
        *self.now.lock().unwrap()
    }
}

struct SeqIdGen {
    counter: Mutex<u32>,
}
impl SeqIdGen {
    fn new() -> Self {
        Self {
            counter: Mutex::new(0),
        }
    }
}
impl IdGenerator for SeqIdGen {
    fn generate(&self) -> String {
        let mut c = self.counter.lock().unwrap();
        *c += 1;
        format!("{:032x}", *c)
    }
}

struct FakeTokenValueGen;
impl dbward_app::ports::TokenValueGenerator for FakeTokenValueGen {
    fn generate_token_value(&self) -> String {
        "dbw_faketoken1234567890abcdef1234".into()
    }
}

// --- Helpers ---

fn make_user(id: &str, roles: &[&str]) -> AuthUser {
    AuthUser {
        subject_id: id.to_string(),
        subject_type: SubjectType::User,
        roles: roles
            .iter()
            .map(|name| ResolvedRole {
                name: name.to_string(),
                permissions: [
                    Permission::RequestExecute,
                    Permission::RequestApprove,
                    Permission::RequestResume,
                    Permission::RequestCancel,
                ]
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
        approval_ttl_secs: Some(3600),
        created_at: None,
        updated_at: None,
    }
}

fn two_step_workflow() -> Workflow {
    Workflow {
        id: "wf-2".into(),
        database: DatabaseName::new("app").unwrap(),
        environment: Environment::new("production").unwrap(),
        operations: vec![],
        auto_approve: None,
        steps: vec![
            WorkflowStep {
                approvers: vec![ApproverGroup {
                    selector: Selector::Role("dba".into()),
                    min: 1,
                }],
                mode: WorkflowStepMode::Any,
            },
            WorkflowStep {
                approvers: vec![ApproverGroup {
                    selector: Selector::Role("cto".into()),
                    min: 1,
                }],
                mode: WorkflowStepMode::Any,
            },
        ],
        require_reason: false,
        allow_self_approve: false,
        allow_same_approver_across_steps: true,
        explain: true,
        pending_ttl_secs: None,
        statement_timeout_secs: None,
        approval_ttl_secs: Some(3600),
        created_at: None,
        updated_at: None,
    }
}

fn make_input() -> CreateRequestInput {
    CreateRequestInput {
        database: DatabaseName::new("app").unwrap(),
        environment: Environment::new("production").unwrap(),
        operation: Operation::ExecuteDml,
        detail: "UPDATE users SET active = true WHERE id > 0".into(),
        reason: None,
        emergency: false,
        allow_ddl: false,
        idempotency_key: None,
        share_with: vec![],
        no_result_store: false,
        metadata_json: "{}".into(),
        channel: RequestChannel::Cli,
    }
}

mod common {
    use dbward_app::error::AppError;
    use dbward_app::ports::transaction::*;

    pub struct NoopUnitOfWork;
    impl dbward_app::ports::UnitOfWork for NoopUnitOfWork {
        fn execute(
            &self,
            f: Box<dyn FnOnce(&dyn TxScope) -> Result<(), AppError> + '_>,
        ) -> Result<(), AppError> {
            f(&NoopTx)
        }
        fn execute_with_result(
            &self,
            f: Box<dyn FnOnce(&dyn TxScope) -> Result<Box<dyn std::any::Any>, AppError> + '_>,
        ) -> Result<Box<dyn std::any::Any>, AppError> {
            f(&NoopTx)
        }

        fn execute_sync(
            &self,
            f: Box<
                dyn FnOnce(
                        &dyn dbward_app::ports::sync_scope::SyncScope,
                    )
                        -> Result<Box<dyn std::any::Any>, dbward_app::error::AppError>
                    + '_,
            >,
        ) -> Result<Box<dyn std::any::Any>, dbward_app::error::AppError> {
            Ok(Box::new(()) as Box<dyn std::any::Any>)
        }
    }
    struct NoopTx;
    impl RequestWriterOps for NoopTx {
        fn insert_request(&self, _: &dbward_domain::entities::Request) -> Result<(), AppError> {
            Ok(())
        }
        fn mark_dispatched(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_approved(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_rejected(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_running(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_cancelled(
            &self,
            _: &str,
            _: &str,
            _: Option<&str>,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_executed(
            &self,
            _: &str,
            _: bool,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_expired(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn cancel_all_for_user(
            &self,
            _: &str,
            _: &str,
            _: Option<&str>,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<Vec<String>, AppError> {
            Ok(vec![])
        }
        fn mark_execution_lost(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn mark_approved_from_dispatched(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
    }
    impl ApprovalWriterOps for NoopTx {
        fn insert_approval(&self, _: &dbward_domain::entities::Approval) -> Result<(), AppError> {
            Ok(())
        }
    }
    impl AuditWriterOps for NoopTx {
        fn record(&self, _: &dbward_domain::entities::AuditEvent) -> Result<(), AppError> {
            Ok(())
        }
    }
    impl ExecutionWriterOps for NoopTx {
        fn insert_execution(&self, _: &dbward_domain::entities::Execution) -> Result<(), AppError> {
            Ok(())
        }
        fn mark_completed(
            &self,
            _: &str,
            _: bool,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
    }
    impl TokenWriterOps for NoopTx {
        fn create_token(&self, _: &dbward_domain::entities::Token) -> Result<(), AppError> {
            Ok(())
        }
        fn revoke_token(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn revoke_all_for_user(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<u32, AppError> {
            Ok(0)
        }
    }
    impl UserWriterOps for NoopTx {
        fn suspend_user(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
        fn activate_user(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<bool, AppError> {
            Ok(true)
        }
    }
    impl dbward_app::ports::ResultWriterOps for NoopTx {
        fn insert_result(
            &self,
            _: &dbward_domain::entities::ExecutionResult,
        ) -> Result<(), AppError> {
            Ok(())
        }
        fn insert_result_access(
            &self,
            _: &[dbward_domain::entities::ResultAccess],
        ) -> Result<(), AppError> {
            Ok(())
        }
    }
    impl ApprovalReaderOps for NoopTx {
        fn get_approvals(
            &self,
            _: &str,
        ) -> Result<Vec<dbward_domain::entities::Approval>, AppError> {
            Ok(vec![])
        }
        fn get_request_state(
            &self,
            _: &str,
        ) -> Result<Option<dbward_app::ports::transaction::RequestState>, AppError> {
            Ok(Some((
                dbward_domain::entities::RequestStatus::Pending,
                None,
            )))
        }
    }
    impl TxScope for NoopTx {}

    pub struct NoopNotifier;
    impl dbward_app::ports::Notifier for NoopNotifier {
        fn dispatch(&self, _: dbward_app::ports::WebhookEvent) {}
    }
}

struct FakeResultChannel;
#[async_trait]
impl ResultChannel for FakeResultChannel {
    fn create_slot(&self, _: &str) {}
    async fn publish(&self, _: &str, _: ResultSummary) {}
    async fn subscribe(&self, _: &str, _: u64) -> Result<Option<ResultSummary>, AppError> {
        Ok(None)
    }
    async fn notify_all(&self) {}
}

struct FakeAuditLogger;
impl AuditLogger for FakeAuditLogger {
    fn record(&self, _: &dbward_domain::entities::AuditEvent) -> Result<(), AppError> {
        Ok(())
    }
}

struct NoopBreakGlassMetrics;
impl BreakGlassMetrics for NoopBreakGlassMetrics {
    fn record_ddl_attempted(&self) {}
    fn record_ddl_allowed(&self) {}
    fn record_ddl_denied(&self) {}
    fn record_audit_failure(&self) {}
}

struct FakeLicenseChecker;
impl LicenseChecker for FakeLicenseChecker {
    fn max_users(&self) -> u32 {
        20
    }
    fn max_databases(&self) -> u32 {
        u32::MAX
    }
    fn max_workflows(&self) -> u32 {
        5
    }
    fn max_webhooks(&self) -> u32 {
        3
    }
    fn max_roles(&self) -> u32 {
        8
    }
    fn is_enterprise(&self) -> bool {
        false
    }
    fn configured_plan(&self) -> &str {
        "free"
    }
    fn effective_plan(&self) -> &str {
        "free"
    }
    fn is_expired(&self) -> bool {
        false
    }
    fn check_expiry(&self, _now: chrono::DateTime<chrono::Utc>) {}
}

struct FakePolicyRepoForDispatch;
impl PolicyRepo for FakePolicyRepoForDispatch {
    fn create_workflow(
        &self,
        _: &dbward_domain::policies::workflow::Workflow,
    ) -> Result<(), AppError> {
        Ok(())
    }
    fn get_workflow(
        &self,
        _: &str,
    ) -> Result<Option<dbward_domain::policies::workflow::Workflow>, AppError> {
        Ok(None)
    }
    fn list_workflows(&self) -> Result<Vec<dbward_domain::policies::workflow::Workflow>, AppError> {
        Ok(vec![])
    }
    fn delete_workflow(&self, _: &str) -> Result<bool, AppError> {
        Ok(true)
    }
    fn count_workflows(&self) -> Result<u32, AppError> {
        Ok(0)
    }
    fn create_execution_policy(&self, _: &ExecutionPolicy) -> Result<(), AppError> {
        Ok(())
    }
    fn get_execution_policy(&self, _: &str) -> Result<Option<ExecutionPolicy>, AppError> {
        Ok(None)
    }
    fn list_execution_policies(&self) -> Result<Vec<ExecutionPolicy>, AppError> {
        Ok(vec![])
    }
    fn delete_execution_policy(&self, _: &str) -> Result<bool, AppError> {
        Ok(true)
    }
    fn find_result_policy(
        &self,
        _: &DatabaseName,
        _: &Environment,
    ) -> Result<Option<ResultPolicy>, AppError> {
        Ok(None)
    }

    fn create_result_policy(
        &self,
        _: &dbward_domain::policies::ResultPolicy,
    ) -> Result<(), AppError> {
        Ok(())
    }
    fn get_result_policy(
        &self,
        _: &str,
    ) -> Result<Option<dbward_domain::policies::ResultPolicy>, AppError> {
        Ok(None)
    }
    fn list_result_policies(&self) -> Result<Vec<dbward_domain::policies::ResultPolicy>, AppError> {
        Ok(vec![])
    }
    fn update_result_policy(
        &self,
        _: &dbward_domain::policies::ResultPolicy,
    ) -> Result<bool, AppError> {
        Ok(false)
    }
    fn delete_result_policy(&self, _: &str) -> Result<bool, AppError> {
        Ok(false)
    }
    fn create_notification_policy(
        &self,
        _: &dbward_domain::policies::NotificationPolicy,
    ) -> Result<(), AppError> {
        Ok(())
    }
    fn get_notification_policy(
        &self,
        _: &str,
    ) -> Result<Option<dbward_domain::policies::NotificationPolicy>, AppError> {
        Ok(None)
    }
    fn list_notification_policies(
        &self,
    ) -> Result<Vec<dbward_domain::policies::NotificationPolicy>, AppError> {
        Ok(vec![])
    }
    fn update_notification_policy(
        &self,
        _: &dbward_domain::policies::NotificationPolicy,
    ) -> Result<bool, AppError> {
        Ok(false)
    }
    fn delete_notification_policy(&self, _: &str) -> Result<bool, AppError> {
        Ok(false)
    }
    fn create_role(&self, _: &dbward_domain::auth::RoleDefinition) -> Result<(), AppError> {
        Ok(())
    }
    fn list_roles(&self) -> Result<Vec<dbward_domain::auth::RoleDefinition>, AppError> {
        Ok(vec![])
    }
    fn get_roles_by_names(
        &self,
        _: &[String],
    ) -> Result<Vec<dbward_domain::auth::RoleDefinition>, AppError> {
        Ok(vec![])
    }
    fn delete_role(&self, _: &str) -> Result<bool, AppError> {
        Ok(true)
    }
    fn count_roles(&self) -> Result<u32, AppError> {
        Ok(0)
    }
}

struct TestHarness {
    repo: Arc<SharedRepo>,
    clock: Arc<FakeClock>,
    id_gen: Arc<SeqIdGen>,
    authorizer: Arc<dyn Authorizer>,
    policy: Arc<FakePolicy>,
    uow: Arc<common::NoopUnitOfWork>,
    notifier: Arc<common::NoopNotifier>,
    db_registry: Arc<dyn DatabaseRegistry>,
    result_channel: Arc<dyn ResultChannel>,
    audit_logger: Arc<dyn AuditLogger>,
}

impl TestHarness {
    fn new(workflow: Option<Workflow>) -> Self {
        Self {
            repo: Arc::new(SharedRepo::new()),
            clock: Arc::new(FakeClock::new()),
            id_gen: Arc::new(SeqIdGen::new()),
            authorizer: Arc::new(AllowAll),
            policy: Arc::new(FakePolicy {
                workflow,
                exec_policy: ExecutionPolicy::default(),
            }),
            uow: Arc::new(common::NoopUnitOfWork),
            notifier: Arc::new(common::NoopNotifier),
            db_registry: Arc::new(FakeDbRegistry),
            result_channel: Arc::new(FakeResultChannel),
            audit_logger: Arc::new(FakeAuditLogger),
        }
    }

    fn with_exec_policy(mut self, ep: ExecutionPolicy) -> Self {
        self.policy = Arc::new(FakePolicy {
            workflow: self.policy.workflow.clone(),
            exec_policy: ep,
        });
        self
    }

    fn create_uc(&self) -> CreateRequest {
        struct FakeSchemaRepo;
        impl SchemaRepo for FakeSchemaRepo {
            fn upsert_snapshot(&self, _: &SchemaSnapshotRecord) -> Result<(), AppError> {
                Ok(())
            }
            fn get_snapshot(
                &self,
                _: &str,
                _: &str,
            ) -> Result<Option<SchemaSnapshotRecord>, AppError> {
                Ok(None)
            }
            fn get_dialect(&self, _: &str, _: &str) -> Result<Option<String>, AppError> {
                Ok(None)
            }
            fn get_tables_for(
                &self,
                _: &str,
                _: &str,
                _: &[dbward_domain::services::table_extractor::TableRef],
            ) -> Result<Option<String>, AppError> {
                Ok(None)
            }
        }
        struct FakeDryRunRepo;
        impl DryRunRepo for FakeDryRunRepo {
            fn create_jobs(&self, _: &[DryRunJobRecord]) -> Result<(), AppError> {
                Ok(())
            }
            fn find_pending_for_agent(
                &self,
                _: &[(String, String)],
            ) -> Result<Vec<DryRunJobRecord>, AppError> {
                Ok(vec![])
            }
            fn claim(&self, _: &str, _: &str, _: &str, _: &str) -> Result<bool, AppError> {
                Ok(false)
            }
            fn complete(
                &self,
                _: &str,
                _: &str,
                _: &str,
                _: &str,
                _: &str,
            ) -> Result<bool, AppError> {
                Ok(false)
            }
            fn fail(&self, _: &str, _: &str, _: &str, _: &str, _: &str) -> Result<bool, AppError> {
                Ok(false)
            }
            fn reclaim_stale(&self, _: &str) -> Result<u32, AppError> {
                Ok(0)
            }
            fn find_for_request(&self, _: &str) -> Result<Vec<DryRunJobRecord>, AppError> {
                Ok(vec![])
            }
            fn get_request_id(&self, _: &str) -> Result<Option<String>, AppError> {
                Ok(None)
            }
        }
        struct FakeContextRepo;
        impl ContextRepo for FakeContextRepo {
            fn create(&self, _: &RequestContextRecord) -> Result<(), AppError> {
                Ok(())
            }
            fn get(&self, _: &str) -> Result<Option<RequestContextRecord>, AppError> {
                Ok(None)
            }
            fn update_explain(&self, _: &str, _: &str, _: &str, _: &str) -> Result<(), AppError> {
                Ok(())
            }
            fn timeout_collecting(&self, _: &str, _: &str) -> Result<u32, AppError> {
                Ok(0)
            }
        }
        CreateRequest {
            authorizer: self.authorizer.clone(),
            policy: self.policy.clone(),
            request_reader: self.repo.clone(),
            request_writer: self.repo.clone(),
            db_registry: self.db_registry.clone(),
            schema_repo: Arc::new(FakeSchemaRepo),
            dry_run_repo: Arc::new(FakeDryRunRepo),
            context_repo: Arc::new(FakeContextRepo),
            uow: self.uow.clone(),
            notifier: self.notifier.clone(),
            audit_logger: self.audit_logger.clone(),
            break_glass_metrics: Arc::new(NoopBreakGlassMetrics),
            clock: self.clock.clone(),
            id_gen: self.id_gen.clone(),
            default_approval_ttl_secs: Some(3600),
        }
    }

    fn approve_uc(&self) -> ApproveRequest {
        ApproveRequest {
            authorizer: self.authorizer.clone(),
            request_reader: self.repo.clone(),
            approval_repo: self.repo.clone(),
            uow: self.uow.clone(),
            notifier: self.notifier.clone(),
            clock: self.clock.clone(),
            id_gen: self.id_gen.clone(),
        }
    }

    fn reject_uc(&self) -> RejectRequest {
        RejectRequest {
            authorizer: self.authorizer.clone(),
            request_reader: self.repo.clone(),
            approval_repo: self.repo.clone(),
            uow: self.uow.clone(),
            notifier: self.notifier.clone(),
            clock: self.clock.clone(),
            id_gen: self.id_gen.clone(),
        }
    }

    fn cancel_uc(&self) -> CancelRequest {
        CancelRequest {
            authorizer: self.authorizer.clone(),
            request_reader: self.repo.clone(),
            uow: self.uow.clone(),
            notifier: self.notifier.clone(),
            clock: self.clock.clone(),
            redaction_mode: dbward_app::services::audit_event_builder::RedactionMode::None,
        }
    }

    fn resume_uc(&self) -> ResumeRequest {
        ResumeRequest {
            authorizer: self.authorizer.clone(),
            policy: self.policy.clone(),
            request_reader: self.repo.clone(),
            result_channel: self.result_channel.clone(),
            uow: self.uow.clone(),
            notifier: self.notifier.clone(),
            policy_repo: Arc::new(FakePolicyRepoForDispatch),
            clock: self.clock.clone(),
        }
    }
}

// === Tests ===

#[test]
fn emergency_without_reason_rejected() {
    let h = TestHarness::new(Some(single_step_workflow()));
    let requester = make_user("alice", &["developer"]);
    let mut input = make_input();
    input.emergency = true;
    // No reason provided
    let result = h.create_uc().execute(
        input,
        &requester,
        &dbward_domain::entities::AuditContext::System,
    );
    assert!(matches!(result, Err(AppError::Validation(_))));
}

#[test]
fn emergency_request_skips_approval() {
    let h = TestHarness::new(Some(single_step_workflow()));
    let requester = make_user("alice", &["developer"]);

    let mut input = make_input();
    input.emergency = true;
    input.reason = Some("critical fix".into());

    let created = h
        .create_uc()
        .execute(
            input,
            &requester,
            &dbward_domain::entities::AuditContext::System,
        )
        .unwrap();
    assert_eq!(created.status, RequestStatus::Dispatched);
    // Already dispatched at creation (ADR-004: break_glass → immediate dispatch)
}

#[test]
fn auto_approved_request_dispatches_directly() {
    // Workflow with auto_approve=always → auto_approved
    let auto_wf = Workflow {
        id: "wf-auto".into(),
        database: DatabaseName::new("*").unwrap(),
        environment: Environment::new("*").unwrap(),
        operations: vec![],
        auto_approve: Some(dbward_domain::policies::AutoApproveSettings {
            mode: dbward_domain::policies::AutoApproveMode::Always,
            max_risk_level: None,
            allow_read_only: true,
            allow_safe_ddl: true,
            max_estimated_rows: 1000,
        }),
        steps: vec![],
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
    let h = TestHarness::new(Some(auto_wf));
    let requester = make_user("alice", &["developer"]);

    let created = h
        .create_uc()
        .execute(
            make_input(),
            &requester,
            &dbward_domain::entities::AuditContext::System,
        )
        .unwrap();
    assert_eq!(created.status, RequestStatus::Dispatched);
    // Already dispatched at creation (ADR-004: auto_approved → immediate dispatch)
}

// === Agent Flow Tests ===

use dbward_app::use_cases::{
    agent_claim::{AgentClaim, AgentClaimInput},
    agent_heartbeat::{AgentHeartbeat, AgentHeartbeatInput},
    agent_poll::{AgentPoll, AgentPollInput},
};

struct SharedAgentRepo {
    executions: Mutex<Vec<Execution>>,
    request_repo: Arc<SharedRepo>,
}

impl SharedAgentRepo {
    fn new(request_repo: Arc<SharedRepo>) -> Self {
        Self {
            executions: Mutex::new(vec![]),
            request_repo,
        }
    }
}

impl AgentRepo for SharedAgentRepo {
    fn upsert(&self, _: &Agent) -> Result<(), AppError> {
        Ok(())
    }
    fn get(&self, _: &str) -> Result<Option<Agent>, AppError> {
        Ok(None)
    }
    fn list(&self) -> Result<Vec<Agent>, AppError> {
        Ok(vec![])
    }
    fn create_execution(&self, exec: &Execution) -> Result<(), AppError> {
        self.executions.lock().unwrap().push(exec.clone());
        // Also mark request as running
        let mut reqs = self.request_repo.requests.lock().unwrap();
        if let Some(r) = reqs.iter_mut().find(|r| r.id == exec.request_id) {
            r.status = RequestStatus::Running;
        }
        Ok(())
    }
    fn get_execution(&self, id: &str) -> Result<Option<Execution>, AppError> {
        Ok(self
            .executions
            .lock()
            .unwrap()
            .iter()
            .find(|e| e.id == id)
            .cloned())
    }
    fn update_execution_status(&self, id: &str, status: ExecutionStatus) -> Result<(), AppError> {
        let mut execs = self.executions.lock().unwrap();
        if let Some(e) = execs.iter_mut().find(|e| e.id == id) {
            e.status = status;
        }
        Ok(())
    }
    fn extend_lease(&self, id: &str, new_expiry: DateTime<Utc>) -> Result<bool, AppError> {
        let mut execs = self.executions.lock().unwrap();
        if let Some(e) = execs
            .iter_mut()
            .find(|e| e.id == id && e.status == ExecutionStatus::Claimed)
        {
            e.lease_expires_at = new_expiry;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn find_dispatched_jobs(
        &self,
        _caps: &[(DatabaseName, Environment)],
    ) -> Result<Vec<Request>, AppError> {
        let reqs = self.request_repo.requests.lock().unwrap();
        Ok(reqs
            .iter()
            .filter(|r| r.status == RequestStatus::Dispatched)
            .cloned()
            .collect())
    }
    fn has_running_migration(
        &self,
        _: &DatabaseName,
        _: &Environment,
        _: &str,
    ) -> Result<bool, AppError> {
        Ok(false)
    }
    fn find_executions_for_request(&self, _: &str) -> Result<Vec<Execution>, AppError> {
        Ok(vec![])
    }
    fn claim_and_mark_running(
        &self,
        exec: &Execution,
        _request_id: &str,
        _now: DateTime<Utc>,
    ) -> Result<bool, AppError> {
        self.executions.lock().unwrap().push(exec.clone());
        let mut reqs = self.request_repo.requests.lock().unwrap();
        if let Some(r) = reqs.iter_mut().find(|r| r.id == exec.request_id) {
            r.status = RequestStatus::Running;
        }
        Ok(true)
    }
    fn complete_execution(
        &self,
        execution_id: &str,
        request_id: &str,
        success: bool,
        now: DateTime<Utc>,
        _audit_event: &dbward_domain::entities::AuditEvent,
        _result_manifest: Option<&ExecutionResult>,
        _share_with: &[ResultAccess],
    ) -> Result<dbward_app::ports::CompletionOutcome, AppError> {
        use dbward_app::ports::CompletionOutcome;
        let mut execs = self.executions.lock().unwrap();
        if let Some(e) = execs.iter_mut().find(|e| e.id == execution_id) {
            e.status = if success {
                ExecutionStatus::Completed
            } else {
                ExecutionStatus::Failed
            };
            e.finished_at = Some(now);
        }
        let mut reqs = self.request_repo.requests.lock().unwrap();
        if let Some(r) = reqs
            .iter_mut()
            .find(|r| r.id == request_id && r.status == RequestStatus::Running)
        {
            r.status = if success {
                RequestStatus::Executed
            } else {
                RequestStatus::Failed
            };
            r.updated_at = now;
            Ok(CompletionOutcome::Normal)
        } else {
            Ok(CompletionOutcome::RequestCancelled)
        }
    }
    fn find_expired_leases(&self, _: &str) -> Result<Vec<(String, String)>, AppError> {
        Ok(vec![])
    }
    fn mark_execution_lost(&self, _: &str, _: &str, _: &str) -> Result<bool, AppError> {
        Ok(true)
    }
    fn mark_execution_lost_and_record(
        &self,
        _: &str,
        _: &str,
        _: &dbward_domain::entities::AuditEvent,
        _: &str,
    ) -> Result<bool, AppError> {
        Ok(true)
    }
    fn find_expired_results(&self, _: &str) -> Result<Vec<(String, String)>, AppError> {
        Ok(vec![])
    }
    fn delete_result(&self, _: &str) -> Result<(), AppError> {
        Ok(())
    }
}

struct FakeTokenSigner;
impl TokenSigner for FakeTokenSigner {
    fn sign(&self, claims: &ExecutionTokenClaims) -> String {
        format!("token:{}:{}", claims.request_id, claims.database)
    }
    fn public_key_hex(&self) -> String {
        "fake".into()
    }
}

struct FakeUserRepoForAgent;
impl UserRepo for FakeUserRepoForAgent {
    fn get(&self, _: &str) -> Result<Option<dbward_domain::entities::User>, AppError> {
        Ok(None)
    }
    fn upsert(&self, _: &dbward_domain::entities::User) -> Result<(), AppError> {
        Ok(())
    }
    fn list(&self) -> Result<Vec<dbward_domain::entities::User>, AppError> {
        Ok(vec![])
    }
    fn suspend(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
        Ok(true)
    }
    fn activate(&self, _: &str, _: DateTime<Utc>) -> Result<bool, AppError> {
        Ok(true)
    }
    fn is_suspended(&self, _: &str) -> Result<bool, AppError> {
        Ok(false)
    }
    fn ensure_exists(&self, _: &str) -> Result<(), AppError> {
        Ok(())
    }

    fn count_active(&self) -> Result<u32, AppError> {
        Ok(1)
    }
    fn get_roles(&self, _: &str) -> Result<Vec<String>, AppError> {
        Ok(vec![])
    }
    fn is_deleted(&self, _: &str) -> Result<bool, AppError> {
        Ok(false)
    }
    fn count_admins(&self) -> Result<u32, AppError> {
        Ok(1)
    }
}

struct FakeRoleResolverForAgent;
impl RoleResolver for FakeRoleResolverForAgent {
    fn resolve(
        &self,
        _: &str,
        _: dbward_domain::auth::SubjectType,
        _: &[String],
    ) -> Result<Vec<dbward_domain::auth::ResolvedRole>, dbward_app::error::AuthError> {
        Ok(vec![dbward_domain::auth::ResolvedRole {
            name: "developer".into(),
            permissions: Default::default(),
            databases: vec![],
            environments: vec![],
        }])
    }
}

fn make_agent_user(id: &str) -> AuthUser {
    AuthUser {
        subject_id: id.to_string(),
        subject_type: SubjectType::Agent,
        roles: vec![ResolvedRole {
            name: "agent-default".into(),
            permissions: [Permission::AgentOperate].into_iter().collect(),
            databases: vec![],
            environments: vec![],
        }],
        groups: vec![],
        token_id: Some("agent-token-1".into()),
    }
}

#[test]
fn event_dispatcher_records_break_glass_auto_dispatch() {
    let h = TestHarness::new(None);
    let requester = make_user("alice", &["developer"]);
    let mut input = make_input();
    input.emergency = true;
    input.reason = Some("critical fix".into());

    let created = h
        .create_uc()
        .execute(
            input,
            &requester,
            &dbward_domain::entities::AuditContext::System,
        )
        .unwrap();
    assert_eq!(created.status, RequestStatus::Dispatched);

    // break_glass emits 2 events: create(BreakGlass) + dispatch(Dispatched)
}

#[test]
fn event_dispatcher_records_auto_approved_two_events() {
    let auto_wf = Workflow {
        id: "wf-auto".into(),
        database: DatabaseName::new("*").unwrap(),
        environment: Environment::new("*").unwrap(),
        operations: vec![],
        auto_approve: Some(dbward_domain::policies::AutoApproveSettings {
            mode: dbward_domain::policies::AutoApproveMode::Always,
            max_risk_level: None,
            allow_read_only: true,
            allow_safe_ddl: true,
            max_estimated_rows: 1000,
        }),
        steps: vec![],
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
    let h = TestHarness::new(Some(auto_wf));
    let requester = make_user("alice", &["developer"]);

    let created = h
        .create_uc()
        .execute(
            make_input(),
            &requester,
            &dbward_domain::entities::AuditContext::System,
        )
        .unwrap();
    assert_eq!(created.status, RequestStatus::Dispatched);
}

// === Regression Tests ===

// BUG-1: fail-closed — no workflow configured = reject (not auto-approve)
#[test]
fn no_workflow_configured_rejects_non_emergency() {
    let h = TestHarness::new(None); // PolicyEvaluator returns None
    let requester = make_user("alice", &["developer"]);
    let input = make_input(); // emergency = false

    let result = h.create_uc().execute(
        input,
        &requester,
        &dbward_domain::entities::AuditContext::System,
    );
    match result {
        Err(AppError::Validation(msg)) => assert!(
            msg.contains("no workflow configured"),
            "unexpected msg: {msg}"
        ),
        Err(e) => panic!("expected Validation error, got: {e:?}"),
        Ok(_) => panic!("expected Validation error, got Ok"),
    }
}

// BUG-1: break-glass exception — no workflow + emergency = success
#[test]
fn no_workflow_configured_allows_break_glass() {
    let h = TestHarness::new(None); // PolicyEvaluator returns None
    let requester = make_user("alice", &["developer"]);
    let mut input = make_input();
    input.emergency = true;
    input.reason = Some("incident #999".into());

    let created = h
        .create_uc()
        .execute(
            input,
            &requester,
            &dbward_domain::entities::AuditContext::System,
        )
        .unwrap();
    assert_eq!(created.status, RequestStatus::Dispatched);
}

// BUG-6: Token prefix = raw[4..12]
#[test]
fn token_prefix_is_raw_4_to_12() {
    use dbward_app::use_cases::token_manage::{TokenCreateInput, TokenManage};

    struct FakeTokenRepo(std::sync::Mutex<Vec<dbward_domain::entities::Token>>);
    impl TokenRepo for FakeTokenRepo {
        fn create(&self, t: &dbward_domain::entities::Token) -> Result<(), AppError> {
            self.0.lock().unwrap().push(t.clone());
            Ok(())
        }
        fn verify(
            &self,
            _: &str,
            _: &str,
        ) -> Result<Option<dbward_domain::entities::Token>, AppError> {
            Ok(None)
        }
        fn list(&self) -> Result<Vec<dbward_domain::entities::Token>, AppError> {
            Ok(vec![])
        }
        fn get(&self, _: &str) -> Result<Option<dbward_domain::entities::Token>, AppError> {
            Ok(None)
        }
        fn revoke(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn revoke_all_for_user(
            &self,
            _: &str,
            _: chrono::DateTime<chrono::Utc>,
        ) -> Result<u32, AppError> {
            Ok(0)
        }
        fn count_active(&self) -> Result<u32, AppError> {
            Ok(0)
        }
        fn purge_revoked(&self, _: &str) -> Result<u32, AppError> {
            Ok(0)
        }
        fn find_active_initial(&self, _: &str) -> Result<Option<Token>, AppError> {
            Ok(None)
        }
        fn count_active_for_subject(&self, _: &str) -> Result<u32, AppError> {
            Ok(0)
        }
    }

    struct FakeUserRepoNotSuspended;
    impl UserRepo for FakeUserRepoNotSuspended {
        fn get(&self, _: &str) -> Result<Option<dbward_domain::entities::User>, AppError> {
            Ok(None)
        }
        fn upsert(&self, _: &dbward_domain::entities::User) -> Result<(), AppError> {
            Ok(())
        }
        fn list(&self) -> Result<Vec<dbward_domain::entities::User>, AppError> {
            Ok(vec![])
        }
        fn suspend(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn activate(&self, _: &str, _: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError> {
            Ok(true)
        }
        fn is_suspended(&self, _: &str) -> Result<bool, AppError> {
            Ok(false)
        }
        fn ensure_exists(&self, _: &str) -> Result<(), AppError> {
            Ok(())
        }

        fn count_active(&self) -> Result<u32, AppError> {
            Ok(1)
        }
        fn get_roles(&self, _: &str) -> Result<Vec<String>, AppError> {
            Ok(vec![])
        }
        fn is_deleted(&self, _: &str) -> Result<bool, AppError> {
            Ok(false)
        }
        fn count_admins(&self) -> Result<u32, AppError> {
            Ok(1)
        }
    }

    struct FakePolicyRepoForToken;
    impl PolicyRepo for FakePolicyRepoForToken {
        fn create_workflow(
            &self,
            _: &dbward_domain::policies::workflow::Workflow,
        ) -> Result<(), AppError> {
            Ok(())
        }
        fn get_workflow(
            &self,
            _: &str,
        ) -> Result<Option<dbward_domain::policies::workflow::Workflow>, AppError> {
            Ok(None)
        }
        fn list_workflows(
            &self,
        ) -> Result<Vec<dbward_domain::policies::workflow::Workflow>, AppError> {
            Ok(vec![])
        }
        fn delete_workflow(&self, _: &str) -> Result<bool, AppError> {
            Ok(true)
        }
        fn count_workflows(&self) -> Result<u32, AppError> {
            Ok(0)
        }
        fn create_execution_policy(
            &self,
            _: &dbward_domain::policies::ExecutionPolicy,
        ) -> Result<(), AppError> {
            Ok(())
        }
        fn get_execution_policy(
            &self,
            _: &str,
        ) -> Result<Option<dbward_domain::policies::ExecutionPolicy>, AppError> {
            Ok(None)
        }
        fn list_execution_policies(
            &self,
        ) -> Result<Vec<dbward_domain::policies::ExecutionPolicy>, AppError> {
            Ok(vec![])
        }
        fn delete_execution_policy(&self, _: &str) -> Result<bool, AppError> {
            Ok(true)
        }
        fn find_result_policy(
            &self,
            _: &DatabaseName,
            _: &Environment,
        ) -> Result<Option<ResultPolicy>, AppError> {
            Ok(None)
        }

        fn create_result_policy(
            &self,
            _: &dbward_domain::policies::ResultPolicy,
        ) -> Result<(), AppError> {
            Ok(())
        }
        fn get_result_policy(
            &self,
            _: &str,
        ) -> Result<Option<dbward_domain::policies::ResultPolicy>, AppError> {
            Ok(None)
        }
        fn list_result_policies(
            &self,
        ) -> Result<Vec<dbward_domain::policies::ResultPolicy>, AppError> {
            Ok(vec![])
        }
        fn update_result_policy(
            &self,
            _: &dbward_domain::policies::ResultPolicy,
        ) -> Result<bool, AppError> {
            Ok(false)
        }
        fn delete_result_policy(&self, _: &str) -> Result<bool, AppError> {
            Ok(false)
        }
        fn create_notification_policy(
            &self,
            _: &dbward_domain::policies::NotificationPolicy,
        ) -> Result<(), AppError> {
            Ok(())
        }
        fn get_notification_policy(
            &self,
            _: &str,
        ) -> Result<Option<dbward_domain::policies::NotificationPolicy>, AppError> {
            Ok(None)
        }
        fn list_notification_policies(
            &self,
        ) -> Result<Vec<dbward_domain::policies::NotificationPolicy>, AppError> {
            Ok(vec![])
        }
        fn update_notification_policy(
            &self,
            _: &dbward_domain::policies::NotificationPolicy,
        ) -> Result<bool, AppError> {
            Ok(false)
        }
        fn delete_notification_policy(&self, _: &str) -> Result<bool, AppError> {
            Ok(false)
        }
        fn create_role(&self, _: &dbward_domain::auth::RoleDefinition) -> Result<(), AppError> {
            Ok(())
        }
        fn list_roles(&self) -> Result<Vec<dbward_domain::auth::RoleDefinition>, AppError> {
            Ok(vec![])
        }
        fn get_roles_by_names(
            &self,
            _: &[String],
        ) -> Result<Vec<dbward_domain::auth::RoleDefinition>, AppError> {
            Ok(vec![])
        }
        fn delete_role(&self, _: &str) -> Result<bool, AppError> {
            Ok(true)
        }
        fn count_roles(&self) -> Result<u32, AppError> {
            Ok(0)
        }
    }

    struct FakeRoleResolverAdmin;
    impl dbward_app::ports::RoleResolver for FakeRoleResolverAdmin {
        fn resolve(
            &self,
            _subject_id: &str,
            _subject_type: dbward_domain::auth::SubjectType,
            _groups: &[String],
        ) -> Result<Vec<dbward_domain::auth::ResolvedRole>, dbward_app::error::AuthError> {
            Ok(vec![dbward_domain::auth::ResolvedRole {
                name: "admin".into(),
                permissions: [dbward_domain::auth::Permission::All].into_iter().collect(),
                databases: vec![],
                environments: vec![],
            }])
        }
    }

    let token_repo = Arc::new(FakeTokenRepo(std::sync::Mutex::new(vec![])));
    let uc = TokenManage {
        authorizer: Arc::new(AllowAll),
        token_repo: token_repo.clone(),
        user_repo: Arc::new(FakeUserRepoNotSuspended),
        policy_repo: Arc::new(FakePolicyRepoForToken),
        role_resolver: Arc::new(FakeRoleResolverAdmin),
        license: Arc::new(FakeLicenseChecker),
        uow: Arc::new(common::NoopUnitOfWork),
        clock: Arc::new(FakeClock::new()),
        id_gen: Arc::new(SeqIdGen::new()),
        token_gen: Arc::new(FakeTokenValueGen),
        max_active_tokens_per_user: 5,
    };

    let admin = make_user("admin", &["admin"]);
    let output = uc
        .create(
            TokenCreateInput {
                subject_id: "admin".into(),
                subject_type: "user".into(),
                name: Some("test-token".into()),
                scope_ceiling: Some(dbward_domain::entities::ScopeCeiling {
                    roles: vec!["admin".into()],
                }),
                expires_at: None,
                issued_by: None,
                groups: vec![],
            },
            &admin,
            &dbward_domain::entities::AuditContext::System,
        )
        .unwrap();

    // Token format: "dbw_{uuid}" → prefix = raw[4..12]
    assert!(output.token.starts_with("dbw_"));
    let expected_prefix = &output.token[4..12];
    assert_eq!(output.prefix, expected_prefix);
}

// === CFG-15: Break-glass DDL bypass tests ===

#[test]
fn break_glass_ddl_drop_table_succeeds() {
    let h = TestHarness::new(Some(single_step_workflow()));
    let requester = make_user("alice", &["developer"]);
    let mut input = make_input();
    input.detail = "DROP TABLE broken_cache".into();
    input.emergency = true;
    input.allow_ddl = true;
    input.reason = Some("corrupted table".into());

    let created = h
        .create_uc()
        .execute(
            input,
            &requester,
            &dbward_domain::entities::AuditContext::System,
        )
        .unwrap();
    assert_eq!(created.status, RequestStatus::Dispatched);
}

#[test]
fn break_glass_ddl_without_allow_ddl_rejected_with_hint() {
    let h = TestHarness::new(Some(single_step_workflow()));
    let requester = make_user("alice", &["developer"]);
    let mut input = make_input();
    input.detail = "DROP TABLE t".into();
    input.emergency = true;
    input.allow_ddl = false;
    input.reason = Some("fix".into());

    let result = h.create_uc().execute(
        input,
        &requester,
        &dbward_domain::entities::AuditContext::System,
    );
    let err = result.unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("Hint: add --allow-ddl"), "got: {msg}");
}

#[test]
fn break_glass_ddl_allow_ddl_without_emergency_rejected() {
    let h = TestHarness::new(Some(single_step_workflow()));
    let requester = make_user("alice", &["developer"]);
    let mut input = make_input();
    input.detail = "DROP TABLE t".into();
    input.emergency = false;
    input.allow_ddl = true;

    let result = h.create_uc().execute(
        input,
        &requester,
        &dbward_domain::entities::AuditContext::System,
    );
    let err = result.unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("--allow-ddl requires --emergency"),
        "got: {msg}"
    );
}

#[test]
fn break_glass_ddl_grant_stays_rejected() {
    let h = TestHarness::new(Some(single_step_workflow()));
    let requester = make_user("alice", &["developer"]);
    let mut input = make_input();
    input.detail = "GRANT ALL ON users TO public".into();
    input.emergency = true;
    input.allow_ddl = true;
    input.reason = Some("fix".into());

    let result = h.create_uc().execute(
        input,
        &requester,
        &dbward_domain::entities::AuditContext::System,
    );
    assert!(result.is_err());
}

#[test]
fn break_glass_ddl_begin_stays_rejected() {
    let h = TestHarness::new(Some(single_step_workflow()));
    let requester = make_user("alice", &["developer"]);
    let mut input = make_input();
    input.detail = "BEGIN".into();
    input.emergency = true;
    input.allow_ddl = true;
    input.reason = Some("fix".into());

    let result = h.create_uc().execute(
        input,
        &requester,
        &dbward_domain::entities::AuditContext::System,
    );
    assert!(result.is_err());
}

#[test]
fn break_glass_ddl_mixed_batch_rejected() {
    let h = TestHarness::new(Some(single_step_workflow()));
    let requester = make_user("alice", &["developer"]);
    let mut input = make_input();
    input.detail = "DROP TABLE t; DELETE FROM users".into();
    input.emergency = true;
    input.allow_ddl = true;
    input.reason = Some("fix".into());

    let result = h.create_uc().execute(
        input,
        &requester,
        &dbward_domain::entities::AuditContext::System,
    );
    assert!(result.is_err());
}

#[test]
fn break_glass_ddl_multi_stmt_repair_succeeds() {
    let h = TestHarness::new(Some(single_step_workflow()));
    let requester = make_user("alice", &["developer"]);
    let mut input = make_input();
    input.detail = "DROP TABLE t; CREATE TABLE t (id INT PRIMARY KEY)".into();
    input.emergency = true;
    input.allow_ddl = true;
    input.reason = Some("rebuild".into());

    let created = h
        .create_uc()
        .execute(
            input,
            &requester,
            &dbward_domain::entities::AuditContext::System,
        )
        .unwrap();
    assert_eq!(created.status, RequestStatus::Dispatched);
}

#[test]
fn break_glass_ddl_mcp_rejected() {
    let h = TestHarness::new(Some(single_step_workflow()));
    let requester = make_user("alice", &["developer"]);
    let mut input = make_input();
    input.detail = "DROP TABLE t".into();
    input.emergency = true;
    input.allow_ddl = true;
    input.reason = Some("fix".into());
    input.channel = RequestChannel::Mcp;

    let result = h.create_uc().execute(
        input,
        &requester,
        &dbward_domain::entities::AuditContext::System,
    );
    let err = result.unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("not allowed via MCP/Slack"), "got: {msg}");
}

#[test]
fn break_glass_ddl_denied_without_permission() {
    /// Allows everything except RequestBreakGlassDdl.
    struct DenyDdlBypass;
    impl Authorizer for DenyDdlBypass {
        fn authorize_scoped(
            &self,
            _: &AuthUser,
            p: Permission,
            _: &DatabaseName,
            _: &Environment,
            _: &ResourceContext,
        ) -> Result<(), dbward_app::error::AuthzError> {
            if p == Permission::RequestBreakGlassDdl {
                Err(dbward_app::error::AuthzError::Forbidden {
                    permission: p,
                    reason: "missing request.break_glass_ddl".into(),
                })
            } else {
                Ok(())
            }
        }
        fn authorize_global(
            &self,
            _: &AuthUser,
            _: Permission,
        ) -> Result<(), dbward_app::error::AuthzError> {
            Ok(())
        }
    }

    let mut h = TestHarness::new(Some(single_step_workflow()));
    h.authorizer = Arc::new(DenyDdlBypass);

    let requester = make_user("alice", &["developer"]);
    let mut input = make_input();
    input.detail = "DROP TABLE t".into();
    input.emergency = true;
    input.allow_ddl = true;
    input.reason = Some("schema repair".into());

    let result = h.create_uc().execute(
        input,
        &requester,
        &dbward_domain::entities::AuditContext::System,
    );
    assert!(matches!(result, Err(AppError::Forbidden(_))));
}
