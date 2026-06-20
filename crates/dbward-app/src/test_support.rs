#![allow(clippy::new_without_default)]
//! Shared test doubles for use case unit tests.

use std::sync::Mutex;

use chrono::{DateTime, Utc};

use dbward_domain::auth::{AuthUser, Permission, ResourceContext};
use dbward_domain::entities::*;
use dbward_domain::policies::Workflow;
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

// --- AuditLogger ---

pub struct NoopAuditLogger;
impl crate::ports::AuditLogger for NoopAuditLogger {
    fn record(&self, _: &dbward_domain::entities::AuditEvent) -> Result<(), AppError> {
        Ok(())
    }
}

// --- BreakGlassMetrics ---

pub struct NoopBreakGlassMetrics;
impl crate::ports::BreakGlassMetrics for NoopBreakGlassMetrics {
    fn record_ddl_attempted(&self) {}
    fn record_ddl_allowed(&self) {}
    fn record_ddl_denied(&self) {}
    fn record_audit_failure(&self) {}
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
    fn find_by_idempotency_key(&self, _: &str, _: &str) -> Result<Option<Request>, AppError> {
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
    pub last_request: Mutex<Option<Request>>,
    pub last_audit_events: Mutex<Vec<AuditEvent>>,
}

impl FakeRequestWriter {
    pub fn new() -> Self {
        Self {
            written: Mutex::new(false),
            last_request: Mutex::new(None),
            last_audit_events: Mutex::new(vec![]),
        }
    }
}

impl RequestWriter for FakeRequestWriter {
    fn insert(&self, req: &Request) -> Result<(), AppError> {
        *self.written.lock().unwrap() = true;
        *self.last_request.lock().unwrap() = Some(req.clone());
        Ok(())
    }
    fn create_and_dispatch(&self, req: &Request) -> Result<(), AppError> {
        *self.written.lock().unwrap() = true;
        *self.last_request.lock().unwrap() = Some(req.clone());
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
            require_reason: false,
            allow_self_approve: false,
            allow_same_approver_across_steps: false,
            explain: true,
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
    ) -> Result<dbward_domain::policies::ExecutionPolicy, crate::error::AppError> {
        Ok(Default::default())
    }
}

// --- DatabaseRegistry ---

pub struct FakeDatabaseRegistry;
impl DatabaseRegistry for FakeDatabaseRegistry {
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

pub struct FakeSchemaRepo;
impl crate::ports::SchemaRepo for FakeSchemaRepo {
    fn upsert_snapshot(
        &self,
        _: &crate::ports::SchemaSnapshotRecord,
    ) -> Result<(), crate::error::AppError> {
        Ok(())
    }
    fn get_snapshot(
        &self,
        _: &str,
        _: &str,
    ) -> Result<Option<crate::ports::SchemaSnapshotRecord>, crate::error::AppError> {
        Ok(None)
    }
    fn get_dialect(&self, _: &str, _: &str) -> Result<Option<String>, crate::error::AppError> {
        Ok(None)
    }
    fn get_tables_for(
        &self,
        _: &str,
        _: &str,
        _: &[dbward_domain::services::table_extractor::TableRef],
    ) -> Result<Option<String>, crate::error::AppError> {
        Ok(None)
    }
}

pub struct FakeDryRunRepo;
impl crate::ports::DryRunRepo for FakeDryRunRepo {
    fn create_jobs(
        &self,
        _: &[crate::ports::DryRunJobRecord],
    ) -> Result<(), crate::error::AppError> {
        Ok(())
    }
    fn find_pending_for_agent(
        &self,
        _: &[(String, String)],
    ) -> Result<Vec<crate::ports::DryRunJobRecord>, crate::error::AppError> {
        Ok(vec![])
    }
    fn claim(&self, _: &str, _: &str, _: &str, _: &str) -> Result<bool, crate::error::AppError> {
        Ok(false)
    }
    fn complete(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<bool, crate::error::AppError> {
        Ok(false)
    }
    fn fail(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<bool, crate::error::AppError> {
        Ok(false)
    }
    fn reclaim_stale(&self, _: &str) -> Result<u32, crate::error::AppError> {
        Ok(0)
    }
    fn find_for_request(
        &self,
        _: &str,
    ) -> Result<Vec<crate::ports::DryRunJobRecord>, crate::error::AppError> {
        Ok(vec![])
    }
    fn get_request_id(&self, _: &str) -> Result<Option<String>, crate::error::AppError> {
        Ok(None)
    }
}

pub struct FakeContextRepo;
impl crate::ports::ContextRepo for FakeContextRepo {
    fn create(&self, _: &crate::ports::RequestContextRecord) -> Result<(), crate::error::AppError> {
        Ok(())
    }
    fn get(
        &self,
        _: &str,
    ) -> Result<Option<crate::ports::RequestContextRecord>, crate::error::AppError> {
        Ok(None)
    }
    fn update_explain(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<(), crate::error::AppError> {
        Ok(())
    }
    fn timeout_collecting(&self, _: &str, _: &str) -> Result<u32, crate::error::AppError> {
        Ok(0)
    }
}

// --- NoopUnitOfWork ---

pub struct NoopUnitOfWork;

impl crate::ports::UnitOfWork for NoopUnitOfWork {
    fn execute(
        &self,
        f: Box<
            dyn FnOnce(
                    &dyn crate::ports::transaction::TxScope,
                ) -> Result<(), crate::error::AppError>
                + '_,
        >,
    ) -> Result<(), crate::error::AppError> {
        f(&NoopTxScope)
    }

    fn execute_with_result(
        &self,
        f: Box<
            dyn FnOnce(
                    &dyn crate::ports::transaction::TxScope,
                ) -> Result<Box<dyn std::any::Any>, crate::error::AppError>
                + '_,
        >,
    ) -> Result<Box<dyn std::any::Any>, crate::error::AppError> {
        f(&NoopTxScope)
    }

    fn execute_sync(
        &self,
        f: Box<
            dyn FnOnce(
                    &dyn crate::ports::sync_scope::SyncScope,
                ) -> Result<Box<dyn std::any::Any>, crate::error::AppError>
                + '_,
        >,
    ) -> Result<Box<dyn std::any::Any>, crate::error::AppError> {
        f(&NoopSyncScope)
    }
}

struct NoopTxScope;

impl crate::ports::transaction::RequestWriterOps for NoopTxScope {
    fn insert_request(
        &self,
        _: &dbward_domain::entities::Request,
    ) -> Result<(), crate::error::AppError> {
        Ok(())
    }
    fn mark_dispatched(
        &self,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, crate::error::AppError> {
        Ok(true)
    }
    fn mark_approved(
        &self,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, crate::error::AppError> {
        Ok(true)
    }
    fn mark_rejected(
        &self,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, crate::error::AppError> {
        Ok(true)
    }
    fn mark_running(
        &self,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, crate::error::AppError> {
        Ok(true)
    }
    fn mark_cancelled(
        &self,
        _: &str,
        _: &str,
        _: Option<&str>,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, crate::error::AppError> {
        Ok(true)
    }
    fn mark_executed(
        &self,
        _: &str,
        _: bool,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, crate::error::AppError> {
        Ok(true)
    }
    fn mark_expired(
        &self,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, crate::error::AppError> {
        Ok(true)
    }
    fn mark_execution_lost(
        &self,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, crate::error::AppError> {
        Ok(true)
    }
    fn cancel_all_for_user(
        &self,
        _: &str,
        _: &str,
        _: Option<&str>,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<String>, crate::error::AppError> {
        Ok(vec![])
    }
}

impl crate::ports::transaction::ApprovalWriterOps for NoopTxScope {
    fn insert_approval(
        &self,
        _: &dbward_domain::entities::Approval,
    ) -> Result<(), crate::error::AppError> {
        Ok(())
    }
}

impl crate::ports::transaction::AuditWriterOps for NoopTxScope {
    fn record(
        &self,
        _: &dbward_domain::entities::AuditEvent,
    ) -> Result<(), crate::error::AppError> {
        Ok(())
    }
}

impl crate::ports::transaction::ExecutionWriterOps for NoopTxScope {
    fn insert_execution(
        &self,
        _: &dbward_domain::entities::Execution,
    ) -> Result<(), crate::error::AppError> {
        Ok(())
    }
    fn mark_completed(
        &self,
        _: &str,
        _: bool,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, crate::error::AppError> {
        Ok(true)
    }
}

impl crate::ports::transaction::TokenWriterOps for NoopTxScope {
    fn create_token(
        &self,
        _: &dbward_domain::entities::Token,
    ) -> Result<(), crate::error::AppError> {
        Ok(())
    }
    fn revoke_token(
        &self,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, crate::error::AppError> {
        Ok(true)
    }
    fn revoke_all_for_user(
        &self,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<u32, crate::error::AppError> {
        Ok(0)
    }
}

impl crate::ports::transaction::UserWriterOps for NoopTxScope {
    fn suspend_user(
        &self,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, crate::error::AppError> {
        Ok(true)
    }
    fn activate_user(
        &self,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, crate::error::AppError> {
        Ok(true)
    }
}

impl crate::ports::transaction::ResultWriterOps for NoopTxScope {
    fn insert_result(
        &self,
        _result: &dbward_domain::entities::ExecutionResult,
    ) -> Result<(), crate::error::AppError> {
        Ok(())
    }
    fn insert_result_access(
        &self,
        _access: &[dbward_domain::entities::ResultAccess],
    ) -> Result<(), crate::error::AppError> {
        Ok(())
    }
}

impl crate::ports::transaction::TxScope for NoopTxScope {}

// --- NoopNotifier ---

pub struct NoopNotifier;

impl crate::ports::Notifier for NoopNotifier {
    fn dispatch(&self, _: crate::ports::WebhookEvent) {}
}

// --- NoopSyncScope for tests ---
pub struct NoopSyncScope;

impl crate::ports::sync_scope::SyncDatabaseOps for NoopSyncScope {
    fn register(
        &self,
        _: &dbward_domain::values::DatabaseName,
        _: &dbward_domain::values::Environment,
    ) -> Result<(), crate::error::AppError> {
        Ok(())
    }
    fn list_active_databases(
        &self,
    ) -> Result<
        Vec<(
            dbward_domain::values::DatabaseName,
            dbward_domain::values::Environment,
        )>,
        crate::error::AppError,
    > {
        Ok(vec![])
    }
    fn reconcile_stale_databases(
        &self,
        _: &[String],
    ) -> Result<(u64, u64), crate::error::AppError> {
        Ok((0, 0))
    }
}
impl crate::ports::sync_scope::SyncUserOps for NoopSyncScope {
    fn upsert_user(&self, _: &dbward_domain::entities::User) -> Result<(), crate::error::AppError> {
        Ok(())
    }
    fn suspend_user(
        &self,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, crate::error::AppError> {
        Ok(false)
    }
    fn activate_user(
        &self,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, crate::error::AppError> {
        Ok(false)
    }
    fn set_user_source(&self, _: &str, _: &str) -> Result<(), crate::error::AppError> {
        Ok(())
    }
    fn get_user_source(&self, _: &str) -> Result<Option<String>, crate::error::AppError> {
        Ok(None)
    }
    fn list_stale_config_user_ids(
        &self,
        _: &[String],
    ) -> Result<Vec<String>, crate::error::AppError> {
        Ok(vec![])
    }
    fn list_active_user_ids(&self) -> Result<Vec<String>, crate::error::AppError> {
        Ok(vec![])
    }
    fn count_active_users(&self) -> Result<u32, crate::error::AppError> {
        Ok(0)
    }
    fn delete_stale_config_users(&self, _: &[String]) -> Result<u64, crate::error::AppError> {
        Ok(0)
    }
}
impl crate::ports::sync_scope::SyncGroupOps for NoopSyncScope {
    fn create_group(&self, _: &str, _: &[String], _: &str) -> Result<(), crate::error::AppError> {
        Ok(())
    }
    fn delete_stale_config_groups(&self, _: &[String]) -> Result<u64, crate::error::AppError> {
        Ok(0)
    }
}
impl crate::ports::sync_scope::SyncRoleBindingOps for NoopSyncScope {
    fn create_role_binding(
        &self,
        _: &str,
        _: &str,
        _: &[String],
        _: &[String],
        _: &str,
    ) -> Result<(), crate::error::AppError> {
        Ok(())
    }
    fn delete_stale_config_role_bindings(
        &self,
        _: &[String],
    ) -> Result<u64, crate::error::AppError> {
        Ok(0)
    }
}
impl crate::ports::sync_scope::SyncTokenOps for NoopSyncScope {
    fn revoke_all_tokens_for_user(
        &self,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<u32, crate::error::AppError> {
        Ok(0)
    }
}
impl crate::ports::sync_scope::SyncPolicyOps for NoopSyncScope {
    fn create_workflow(
        &self,
        _: &dbward_domain::policies::Workflow,
    ) -> Result<(), crate::error::AppError> {
        Ok(())
    }
    fn delete_stale_workflows(&self, _: &[String]) -> Result<u64, crate::error::AppError> {
        Ok(0)
    }
    fn count_workflows(&self) -> Result<u32, crate::error::AppError> {
        Ok(0)
    }
    fn create_execution_policy(
        &self,
        _: &dbward_domain::policies::ExecutionPolicy,
    ) -> Result<(), crate::error::AppError> {
        Ok(())
    }
    fn delete_stale_execution_policies(&self, _: &[String]) -> Result<u64, crate::error::AppError> {
        Ok(0)
    }
    fn create_notification_policy(
        &self,
        _: &dbward_domain::policies::NotificationPolicy,
    ) -> Result<(), crate::error::AppError> {
        Ok(())
    }
    fn delete_stale_notification_policies(
        &self,
        _: &[String],
    ) -> Result<u64, crate::error::AppError> {
        Ok(0)
    }
    fn create_result_policy(
        &self,
        _: &dbward_domain::policies::ResultPolicy,
    ) -> Result<(), crate::error::AppError> {
        Ok(())
    }
    fn delete_stale_result_policies(&self, _: &[String]) -> Result<u64, crate::error::AppError> {
        Ok(0)
    }
    fn create_role(
        &self,
        _: &dbward_domain::auth::RoleDefinition,
    ) -> Result<(), crate::error::AppError> {
        Ok(())
    }
    fn delete_stale_config_roles(&self, _: &[String]) -> Result<u64, crate::error::AppError> {
        Ok(0)
    }
    fn count_roles(&self) -> Result<u32, crate::error::AppError> {
        Ok(0)
    }
}
impl crate::ports::sync_scope::SyncWebhookOps for NoopSyncScope {
    fn create_webhook(
        &self,
        _: &dbward_domain::entities::Webhook,
    ) -> Result<(), crate::error::AppError> {
        Ok(())
    }
    fn delete_stale_config_webhooks(&self, _: &[String]) -> Result<u64, crate::error::AppError> {
        Ok(0)
    }
    fn list_active_webhooks(
        &self,
    ) -> Result<Vec<dbward_domain::entities::Webhook>, crate::error::AppError> {
        Ok(vec![])
    }
}
impl crate::ports::sync_scope::SyncConfigGenerationOps for NoopSyncScope {
    fn record_generation(
        &self,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
        _: &str,
    ) -> Result<(), crate::error::AppError> {
        Ok(())
    }
}
impl crate::ports::transaction::AuditWriterOps for NoopSyncScope {
    fn record(
        &self,
        _: &dbward_domain::entities::AuditEvent,
    ) -> Result<(), crate::error::AppError> {
        Ok(())
    }
}
impl crate::ports::transaction::RequestWriterOps for NoopSyncScope {
    fn insert_request(
        &self,
        _: &dbward_domain::entities::Request,
    ) -> Result<(), crate::error::AppError> {
        Ok(())
    }
    fn mark_dispatched(
        &self,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, crate::error::AppError> {
        Ok(false)
    }
    fn mark_approved(
        &self,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, crate::error::AppError> {
        Ok(false)
    }
    fn mark_rejected(
        &self,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, crate::error::AppError> {
        Ok(false)
    }
    fn mark_running(
        &self,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, crate::error::AppError> {
        Ok(false)
    }
    fn mark_cancelled(
        &self,
        _: &str,
        _: &str,
        _: Option<&str>,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, crate::error::AppError> {
        Ok(false)
    }
    fn mark_executed(
        &self,
        _: &str,
        _: bool,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, crate::error::AppError> {
        Ok(false)
    }
    fn mark_expired(
        &self,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, crate::error::AppError> {
        Ok(false)
    }
    fn mark_execution_lost(
        &self,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, crate::error::AppError> {
        Ok(false)
    }
    fn cancel_all_for_user(
        &self,
        _: &str,
        _: &str,
        _: Option<&str>,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<String>, crate::error::AppError> {
        Ok(vec![])
    }
}
