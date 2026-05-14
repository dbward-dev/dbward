use async_trait::async_trait;

use dbward_domain::entities::*;
use dbward_domain::values::{DatabaseName, Environment, ResultSummary};

use crate::error::AppError;

// --- RequestRepo ---

pub trait RequestRepo: Send + Sync {
    fn insert(&self, req: &Request) -> Result<(), AppError>;
    fn get(&self, id: &str) -> Result<Option<Request>, AppError>;
    fn list(
        &self,
        limit: u32,
        offset: u32,
        status: Option<&str>,
        user: Option<&str>,
    ) -> Result<(Vec<Request>, u32), AppError>;
    fn find_by_idempotency_key(&self, key: &str) -> Result<Option<Request>, AppError>;
    /// List pending requests approvable by user (via denormalized pending_approvers table).
    fn list_pending_for_user(
        &self,
        user_id: &str,
        groups: &[String],
        roles: &[String],
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<Request>, u32), AppError>;
    fn insert_approval(&self, approval: &Approval) -> Result<(), AppError>;
    fn get_approvals(&self, request_id: &str) -> Result<Vec<Approval>, AppError>;
    fn count_executions(&self, request_id: &str) -> Result<u32, AppError>;

    /// Returns false if the request was not in an expected source state (optimistic lock).
    fn mark_approved(&self, id: &str, now: chrono::DateTime<chrono::Utc>)
        -> Result<bool, AppError>;
    /// Atomically inserts approval and marks request as approved in one transaction.
    fn approve_and_mark_approved(
        &self,
        approval: &Approval,
        request_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, AppError>;
    fn mark_rejected(&self, id: &str, now: chrono::DateTime<chrono::Utc>)
        -> Result<bool, AppError>;
    /// Atomically inserts rejection approval and marks request as rejected in one transaction.
    fn reject_and_record(
        &self,
        request_id: &str,
        approval: &Approval,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, AppError>;
    fn mark_cancelled(
        &self,
        id: &str,
        actor: &str,
        reason: Option<&str>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, AppError>;
    fn mark_dispatched(
        &self,
        id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, AppError>;
    /// Atomically inserts a request and marks it as dispatched in one transaction.
    fn create_and_dispatch(&self, request: &Request) -> Result<(), AppError>;
    fn mark_running(&self, id: &str, now: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError>;
    fn mark_executed(&self, id: &str, now: chrono::DateTime<chrono::Utc>)
        -> Result<bool, AppError>;
    fn mark_failed(&self, id: &str, now: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError>;
    fn cancel_all_for_user(
        &self,
        user_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<u32, AppError>;

    // Background task methods
    fn find_expired_approved(&self, now: &str) -> Result<Vec<String>, AppError>;
    fn find_expired_pending(&self, now: &str) -> Result<Vec<String>, AppError>;
    fn find_dispatched_older_than(&self, cutoff: &str) -> Result<Vec<String>, AppError>;
    fn mark_expired(&self, id: &str, now: &str) -> Result<bool, AppError>;
    /// Atomically marks request expired and records audit event in one transaction.
    fn mark_expired_and_record(
        &self,
        id: &str,
        audit_event: &AuditEvent,
        now: &str,
    ) -> Result<bool, AppError>;
    fn mark_approved_from_dispatched(&self, id: &str, now: &str) -> Result<bool, AppError>;
    fn purge_old_requests(&self, before: &str) -> Result<u32, AppError>;
    fn count_by_status(&self, status: &str) -> Result<u32, AppError>;
    fn wal_checkpoint(&self) -> Result<(), AppError>;
    /// List stored results accessible by a user (requester or share_with).
    fn list_results_for_user(
        &self,
        user_id: &str,
        groups: &[String],
        roles: &[String],
        limit: u32,
    ) -> Result<Vec<StoredResultEntry>, AppError>;
    /// Check if a user is a pending approver for a specific request (current step only).
    fn is_pending_approver(
        &self,
        request_id: &str,
        user_id: &str,
        groups: &[String],
        roles: &[String],
    ) -> Result<bool, AppError>;
}

// --- AgentRepo ---

pub trait AgentRepo: Send + Sync {
    fn upsert(&self, agent: &Agent) -> Result<(), AppError>;
    fn get(&self, agent_id: &str) -> Result<Option<Agent>, AppError>;
    fn list(&self) -> Result<Vec<Agent>, AppError>;
    fn create_execution(&self, execution: &Execution) -> Result<(), AppError>;
    fn get_execution(&self, execution_id: &str) -> Result<Option<Execution>, AppError>;
    fn update_execution_status(
        &self,
        execution_id: &str,
        status: ExecutionStatus,
    ) -> Result<(), AppError>;
    fn extend_lease(
        &self,
        execution_id: &str,
        new_expiry: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AppError>;
    fn find_dispatched_jobs(
        &self,
        databases: &[(DatabaseName, Environment)],
    ) -> Result<Vec<Request>, AppError>;
    fn has_running_migration(
        &self,
        db: &DatabaseName,
        env: &Environment,
        exclude_request_id: &str,
    ) -> Result<bool, AppError>;
    /// Returns executions ordered by created_at ASC (oldest first).
    fn find_executions_for_request(&self, request_id: &str) -> Result<Vec<Execution>, AppError>;
    /// Atomically creates execution and marks request as running in a single transaction.
    fn claim_and_mark_running(
        &self,
        execution: &Execution,
        request_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, AppError>;
    /// Atomically updates execution status (Completed/Failed) and request status (executed/failed).
    #[allow(clippy::too_many_arguments)]
    /// Also inserts audit event, result manifest, and result_access records in the same TX.
    /// Returns false if request was cancelled (request update skipped).
    fn complete_execution(
        &self,
        execution_id: &str,
        request_id: &str,
        success: bool,
        now: chrono::DateTime<chrono::Utc>,
        audit_event: &AuditEvent,
        result_manifest: Option<&ExecutionResult>,
        share_with: &[ResultAccess],
    ) -> Result<bool, AppError>;

    // Background task methods
    fn find_expired_leases(&self, now: &str) -> Result<Vec<(String, String)>, AppError>;
    fn mark_execution_lost(
        &self,
        execution_id: &str,
        request_id: &str,
        now: &str,
    ) -> Result<bool, AppError>;
    /// Atomically marks execution lost and records audit event in one transaction.
    fn mark_execution_lost_and_record(
        &self,
        execution_id: &str,
        request_id: &str,
        audit_event: &AuditEvent,
        now: &str,
    ) -> Result<bool, AppError>;
    /// Returns (result_id, storage_key) for results past their expires_at.
    fn find_expired_results(&self, now: &str) -> Result<Vec<(String, String)>, AppError>;
    /// Delete a result record by id.
    fn delete_result(&self, result_id: &str) -> Result<(), AppError>;
}

#[derive(Debug, Clone)]
pub struct StoredResultEntry {
    pub request_id: String,
    pub database: String,
    pub environment: String,
    pub operation: String,
    pub stored_at: String,
    pub content_length: i64,
}

// --- UserRepo ---

pub trait UserRepo: Send + Sync {
    fn get(&self, user_id: &str) -> Result<Option<User>, AppError>;
    fn upsert(&self, user: &User) -> Result<(), AppError>;
    fn list(&self) -> Result<Vec<User>, AppError>;
    fn suspend(&self, user_id: &str, now: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError>;
    fn activate(&self, user_id: &str, now: chrono::DateTime<chrono::Utc>)
        -> Result<bool, AppError>;
    fn is_suspended(&self, user_id: &str) -> Result<bool, AppError>;
    /// Auto-create user record on first auth if not exists.
    fn ensure_exists(&self, subject_id: &str) -> Result<(), AppError>;
}

// --- TokenRepo ---

pub trait TokenRepo: Send + Sync {
    fn create(&self, token: &Token) -> Result<(), AppError>;
    fn verify(&self, prefix: &str, hash: &str) -> Result<Option<Token>, AppError>;
    fn list(&self) -> Result<Vec<Token>, AppError>;
    fn get(&self, token_id: &str) -> Result<Option<Token>, AppError>;
    fn revoke(&self, token_id: &str, now: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError>;
    fn revoke_all_for_user(
        &self,
        subject_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<u32, AppError>;
    fn count_active(&self) -> Result<u32, AppError>;
    fn purge_revoked(&self, before: &str) -> Result<u32, AppError>;
}

// --- WebhookRepo ---

pub trait WebhookRepo: Send + Sync {
    fn create(&self, webhook: &Webhook) -> Result<(), AppError>;
    fn get(&self, id: &str) -> Result<Option<Webhook>, AppError>;
    fn list(&self) -> Result<Vec<Webhook>, AppError>;
    fn update(&self, webhook: &Webhook) -> Result<(), AppError>;
    fn delete(&self, id: &str) -> Result<(), AppError>;
}

// --- DatabaseRegistry ---

pub trait DatabaseRegistry: Send + Sync {
    fn register(&self, db: &DatabaseName, env: &Environment) -> Result<(), AppError>;
    fn exists(&self, db: &DatabaseName, env: &Environment) -> Result<bool, AppError>;
    fn list(&self) -> Result<Vec<(DatabaseName, Environment)>, AppError>;
}

// --- AuditLogger ---

pub trait AuditLogger: Send + Sync {
    fn record(&self, event: &AuditEvent) -> Result<(), AppError>;
}

// --- AuditRepo (query/verify) ---

pub trait AuditRepo: Send + Sync {
    fn list(&self, filter: &AuditFilter) -> Result<Vec<AuditEvent>, AppError>;
    fn verify_chain(&self) -> Result<AuditVerifyResult, AppError>;
    fn purge_old(&self, before: &str) -> Result<u32, AppError>;
}

pub struct AuditFilter {
    pub actor_id: Option<String>,
    pub event_type: Option<String>,
    pub event_category: Option<String>,
    pub outcome: Option<String>,
    pub environment: Option<String>,
    pub database: Option<String>,
    pub since: Option<chrono::DateTime<chrono::Utc>>,
    pub until: Option<chrono::DateTime<chrono::Utc>>,
    pub limit: u32,
    pub offset: u32,
}

pub struct AuditVerifyResult {
    pub total_events: u64,
    pub first_broken_id: Option<String>,
}

// --- PolicyRepo ---

pub trait PolicyRepo: Send + Sync {
    fn create_workflow(&self, wf: &dbward_domain::policies::Workflow) -> Result<(), AppError>;
    fn get_workflow(&self, id: &str)
        -> Result<Option<dbward_domain::policies::Workflow>, AppError>;
    fn list_workflows(&self) -> Result<Vec<dbward_domain::policies::Workflow>, AppError>;
    fn delete_workflow(&self, id: &str) -> Result<bool, AppError>;
    fn count_workflows(&self) -> Result<u32, AppError>;

    fn create_execution_policy(
        &self,
        ep: &dbward_domain::policies::ExecutionPolicy,
    ) -> Result<(), AppError>;
    fn get_execution_policy(
        &self,
        id: &str,
    ) -> Result<Option<dbward_domain::policies::ExecutionPolicy>, AppError>;
    fn list_execution_policies(
        &self,
    ) -> Result<Vec<dbward_domain::policies::ExecutionPolicy>, AppError>;
    fn delete_execution_policy(&self, id: &str) -> Result<bool, AppError>;

    fn find_result_policy(
        &self,
        db: &DatabaseName,
        env: &Environment,
    ) -> Result<Option<dbward_domain::policies::ResultPolicy>, AppError>;

    fn create_role(&self, role: &dbward_domain::auth::RoleDefinition) -> Result<(), AppError>;
    fn list_roles(&self) -> Result<Vec<dbward_domain::auth::RoleDefinition>, AppError>;
    fn get_roles_by_names(
        &self,
        names: &[String],
    ) -> Result<Vec<dbward_domain::auth::RoleDefinition>, AppError>;
    fn delete_role(&self, name: &str) -> Result<bool, AppError>;
    fn count_roles(&self) -> Result<u32, AppError>;
}

// --- LicenseChecker ---

pub trait LicenseChecker: Send + Sync {
    fn max_tokens(&self) -> u32;
    fn max_workflows(&self) -> u32;
    fn max_webhooks(&self) -> u32;
    fn max_roles(&self) -> u32;
    fn max_agents(&self) -> u32;
    fn is_pro(&self) -> bool;
}

// --- ResultChannel (UC-6 long-poll) ---

#[async_trait]
pub trait ResultChannel: Send + Sync {
    fn create_slot(&self, request_id: &str);
    async fn publish(&self, request_id: &str, summary: ResultSummary);
    async fn subscribe(
        &self,
        request_id: &str,
        timeout_secs: u64,
    ) -> Result<Option<ResultSummary>, AppError>;
    async fn notify_all(&self);
}

// --- SsrfValidator (UC-15 webhook URL validation) ---

pub trait SsrfValidator: Send + Sync {
    fn validate_url(&self, url: &str) -> Result<(), AppError>;
}

// --- ResultStore ---

#[async_trait]
pub trait ResultStore: Send + Sync {
    async fn put(&self, key: &str, data: &[u8]) -> Result<(), AppError>;
    async fn get(&self, key: &str) -> Result<Vec<u8>, AppError>;
    async fn delete(&self, key: &str) -> Result<(), AppError>;
}

// --- TokenSigner ---

pub trait TokenSigner: Send + Sync {
    fn sign(&self, claims: &ExecutionTokenClaims) -> String;
    fn public_key_hex(&self) -> String;
}

/// Claims embedded in an execution token.
pub struct ExecutionTokenClaims {
    pub request_id: String,
    pub operation: String,
    pub database: String,
    pub environment: String,
    pub detail_hash: String,
    pub requester: String,
    pub requester_role: String,
}

// --- Notifier ---
// (in services.rs)
