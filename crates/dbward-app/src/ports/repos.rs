use async_trait::async_trait;

use dbward_domain::entities::*;
use dbward_domain::values::{DatabaseName, Environment, ResultSummary};

use crate::error::AppError;

/// Outcome of `complete_execution` — distinguishes normal completion from
/// late completion of a cancelled request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompletionOutcome {
    /// Request status was updated to executed/failed.
    Normal,
    /// Request was already cancelled; result is stored but status unchanged.
    RequestCancelled,
}

// --- RequestReader ---

pub trait RequestReader: Send + Sync {
    fn get(&self, id: &str) -> Result<Option<Request>, AppError>;
    fn list(
        &self,
        limit: u32,
        offset: u32,
        status: Option<&str>,
        user: Option<&str>,
    ) -> Result<(Vec<Request>, u32), AppError>;
    fn find_by_idempotency_key(&self, key: &str) -> Result<Option<Request>, AppError>;
    fn list_visible_to_user(
        &self,
        user_id: &str,
        groups: &[String],
        roles: &[String],
        status: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<Request>, u32), AppError>;
    fn list_pending_for_user(
        &self,
        user_id: &str,
        groups: &[String],
        roles: &[String],
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<Request>, u32), AppError>;
    fn is_pending_approver(
        &self,
        request_id: &str,
        user_id: &str,
        groups: &[String],
        roles: &[String],
    ) -> Result<bool, AppError>;
    fn count_executions(&self, request_id: &str) -> Result<u32, AppError>;
    fn list_results_for_user(
        &self,
        user_id: &str,
        groups: &[String],
        roles: &[String],
        limit: u32,
    ) -> Result<Vec<StoredResultEntry>, AppError>;
    fn count_by_status(&self, status: &str) -> Result<u32, AppError>;
    fn get_pending_approvers_for_requests(
        &self,
        request_ids: &[&str],
    ) -> Result<std::collections::HashMap<String, (u32, Vec<String>)>, AppError>;
}

// --- RequestWriter ---

pub trait RequestWriter: Send + Sync {
    fn insert(&self, req: &Request) -> Result<(), AppError>;
    fn create_and_dispatch(&self, request: &Request) -> Result<(), AppError>;
    fn mark_approved(&self, id: &str, now: chrono::DateTime<chrono::Utc>)
        -> Result<bool, AppError>;
    fn mark_rejected(&self, id: &str, now: chrono::DateTime<chrono::Utc>)
        -> Result<bool, AppError>;
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
    fn mark_running(&self, id: &str, now: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError>;
    fn mark_executed(&self, id: &str, now: chrono::DateTime<chrono::Utc>)
        -> Result<bool, AppError>;
    fn mark_failed(&self, id: &str, now: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError>;
    fn cancel_all_for_user(
        &self,
        user_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<u32, AppError>;
    fn mark_approved_from_dispatched(&self, id: &str, now: &str) -> Result<bool, AppError>;
}

// --- ApprovalRepo ---

pub trait ApprovalRepo: Send + Sync {
    fn insert_approval(&self, approval: &Approval) -> Result<(), AppError>;
    fn get_approvals(&self, request_id: &str) -> Result<Vec<Approval>, AppError>;
    fn approve_and_mark_approved(
        &self,
        approval: &Approval,
        request_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, AppError>;
    fn reject_and_record(
        &self,
        request_id: &str,
        approval: &Approval,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, AppError>;
}

// --- BackgroundTaskRepo ---

pub trait BackgroundTaskRepo: Send + Sync {
    fn find_expired_approved(&self, now: &str) -> Result<Vec<String>, AppError>;
    fn find_expired_pending(&self, now: &str) -> Result<Vec<String>, AppError>;
    fn find_dispatched_older_than(&self, cutoff: &str) -> Result<Vec<String>, AppError>;
    fn mark_expired(&self, id: &str, now: &str) -> Result<bool, AppError>;
    fn mark_expired_and_record(
        &self,
        id: &str,
        audit_event: &AuditEvent,
        now: &str,
    ) -> Result<bool, AppError>;
    fn purge_old_requests(&self, before: &str) -> Result<u32, AppError>;
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
    ) -> Result<CompletionOutcome, AppError>;

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
    /// Update slack_user_id for a user (upserts if user doesn't exist).
    fn update_slack_user_id(
        &self,
        _subject_id: &str,
        _slack_user_id: Option<&str>,
    ) -> Result<(), AppError> {
        Ok(())
    }
    /// Find subject_id by slack_user_id (for Slack interaction resolution).
    fn find_by_slack_user_id(&self, _slack_user_id: &str) -> Result<Option<String>, AppError> {
        Ok(None)
    }
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

// --- SchemaRepo ---

#[derive(Debug, Clone)]
pub struct SchemaSnapshotRecord {
    pub database_name: String,
    pub environment: String,
    pub status: String,
    pub snapshot_json: Option<String>,
    pub error_message: Option<String>,
    pub dialect: String,
    pub collected_at: String,
    pub agent_id: String,
}

pub trait SchemaRepo: Send + Sync {
    fn upsert_snapshot(&self, record: &SchemaSnapshotRecord) -> Result<(), AppError>;
    fn get_snapshot(&self, db: &str, env: &str) -> Result<Option<SchemaSnapshotRecord>, AppError>;
    fn get_dialect(&self, db: &str, env: &str) -> Result<Option<String>, AppError>;
    // TODO(v0.2): Return domain DTO (Vec<TableRiskInfo>) instead of raw JSON string
    fn get_tables_for(
        &self,
        db: &str,
        env: &str,
        tables: &[dbward_domain::services::table_extractor::TableRef],
    ) -> Result<Option<String>, AppError>;
}

// --- DryRunRepo ---

#[derive(Debug, Clone)]
pub struct DryRunJobRecord {
    pub id: String,
    pub request_id: String,
    pub database_name: String,
    pub environment: String,
    pub sql_text: String,
    pub status: String,
    pub claimed_by: Option<String>,
    pub claimed_at: Option<String>,
    pub claim_token: Option<String>,
    pub result_json: Option<String>,
    pub error_message: Option<String>,
    pub created_at: String,
    pub completed_at: Option<String>,
}

pub trait DryRunRepo: Send + Sync {
    fn create_jobs(&self, jobs: &[DryRunJobRecord]) -> Result<(), AppError>;
    fn find_pending_for_agent(
        &self,
        databases: &[(String, String)],
    ) -> Result<Vec<DryRunJobRecord>, AppError>;
    fn claim(
        &self,
        job_id: &str,
        agent_id: &str,
        claim_token: &str,
        now: &str,
    ) -> Result<bool, AppError>;
    fn complete(
        &self,
        job_id: &str,
        agent_id: &str,
        claim_token: &str,
        result_json: &str,
        now: &str,
    ) -> Result<bool, AppError>;
    fn fail(
        &self,
        job_id: &str,
        agent_id: &str,
        claim_token: &str,
        error: &str,
        now: &str,
    ) -> Result<bool, AppError>;
    fn reclaim_stale(&self, cutoff: &str) -> Result<u32, AppError>;
    fn find_for_request(&self, request_id: &str) -> Result<Vec<DryRunJobRecord>, AppError>;
    fn get_request_id(&self, job_id: &str) -> Result<Option<String>, AppError>;
}

// --- ContextRepo ---

#[derive(Debug, Clone)]
pub struct RequestContextRecord {
    pub request_id: String,
    pub status: String,
    pub schema_snapshot_collected_at: Option<String>,
    pub tables_json: Option<String>,
    pub sql_review_json: Option<String>,
    pub risk_json: Option<String>,
    pub explain_json: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

pub trait ContextRepo: Send + Sync {
    fn create(&self, ctx: &RequestContextRecord) -> Result<(), AppError>;
    fn get(&self, request_id: &str) -> Result<Option<RequestContextRecord>, AppError>;
    fn update_explain(
        &self,
        request_id: &str,
        explain_json: &str,
        status: &str,
        now: &str,
    ) -> Result<(), AppError>;
    fn timeout_collecting(&self, cutoff: &str, now: &str) -> Result<u32, AppError>;
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

    // ResultPolicy CRUD
    fn create_result_policy(
        &self,
        policy: &dbward_domain::policies::ResultPolicy,
    ) -> Result<(), AppError>;
    fn get_result_policy(
        &self,
        id: &str,
    ) -> Result<Option<dbward_domain::policies::ResultPolicy>, AppError>;
    fn list_result_policies(&self) -> Result<Vec<dbward_domain::policies::ResultPolicy>, AppError>;
    fn update_result_policy(
        &self,
        policy: &dbward_domain::policies::ResultPolicy,
    ) -> Result<bool, AppError>;
    fn delete_result_policy(&self, id: &str) -> Result<bool, AppError>;

    // NotificationPolicy CRUD
    fn create_notification_policy(
        &self,
        policy: &dbward_domain::policies::NotificationPolicy,
    ) -> Result<(), AppError>;
    fn get_notification_policy(
        &self,
        id: &str,
    ) -> Result<Option<dbward_domain::policies::NotificationPolicy>, AppError>;
    fn list_notification_policies(
        &self,
    ) -> Result<Vec<dbward_domain::policies::NotificationPolicy>, AppError>;
    fn update_notification_policy(
        &self,
        policy: &dbward_domain::policies::NotificationPolicy,
    ) -> Result<bool, AppError>;
    fn delete_notification_policy(&self, id: &str) -> Result<bool, AppError>;

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
    fn max_databases(&self) -> u32;
    fn max_workflows(&self) -> u32;
    fn max_webhooks(&self) -> u32;
    fn max_tokens(&self) -> u32;
    fn max_roles(&self) -> u32;
    fn is_enterprise(&self) -> bool;
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

/// Options for storing a result object.
#[derive(Default)]
pub struct PutOptions {
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// A streaming result from object storage.
pub struct ResultStream {
    pub content_length: Option<u64>,
    pub stream: futures_core::stream::BoxStream<'static, Result<bytes::Bytes, AppError>>,
}

impl ResultStream {
    /// Collect all chunks into a Vec<u8> (for tests and small results).
    pub async fn collect(self) -> Result<Vec<u8>, AppError> {
        let stream = self.stream;
        let mut buf = Vec::new();
        let mut pinned = std::pin::pin!(stream);
        loop {
            match std::future::poll_fn(|cx| {
                use futures_core::Stream;
                pinned.as_mut().poll_next(cx)
            })
            .await
            {
                Some(Ok(chunk)) => buf.extend_from_slice(&chunk),
                Some(Err(e)) => return Err(e),
                None => break,
            }
        }
        Ok(buf)
    }
}

#[async_trait]
pub trait ResultStore: Send + Sync {
    async fn put(&self, key: &str, data: &[u8], opts: PutOptions) -> Result<(), AppError>;
    async fn get_stream(&self, key: &str) -> Result<ResultStream, AppError>;
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

// --- WebhookDeliveryRepo ---

pub trait WebhookDeliveryRepo: Send + Sync {
    fn insert(&self, delivery: &WebhookDelivery) -> Result<(), AppError>;
    fn claim_for_retry(&self, now: &str, limit: u32) -> Result<Vec<WebhookDelivery>, AppError>;
    fn mark_delivered(&self, id: &str, now: &str) -> Result<(), AppError>;
    fn mark_failed(
        &self,
        id: &str,
        error: &str,
        next_retry_at: &str,
        attempts: u32,
    ) -> Result<(), AppError>;
    fn mark_dead(&self, id: &str) -> Result<(), AppError>;
    fn reclaim_stale(&self, older_than: &str) -> Result<u32, AppError>;
    fn list_by_status(
        &self,
        status: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<WebhookDelivery>, u32), AppError>;
    fn purge_old(&self, before: &str) -> Result<u32, AppError>;
}

// --- Notifier ---
// (in services.rs)
