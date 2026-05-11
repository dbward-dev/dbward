use async_trait::async_trait;

use dbward_domain::entities::*;
use dbward_domain::values::{DatabaseName, Environment};

use crate::error::AppError;

// --- RequestRepo ---

pub trait RequestRepo: Send + Sync {
    fn insert(&self, req: &Request) -> Result<(), AppError>;
    fn get(&self, id: &str) -> Result<Option<Request>, AppError>;
    fn find_by_idempotency_key(&self, key: &str) -> Result<Option<Request>, AppError>;
    fn insert_approval(&self, approval: &Approval) -> Result<(), AppError>;
    fn get_approvals(&self, request_id: &str) -> Result<Vec<Approval>, AppError>;
    fn count_executions(&self, request_id: &str) -> Result<u32, AppError>;

    /// Returns false if the request was not in an expected source state (optimistic lock).
    fn mark_approved(&self, id: &str, now: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError>;
    fn mark_rejected(&self, id: &str, now: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError>;
    fn mark_cancelled(&self, id: &str, actor: &str, reason: Option<&str>, now: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError>;
    fn mark_dispatched(&self, id: &str, now: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError>;
    fn mark_running(&self, id: &str, now: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError>;
    fn mark_executed(&self, id: &str, now: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError>;
    fn mark_failed(&self, id: &str, now: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError>;
    fn cancel_all_for_user(&self, user_id: &str, now: chrono::DateTime<chrono::Utc>) -> Result<u32, AppError>;
}

// --- AgentRepo ---

pub trait AgentRepo: Send + Sync {
    fn upsert(&self, agent: &Agent) -> Result<(), AppError>;
    fn get(&self, agent_id: &str) -> Result<Option<Agent>, AppError>;
    fn create_execution(&self, execution: &Execution) -> Result<(), AppError>;
    fn get_execution(&self, execution_id: &str) -> Result<Option<Execution>, AppError>;
    fn update_execution_status(&self, execution_id: &str, status: ExecutionStatus) -> Result<(), AppError>;
    fn extend_lease(&self, execution_id: &str, new_expiry: chrono::DateTime<chrono::Utc>) -> Result<(), AppError>;
    fn find_dispatched_jobs(&self, databases: &[(DatabaseName, Environment)]) -> Result<Vec<Request>, AppError>;
    fn has_running_migration(&self, db: &DatabaseName, env: &Environment, exclude_request_id: &str) -> Result<bool, AppError>;
    /// Returns executions ordered by created_at ASC (oldest first).
    fn find_executions_for_request(&self, request_id: &str) -> Result<Vec<Execution>, AppError>;
}

// --- UserRepo ---

pub trait UserRepo: Send + Sync {
    fn get(&self, user_id: &str) -> Result<Option<User>, AppError>;
    fn upsert(&self, user: &User) -> Result<(), AppError>;
    fn list(&self) -> Result<Vec<User>, AppError>;
    fn suspend(&self, user_id: &str, now: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError>;
    fn activate(&self, user_id: &str, now: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError>;
    fn is_suspended(&self, user_id: &str) -> Result<bool, AppError>;
}

// --- TokenRepo ---

pub trait TokenRepo: Send + Sync {
    fn create(&self, token: &Token) -> Result<(), AppError>;
    fn verify(&self, prefix: &str, hash: &str) -> Result<Option<Token>, AppError>;
    fn list(&self) -> Result<Vec<Token>, AppError>;
    fn get(&self, token_id: &str) -> Result<Option<Token>, AppError>;
    fn revoke(&self, token_id: &str, now: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError>;
    fn revoke_all_for_user(&self, subject_id: &str, now: chrono::DateTime<chrono::Utc>) -> Result<u32, AppError>;
    fn count_active(&self) -> Result<u32, AppError>;
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
    fn get_workflow(&self, id: &str) -> Result<Option<dbward_domain::policies::Workflow>, AppError>;
    fn list_workflows(&self) -> Result<Vec<dbward_domain::policies::Workflow>, AppError>;
    fn delete_workflow(&self, id: &str) -> Result<bool, AppError>;
    fn count_workflows(&self) -> Result<u32, AppError>;

    fn create_execution_policy(&self, ep: &dbward_domain::policies::ExecutionPolicy) -> Result<(), AppError>;
    fn get_execution_policy(&self, id: &str) -> Result<Option<dbward_domain::policies::ExecutionPolicy>, AppError>;
    fn list_execution_policies(&self) -> Result<Vec<dbward_domain::policies::ExecutionPolicy>, AppError>;
    fn delete_execution_policy(&self, id: &str) -> Result<bool, AppError>;

    fn create_role(&self, role: &dbward_domain::auth::RoleDefinition) -> Result<(), AppError>;
    fn list_roles(&self) -> Result<Vec<dbward_domain::auth::RoleDefinition>, AppError>;
    fn delete_role(&self, name: &str) -> Result<bool, AppError>;
    fn count_roles(&self) -> Result<u32, AppError>;
}

// --- LicenseChecker ---

pub trait LicenseChecker: Send + Sync {
    fn max_tokens(&self) -> u32;
    fn max_workflows(&self) -> u32;
    fn max_webhooks(&self) -> u32;
    fn max_roles(&self) -> u32;
    fn is_pro(&self) -> bool;
}

// --- ResultChannel (UC-6 long-poll) ---

#[async_trait]
pub trait ResultChannel: Send + Sync {
    async fn subscribe(&self, request_id: &str, timeout_secs: u64) -> Result<Option<Vec<u8>>, AppError>;
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
}

/// Claims embedded in an execution token.
pub struct ExecutionTokenClaims {
    pub request_id: String,
    pub operation: String,
    pub database: String,
    pub environment: String,
    pub detail_hash: String,
    pub requester: String,
}

// --- Notifier ---
// (in services.rs)
