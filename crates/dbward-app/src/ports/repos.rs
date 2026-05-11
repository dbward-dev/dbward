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
}

// --- UserRepo ---

pub trait UserRepo: Send + Sync {
    fn get(&self, user_id: &str) -> Result<Option<User>, AppError>;
    fn upsert(&self, user: &User) -> Result<(), AppError>;
    fn list(&self) -> Result<Vec<User>, AppError>;
    fn suspend(&self, user_id: &str) -> Result<(), AppError>;
    fn activate(&self, user_id: &str) -> Result<(), AppError>;
}

// --- TokenRepo ---

pub trait TokenRepo: Send + Sync {
    fn create(&self, token: &Token) -> Result<(), AppError>;
    fn verify(&self, prefix: &str, hash: &str) -> Result<Option<Token>, AppError>;
    fn list(&self) -> Result<Vec<Token>, AppError>;
    fn revoke(&self, token_id: &str) -> Result<(), AppError>;
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
