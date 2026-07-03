//! Transactional Unit of Work port for fail-closed audit.
//!
//! # Invariant
//! The closure passed to `execute` / `execute_with_result` is **synchronous**.
//! No `.await`, no spawning tasks, no blocking I/O other than SQLite.
//! Async operations (webhook, result channel, etc.) happen AFTER the closure returns.

use std::any::Any;

use dbward_domain::entities::AuditEvent;

use crate::error::AppError;

/// Operations available on requests within a transaction.
pub trait RequestWriterOps {
    fn insert_request(&self, req: &dbward_domain::entities::Request) -> Result<(), AppError>;
    fn mark_dispatched(
        &self,
        id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, AppError>;
    fn mark_approved(&self, id: &str, now: chrono::DateTime<chrono::Utc>)
    -> Result<bool, AppError>;
    fn mark_rejected(&self, id: &str, now: chrono::DateTime<chrono::Utc>)
    -> Result<bool, AppError>;
    fn mark_running(&self, id: &str, now: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError>;
    fn mark_cancelled(
        &self,
        id: &str,
        cancelled_by: &str,
        reason: Option<&str>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, AppError>;
    fn mark_executed(
        &self,
        id: &str,
        success: bool,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, AppError>;
    fn mark_expired(&self, id: &str, now: chrono::DateTime<chrono::Utc>) -> Result<bool, AppError>;
    fn mark_execution_lost(
        &self,
        id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, AppError>;
    /// Revert dispatched → approved (dispatch_timeout recovery).
    fn mark_approved_from_dispatched(
        &self,
        id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, AppError>;
    /// Cancel all pending/dispatched requests for a user. Returns cancelled IDs.
    fn cancel_all_for_user(
        &self,
        user_id: &str,
        cancelled_by: &str,
        reason: Option<&str>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<String>, AppError>;
}

/// Operations available on approvals within a transaction.
pub trait ApprovalWriterOps {
    fn insert_approval(&self, approval: &dbward_domain::entities::Approval)
    -> Result<(), AppError>;
}

/// Read operations on approvals within a transaction (for in-TX recheck).
/// Status + expiry snapshot for in-TX recheck.
pub type RequestState = (
    dbward_domain::entities::RequestStatus,
    Option<chrono::DateTime<chrono::Utc>>,
);

pub trait ApprovalReaderOps {
    fn get_approvals(
        &self,
        request_id: &str,
    ) -> Result<Vec<dbward_domain::entities::Approval>, AppError>;
    /// Returns (status, expires_at) for authoritative in-TX recheck.
    fn get_request_state(&self, request_id: &str) -> Result<Option<RequestState>, AppError>;
}

/// Operations available on audit within a transaction.
pub trait AuditWriterOps {
    fn record(&self, event: &AuditEvent) -> Result<(), AppError>;
}

/// Operations available on executions within a transaction.
pub trait ExecutionWriterOps {
    fn insert_execution(&self, exec: &dbward_domain::entities::Execution) -> Result<(), AppError>;
    fn mark_completed(
        &self,
        execution_id: &str,
        success: bool,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, AppError>;
}

/// Operations available on tokens within a transaction.
pub trait TokenWriterOps {
    fn create_token(&self, token: &dbward_domain::entities::Token) -> Result<(), AppError>;
    fn revoke_token(
        &self,
        token_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, AppError>;
    fn revoke_all_for_user(
        &self,
        user_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<u32, AppError>;
}

/// Operations available on users within a transaction.
pub trait UserWriterOps {
    fn suspend_user(
        &self,
        user_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, AppError>;
    fn activate_user(
        &self,
        user_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, AppError>;
    /// Insert or update user in transaction.
    fn upsert_user_tx(
        &self,
        _user: &dbward_domain::entities::User,
    ) -> Result<(), AppError> {
        Ok(())
    }
    /// Create token in transaction.
    fn create_token_tx(
        &self,
        _token: &dbward_domain::entities::Token,
    ) -> Result<(), AppError> {
        Ok(())
    }
}

/// Operations available on execution results within a transaction.
pub trait ResultWriterOps {
    fn insert_result(
        &self,
        result: &dbward_domain::entities::ExecutionResult,
    ) -> Result<(), AppError>;
    fn insert_result_access(
        &self,
        access: &[dbward_domain::entities::ResultAccess],
    ) -> Result<(), AppError>;
}

/// Combined transaction scope providing all writer operations.
pub trait TxScope:
    RequestWriterOps
    + ApprovalWriterOps
    + ApprovalReaderOps
    + AuditWriterOps
    + ExecutionWriterOps
    + TokenWriterOps
    + UserWriterOps
    + ResultWriterOps
{
}

/// Unit of Work: executes a closure atomically within a single DB transaction.
///
/// Holding the connection lock for the entire closure guarantees no interleaving.
/// The closure receives `&dyn TxScope` to perform all writes.
///
/// # Safety contract
/// The closure MUST NOT call any standalone repo method that acquires `DbConn`
/// (e.g., `RequestWriter::mark_cancelled`, `AuditLogger::record`).
/// Doing so will deadlock because the MutexGuard is already held.
/// All writes must go through the provided `TxScope`.
///
/// # Object safety
/// Uses `Box<dyn FnOnce>` to remain object-safe (`Arc<dyn UnitOfWork>`).
#[allow(clippy::type_complexity)]
pub trait UnitOfWork: Send + Sync {
    /// Execute operations atomically (no return value).
    fn execute(
        &self,
        f: Box<dyn FnOnce(&dyn TxScope) -> Result<(), AppError> + '_>,
    ) -> Result<(), AppError>;

    /// Execute operations atomically and return a value.
    fn execute_with_result(
        &self,
        f: Box<dyn FnOnce(&dyn TxScope) -> Result<Box<dyn Any>, AppError> + '_>,
    ) -> Result<Box<dyn Any>, AppError>;

    /// Execute config-sync operations atomically and return a value.
    fn execute_sync(
        &self,
        f: Box<
            dyn FnOnce(&dyn crate::ports::sync_scope::SyncScope) -> Result<Box<dyn Any>, AppError>
                + '_,
        >,
    ) -> Result<Box<dyn Any>, AppError>;
}

/// Typed convenience wrapper for `execute_with_result`.
pub fn uow_execute<T: 'static>(
    uow: &dyn UnitOfWork,
    f: impl FnOnce(&dyn TxScope) -> Result<T, AppError>,
) -> Result<T, AppError> {
    let boxed =
        uow.execute_with_result(Box::new(|tx| f(tx).map(|v| Box::new(v) as Box<dyn Any>)))?;
    boxed
        .downcast::<T>()
        .map(|b| *b)
        .map_err(|_| AppError::Internal("UoW type downcast failed".into()))
}

/// Typed convenience wrapper for `execute_sync`.
pub fn uow_execute_sync<T: 'static>(
    uow: &dyn UnitOfWork,
    f: impl FnOnce(&dyn crate::ports::sync_scope::SyncScope) -> Result<T, AppError>,
) -> Result<T, AppError> {
    let boxed = uow.execute_sync(Box::new(|scope| {
        f(scope).map(|v| Box::new(v) as Box<dyn Any>)
    }))?;
    boxed
        .downcast::<T>()
        .map(|b| *b)
        .map_err(|_| AppError::Internal("UoW sync type downcast failed".into()))
}
