//! Shared test stubs for dbward-server integration tests.
//! Provides Noop/Stub implementations of port traits to reduce boilerplate.

#![allow(dead_code)]

pub use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use dbward_app::error::{AppError, AuthError};
use dbward_app::ports::*;
use dbward_domain::auth::*;
use dbward_domain::values::ResultSummary;

// --- RoleResolver ---

pub struct NoopRoleResolver;
impl RoleResolver for NoopRoleResolver {
    fn resolve(
        &self,
        _: &str,
        _: SubjectType,
        _: &[String],
    ) -> Result<Vec<ResolvedRole>, AuthError> {
        Ok(vec![])
    }
}

// --- ResultStore ---

pub struct NoopResultStore;
#[async_trait]
impl ResultStore for NoopResultStore {
    async fn put(&self, _: &str, _: &[u8], _: PutOptions) -> Result<(), AppError> {
        Ok(())
    }
    async fn get_stream(&self, _: &str) -> Result<ResultStream, AppError> {
        Ok(ResultStream {
            content_length: Some(0),
            stream: Box::pin(EmptyResultStream),
        })
    }
    async fn delete(&self, _: &str) -> Result<(), AppError> {
        Ok(())
    }
    async fn health_check(&self) -> Result<(), AppError> {
        Ok(())
    }
}

pub struct EmptyResultStream;
impl futures_core::Stream for EmptyResultStream {
    type Item = Result<bytes::Bytes, AppError>;
    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::task::Poll::Ready(None)
    }
}

// --- ResultChannel ---

pub struct NoopResultChannel;
#[async_trait]
impl ResultChannel for NoopResultChannel {
    fn create_slot(&self, _: &str) {}
    async fn publish(&self, _: &str, _: ResultSummary) {}
    async fn subscribe(&self, _: &str, _: u64) -> Result<Option<ResultSummary>, AppError> {
        Ok(None)
    }
    async fn notify_all(&self) {}
}

// --- TokenSigner ---

pub struct NoopTokenSigner;
impl TokenSigner for NoopTokenSigner {
    fn sign(&self, _: &ExecutionTokenClaims) -> String {
        "signed".into()
    }
    fn public_key_hex(&self) -> String {
        "aa".repeat(32)
    }
}

// --- Notifier ---

pub struct NoopNotifier;
impl Notifier for NoopNotifier {
    fn dispatch(&self, _: WebhookEvent) {}
}

// --- SsrfValidator ---

pub struct NoopSsrfValidator;
impl SsrfValidator for NoopSsrfValidator {
    fn validate_url(&self, _: &str) -> Result<(), AppError> {
        Ok(())
    }
}

// --- WebhookSender ---

pub struct NoopWebhookSender;
#[async_trait]
impl WebhookSender for NoopWebhookSender {
    async fn send_one(&self, _: &str, _: &str, _: Option<&str>) -> Result<(), String> {
        Ok(())
    }
}

// --- LicenseChecker ---

pub struct NoopLicenseChecker;
impl LicenseChecker for NoopLicenseChecker {
    fn max_users(&self) -> u32 {
        10
    }
    fn max_databases(&self) -> u32 {
        u32::MAX
    }
    fn max_workflows(&self) -> u32 {
        10
    }
    fn max_webhooks(&self) -> u32 {
        3
    }
    fn max_roles(&self) -> u32 {
        10
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
    fn check_expiry(&self, _: chrono::DateTime<chrono::Utc>) {}
}

// --- Clock ---

pub struct RealClock;
impl Clock for RealClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
    }
}

// --- IdGenerator ---

pub struct SeqIdGen(pub AtomicU64);
impl SeqIdGen {
    pub fn new() -> Self {
        Self(AtomicU64::new(1))
    }
}
impl IdGenerator for SeqIdGen {
    fn generate(&self) -> String {
        let n = self.0.fetch_add(1, Ordering::SeqCst);
        format!("id-{n:04}")
    }
}

// --- NoopUnitOfWork ---

pub struct NoopUnitOfWork;

impl dbward_app::ports::UnitOfWork for NoopUnitOfWork {
    fn execute(
        &self,
        f: Box<
            dyn FnOnce(
                    &dyn dbward_app::ports::transaction::TxScope,
                ) -> Result<(), dbward_app::error::AppError>
                + '_,
        >,
    ) -> Result<(), dbward_app::error::AppError> {
        f(&NoopTxScope)
    }
    fn execute_with_result(
        &self,
        f: Box<
            dyn FnOnce(
                    &dyn dbward_app::ports::transaction::TxScope,
                )
                    -> Result<Box<dyn std::any::Any>, dbward_app::error::AppError>
                + '_,
        >,
    ) -> Result<Box<dyn std::any::Any>, dbward_app::error::AppError> {
        f(&NoopTxScope)
    }

    fn execute_sync(
        &self,
        _f: Box<
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

struct NoopTxScope;
impl dbward_app::ports::transaction::RequestWriterOps for NoopTxScope {
    fn insert_request(
        &self,
        _: &dbward_domain::entities::Request,
    ) -> Result<(), dbward_app::error::AppError> {
        Ok(())
    }
    fn mark_dispatched(
        &self,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, dbward_app::error::AppError> {
        Ok(true)
    }
    fn mark_approved(
        &self,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, dbward_app::error::AppError> {
        Ok(true)
    }
    fn mark_rejected(
        &self,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, dbward_app::error::AppError> {
        Ok(true)
    }
    fn mark_running(
        &self,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, dbward_app::error::AppError> {
        Ok(true)
    }
    fn mark_cancelled(
        &self,
        _: &str,
        _: &str,
        _: Option<&str>,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, dbward_app::error::AppError> {
        Ok(true)
    }
    fn mark_executed(
        &self,
        _: &str,
        _: bool,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, dbward_app::error::AppError> {
        Ok(true)
    }
    fn mark_expired(
        &self,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, dbward_app::error::AppError> {
        Ok(true)
    }
    fn mark_execution_lost(
        &self,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, dbward_app::error::AppError> {
        Ok(true)
    }
    fn mark_approved_from_dispatched(
        &self,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, dbward_app::error::AppError> {
        Ok(true)
    }
    fn cancel_all_for_user(
        &self,
        _: &str,
        _: &str,
        _: Option<&str>,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<String>, dbward_app::error::AppError> {
        Ok(vec![])
    }
}
impl dbward_app::ports::transaction::ApprovalWriterOps for NoopTxScope {
    fn insert_approval(
        &self,
        _: &dbward_domain::entities::Approval,
    ) -> Result<(), dbward_app::error::AppError> {
        Ok(())
    }
}
impl dbward_app::ports::transaction::AuditWriterOps for NoopTxScope {
    fn record(
        &self,
        _: &dbward_domain::entities::AuditEvent,
    ) -> Result<(), dbward_app::error::AppError> {
        Ok(())
    }
}
impl dbward_app::ports::transaction::ExecutionWriterOps for NoopTxScope {
    fn insert_execution(
        &self,
        _: &dbward_domain::entities::Execution,
    ) -> Result<(), dbward_app::error::AppError> {
        Ok(())
    }
    fn mark_completed(
        &self,
        _: &str,
        _: bool,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, dbward_app::error::AppError> {
        Ok(true)
    }
}
impl dbward_app::ports::transaction::TokenWriterOps for NoopTxScope {
    fn create_token(
        &self,
        _: &dbward_domain::entities::Token,
    ) -> Result<(), dbward_app::error::AppError> {
        Ok(())
    }
    fn revoke_token(
        &self,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, dbward_app::error::AppError> {
        Ok(true)
    }
    fn revoke_all_for_user(
        &self,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<u32, dbward_app::error::AppError> {
        Ok(0)
    }
}
impl dbward_app::ports::transaction::UserWriterOps for NoopTxScope {
    fn suspend_user(
        &self,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, dbward_app::error::AppError> {
        Ok(true)
    }
    fn activate_user(
        &self,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, dbward_app::error::AppError> {
        Ok(true)
    }
}
impl dbward_app::ports::transaction::ResultWriterOps for NoopTxScope {
    fn insert_result(
        &self,
        _result: &dbward_domain::entities::ExecutionResult,
    ) -> Result<(), dbward_app::error::AppError> {
        Ok(())
    }
    fn insert_result_access(
        &self,
        _access: &[dbward_domain::entities::ResultAccess],
    ) -> Result<(), dbward_app::error::AppError> {
        Ok(())
    }
}
impl dbward_app::ports::transaction::ApprovalReaderOps for NoopTxScope {
    fn get_approvals(
        &self,
        _: &str,
    ) -> Result<Vec<dbward_domain::entities::Approval>, dbward_app::error::AppError> {
        Ok(vec![])
    }
    fn get_request_state(
        &self,
        _: &str,
    ) -> Result<Option<dbward_app::ports::transaction::RequestState>, dbward_app::error::AppError>
    {
        Ok(Some((
            dbward_domain::entities::RequestStatus::Pending,
            None,
        )))
    }
}
impl dbward_app::ports::transaction::TxScope for NoopTxScope {}

// --- AuditSigner ---
pub struct NoopAuditSigner;
impl dbward_app::ports::crypto::AuditSigner for NoopAuditSigner {
    fn sign(&self, _payload: &[u8]) -> Vec<u8> {
        vec![0u8; 64]
    }
    fn current_key_id(&self) -> &str {
        "noop"
    }
}
impl dbward_app::ports::crypto::AuditVerifier for NoopAuditSigner {
    fn verify(&self, _payload: &[u8], _signature: &[u8]) -> bool {
        true
    }
    fn verify_with_key(&self, _key_id: &str, _payload: &[u8], _signature: &[u8]) -> bool {
        true
    }
}
