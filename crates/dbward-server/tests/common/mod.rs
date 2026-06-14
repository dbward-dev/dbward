//! Shared test stubs for dbward-server integration tests.
//! Provides Noop/Stub implementations of port traits to reduce boilerplate.

#![allow(dead_code)]

pub use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use dbward_app::error::{AppError, AuthError};
use dbward_app::ports::*;
use dbward_domain::auth::*;
use dbward_domain::services::status_machine::{EventDispatcher, TransitionEvent};
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

// --- EventDispatcher ---

pub struct NoopEventDispatcher;
impl EventDispatcher for NoopEventDispatcher {
    fn dispatch(&self, _: TransitionEvent) {}
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
