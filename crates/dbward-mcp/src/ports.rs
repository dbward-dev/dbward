use async_trait::async_trait;
use serde_json::Value;

use dbward_domain::auth::AuthUser;

/// Result type for MCP backend operations.
pub type McpResult<T> = Result<T, String>;

/// Backend operations for MCP tool handlers.
/// CLI implements this via ServerClient (HTTP), Server implements via UC direct calls.
#[async_trait]
pub trait McpBackend: Send + Sync {
    // --- Request operations ---

    async fn create_request(
        &self,
        input: CreateRequestInput,
        user: &AuthUser,
    ) -> McpResult<CreateRequestOutput>;

    async fn resume_and_wait(
        &self,
        request_id: &str,
        timeout_secs: u64,
        user: &AuthUser,
    ) -> McpResult<WaitOutput>;

    async fn wait_request(
        &self,
        request_id: &str,
        timeout_secs: u64,
        user: &AuthUser,
    ) -> McpResult<WaitOutput>;

    async fn list_pending(&self, limit: u32, user: &AuthUser) -> McpResult<Value>;

    async fn find_similar(&self, sql: &str, limit: u32, user: &AuthUser) -> McpResult<Value>;

    async fn preview_impact(
        &self,
        sql: &str,
        database: &str,
        environment: &str,
        user: &AuthUser,
    ) -> McpResult<Value>;

    async fn who_can_approve(&self, request_id: &str, user: &AuthUser) -> McpResult<Value>;

    async fn explain_policy_failure(
        &self,
        request_id: Option<&str>,
        operation: Option<&str>,
        database: &str,
        environment: &str,
        user: &AuthUser,
    ) -> McpResult<Value>;

    // --- Schema operations ---

    async fn inspect_schema(
        &self,
        database: &str,
        environment: Option<&str>,
        table: Option<&str>,
        summary: bool,
        user: &AuthUser,
    ) -> McpResult<Value>;

    async fn list_databases(&self, user: &AuthUser) -> McpResult<Value>;

    // --- Request read (no side effects) ---

    async fn get_request(&self, request_id: &str, user: &AuthUser) -> McpResult<Value>;

    // --- Migration operations (remote-capable subset) ---

    async fn migrate_status(
        &self,
        database: &str,
        environment: &str,
        user: &AuthUser,
    ) -> McpResult<Value>;

    // --- Audit operations ---

    async fn audit_recent(&self, limit: u32, user: &AuthUser) -> McpResult<Value>;
}

// --- Input/Output DTOs ---

pub struct CreateRequestInput {
    pub operation: String,
    pub environment: String,
    pub database: String,
    pub detail: String,
    pub reason: Option<String>,
    pub idempotency_key: Option<String>,
}

pub struct CreateRequestOutput {
    pub request_id: String,
    pub status: RequestStatus,
}

/// Simplified request status for MCP layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestStatus {
    Pending,
    Approved,
    Rejected,
    Failed,
}

impl RequestStatus {
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }

    pub fn is_terminal_failure(&self) -> bool {
        matches!(self, Self::Rejected | Self::Failed)
    }
}

pub enum WaitOutput {
    /// Execution completed, result text
    Completed(String),
    /// Still pending (approval needed)
    Pending { request_id: String },
    /// Timed out waiting
    TimedOut { request_id: String },
}

// --- Elicitation ---

/// Transport for server→client elicitation requests.
#[async_trait]
pub trait ElicitationTransport: Send + Sync {
    async fn ask(&self, message: &str, schema: Value) -> Result<ElicitResult, String>;
    fn supported(&self) -> bool;
}

#[derive(Debug, Clone)]
pub enum ElicitResult {
    Accept { content: Value },
    Decline,
    Cancel,
}

/// No-op implementation for Phase 1 HTTP transport (elicitation not supported).
pub struct NoopElicitation;

#[async_trait]
impl ElicitationTransport for NoopElicitation {
    async fn ask(&self, _message: &str, _schema: Value) -> Result<ElicitResult, String> {
        Err("elicitation not supported".into())
    }

    fn supported(&self) -> bool {
        false
    }
}
