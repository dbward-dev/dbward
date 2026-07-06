use crate::error::AppError;
use chrono::{DateTime, Utc};

/// Onboarding request entity (read from DB).
#[derive(Debug, Clone)]
pub struct OnboardingRequest {
    pub id: String,
    pub slack_user_id: String,
    pub display_name: Option<String>,
    pub requested_roles: Vec<String>,
    pub requested_groups: Vec<String>,
    pub reason: Option<String>,
    pub status: String,
    pub message_ts: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Input for creating a new onboarding request.
#[derive(Debug, Clone)]
pub struct CreateOnboardingInput {
    pub id: String,
    pub slack_user_id: String,
    pub display_name: Option<String>,
    pub requested_roles: Vec<String>,
    pub requested_groups: Vec<String>,
    pub reason: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Result of claiming an onboarding request for approval/rejection.
#[derive(Debug, Clone)]
pub struct ClaimResult {
    pub claimed: bool,
}

/// Port trait for onboarding request persistence.
pub trait OnboardingRequestRepo: Send + Sync {
    /// Check if a pending request exists for this Slack user.
    fn has_pending(&self, slack_user_id: &str) -> Result<bool, AppError>;

    /// Insert a new pending onboarding request.
    fn create(&self, input: &CreateOnboardingInput) -> Result<(), AppError>;

    /// Set the message_ts (Slack channel message reference).
    fn set_message_ts(&self, request_id: &str, message_ts: &str) -> Result<(), AppError>;

    /// Get a pending request by ID. Returns None if not found or not pending.
    fn get_pending(&self, request_id: &str) -> Result<Option<OnboardingRequest>, AppError>;

    /// Atomically claim a request as approved (CAS: pending → approved).
    /// Returns ClaimResult { claimed: true } if successfully claimed, false if already processed.
    fn claim_approved(
        &self,
        request_id: &str,
        decided_by: &str,
        decided_at: DateTime<Utc>,
        approved_roles: &[String],
        approved_groups: &[String],
        decision_comment: Option<&str>,
    ) -> Result<ClaimResult, AppError>;

    /// Atomically claim a request as rejected (CAS: pending → rejected).
    fn claim_rejected(
        &self,
        request_id: &str,
        decided_by: &str,
        decided_at: DateTime<Utc>,
        decision_comment: Option<&str>,
    ) -> Result<ClaimResult, AppError>;

    /// Rollback an approved request back to pending (on user creation failure).
    fn rollback_to_pending(&self, request_id: &str) -> Result<(), AppError>;
}
