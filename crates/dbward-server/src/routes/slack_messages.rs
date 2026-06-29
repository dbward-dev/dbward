// Common error messages for Slack interaction responses.

pub const REQUEST_NOT_FOUND: &str = "Request not found.";
pub const REQUEST_EXPIRED: &str = "Request has expired.";
pub const AUTH_FAILED: &str = "Authentication failed.";
pub const ACCOUNT_SUSPENDED: &str = "Account suspended.";
pub const ACCOUNT_NOT_LINKED: &str = "Slack account not linked to dbward.";
pub const PERMISSION_DENIED_ACCESS: &str = "You don't have permission to access this request.";
pub const PERMISSION_DENIED_VIEW: &str = "You don't have permission to view this request.";
pub const PERMISSION_DENIED_VIEW_RESULT: &str = "You don't have permission to view this result.";
pub const PERMISSION_DENIED_RESUME: &str = "You don't have permission to resume this request.";
pub const PERMISSION_DENIED_APPROVE: &str = "Not eligible to approve/reject this request.";
pub const PERMISSION_DENIED_GENERIC: &str = "Permission denied.";
pub const GENERIC_ERROR: &str = "An error occurred. Please try again.";
pub const DECISION_REQUIRED: &str = "Please select Approve or Reject.";
pub const COMMENT_REQUIRED: &str = "Comment is required for rejection.";
pub const INVALID_DECISION: &str = "Invalid decision.";
pub const SQL_REQUIRED: &str = "SQL is required.";
pub const DB_ENV_REQUIRED: &str = "Database/Environment is required.";
pub const INVALID_SELECTION: &str = "Invalid selection.";
pub const INVALID_DB_NAME: &str = "Invalid database name.";
pub const INVALID_ENVIRONMENT: &str = "Invalid environment.";
pub const DB_NOT_FOUND: &str = "Database not found or not registered.";
pub const DUPLICATE_REQUEST: &str = "Duplicate request (already submitted).";
pub const CREATE_FAILED: &str = "Request creation failed. Try again or use CLI.";
pub const RESUME_FAILED: &str = "Resume failed. Please try again or use the CLI.";
pub const RESULT_LOAD_FAILED: &str = "Failed to load result.";
pub const DB_LOAD_FAILED: &str = "Failed to load databases.";
