//! Unified validation types for configuration diagnostics.
//!
//! These types are used by both `load()` (fail-fast) and `diagnose_static()` (collect-all)
//! to provide consistent error/warning reporting.

/// Severity level for validation issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationSeverity {
    /// Configuration error that prevents startup.
    Error,
    /// Warning that should be addressed but doesn't block startup.
    Warning,
}

/// A single validation issue found during configuration analysis.
#[derive(Debug, Clone)]
pub struct ValidationIssue {
    /// Unique identifier for this issue type (e.g., "workflow_dead_steps").
    pub id: &'static str,
    /// Whether this is an error or warning.
    pub severity: ValidationSeverity,
    /// Human-readable description of the issue.
    pub message: String,
    /// Optional hint for how to fix the issue.
    pub hint: Option<String>,
    /// Optional structured context data for rich display.
    pub context: Option<IssueContext>,
}

impl ValidationIssue {
    /// Create a new error issue.
    pub fn error(id: &'static str, message: impl Into<String>) -> Self {
        Self {
            id,
            severity: ValidationSeverity::Error,
            message: message.into(),
            hint: None,
            context: None,
        }
    }

    /// Create a new warning issue.
    pub fn warning(id: &'static str, message: impl Into<String>) -> Self {
        Self {
            id,
            severity: ValidationSeverity::Warning,
            message: message.into(),
            hint: None,
            context: None,
        }
    }

    /// Add a hint to this issue.
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// Add structured context to this issue.
    pub fn with_context(mut self, context: IssueContext) -> Self {
        self.context = Some(context);
        self
    }

    /// Returns true if this is an error (not a warning).
    pub fn is_error(&self) -> bool {
        self.severity == ValidationSeverity::Error
    }
}

/// Structured context data for specific issue types.
///
/// This allows rich display of validation issues (e.g., tables showing coverage gaps).
#[derive(Debug, Clone)]
pub enum IssueContext {
    /// workflow_coverage: DB×env coverage information.
    WorkflowCoverage(Vec<CoverageEntry>),
    /// workflow_step_validity: dead steps information.
    DeadSteps(Vec<DeadStepEntry>),
    /// workflow_validity: invalid workflow information.
    InvalidWorkflows(Vec<InvalidWorkflowEntry>),
    /// sql_review_safety: dangerous SQL review settings.
    SqlReviewSafety(Vec<SqlReviewSafetyEntry>),
    /// built_in_role_collision: collision with built-in roles.
    BuiltInRoleCollision(Vec<String>),
    /// env_var_issues: environment variable problems.
    EnvVarIssues(Vec<EnvVarIssueEntry>),
    /// slack_config: Slack configuration issues.
    SlackConfig(Vec<SlackConfigEntry>),
}

/// Coverage entry for workflow_coverage issue.
#[derive(Debug, Clone)]
pub struct CoverageEntry {
    pub database: String,
    pub environment: String,
    pub workflow: Option<String>,
    pub auto_approve: Option<String>,
}

/// Dead step entry for workflow_step_validity issue.
#[derive(Debug, Clone)]
pub struct DeadStepEntry {
    pub workflow_index: usize,
    pub workflow_name: String,
    pub step_index: usize,
    pub reason: String,
}

/// Invalid workflow entry for workflow_validity issue.
#[derive(Debug, Clone)]
pub struct InvalidWorkflowEntry {
    pub workflow_index: usize,
    pub workflow_name: String,
    pub reason: String,
}

/// SQL review safety entry for sql_review_safety issue.
#[derive(Debug, Clone)]
pub struct SqlReviewSafetyEntry {
    pub database: String,
    pub environment: String,
    pub rule: String,
}

/// Environment variable issue entry.
#[derive(Debug, Clone)]
pub struct EnvVarIssueEntry {
    pub var_name: String,
    pub issue_type: EnvVarIssueType,
}

/// Type of environment variable issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvVarIssueType {
    /// Variable is not defined in environment.
    Undefined,
    /// Sensitive variable (token/password/secret) is empty.
    EmptySensitive,
}

/// Slack configuration issue entry.
#[derive(Debug, Clone)]
pub struct SlackConfigEntry {
    pub field: String,
    pub issue: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let issue = ValidationIssue::error("test_error", "Something went wrong");
        assert_eq!(issue.id, "test_error");
        assert!(issue.is_error());
        assert_eq!(issue.severity, ValidationSeverity::Error);
        assert_eq!(issue.message, "Something went wrong");
        assert!(issue.hint.is_none());
        assert!(issue.context.is_none());
    }

    #[test]
    fn test_warning_creation() {
        let issue = ValidationIssue::warning("test_warning", "Consider fixing this");
        assert_eq!(issue.id, "test_warning");
        assert!(!issue.is_error());
        assert_eq!(issue.severity, ValidationSeverity::Warning);
    }

    #[test]
    fn test_with_hint() {
        let issue = ValidationIssue::error("test", "Error").with_hint("Try doing X instead");
        assert_eq!(issue.hint, Some("Try doing X instead".to_string()));
    }

    #[test]
    fn test_with_context() {
        let context = IssueContext::BuiltInRoleCollision(vec!["admin".to_string()]);
        let issue = ValidationIssue::error("collision", "Role collision").with_context(context);
        assert!(issue.context.is_some());
    }
}
