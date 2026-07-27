//! Environment variable auditing and diagnostics utilities.
//!
//! This module provides functions for auditing environment variable usage
//! in configuration files before expansion, used by both Server and Agent configs.

use regex::Regex;
use std::sync::LazyLock;

use crate::expand::ENV_VAR_PATTERN;
use crate::validation::{EnvVarIssueEntry, EnvVarIssueType, IssueContext, ValidationIssue};

/// Compiled regex for environment variable references, reusing the pattern from expand.rs.
static ENV_VAR_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(ENV_VAR_PATTERN).expect("BUG: invalid ENV_VAR_PATTERN regex"));

/// Sensitive variable name patterns (lowercase).
const SENSITIVE_PATTERNS: &[&str] = &["token", "password", "secret", "key", "credential"];

/// Audit environment variables referenced in a raw TOML string.
///
/// This function scans for `${VAR}` patterns and checks their status in the environment.
/// Variables with default values (`${VAR:-default}`) are skipped.
///
/// # Returns
/// A list of `EnvVarIssueEntry` for any problematic variables:
/// - `Undefined`: Variable is not defined in the environment
/// - `EmptySensitive`: Variable is defined but empty, and appears to be sensitive
pub fn audit_env_vars(raw_toml: &str) -> Vec<EnvVarIssueEntry> {
    let mut issues = Vec::new();
    let mut seen_vars: std::collections::HashSet<String> = std::collections::HashSet::new();

    for cap in ENV_VAR_RE.captures_iter(raw_toml) {
        let var_name = &cap[1];
        // Check if this reference has a default value (capture group 2)
        let has_default = cap.get(2).is_some();

        // Skip if we've already processed this variable
        if !seen_vars.insert(var_name.to_string()) {
            continue;
        }

        // Skip if this reference has a default value
        if has_default {
            continue;
        }

        match std::env::var(var_name) {
            Ok(value) => {
                // Check if it's a sensitive variable that's empty
                if value.is_empty() && is_sensitive_var(var_name) {
                    issues.push(EnvVarIssueEntry {
                        var_name: var_name.to_string(),
                        issue_type: EnvVarIssueType::EmptySensitive,
                    });
                }
                // Non-sensitive empty values are allowed (empty string is valid)
            }
            Err(_) => {
                issues.push(EnvVarIssueEntry {
                    var_name: var_name.to_string(),
                    issue_type: EnvVarIssueType::Undefined,
                });
            }
        }
    }

    issues
}

/// Check if a variable name appears to be sensitive based on common patterns.
fn is_sensitive_var(var_name: &str) -> bool {
    let lower = var_name.to_lowercase();
    SENSITIVE_PATTERNS.iter().any(|p| lower.contains(p))
}

/// Convert env var audit results to ValidationIssues.
///
/// This is used by `diagnose_static()` to include env var issues in the diagnostics.
pub fn env_issues_to_validation_issues(issues: &[EnvVarIssueEntry]) -> Vec<ValidationIssue> {
    let mut result = Vec::new();

    // Group by issue type for context
    let undefined: Vec<_> = issues
        .iter()
        .filter(|i| i.issue_type == EnvVarIssueType::Undefined)
        .cloned()
        .collect();
    let empty_sensitive: Vec<_> = issues
        .iter()
        .filter(|i| i.issue_type == EnvVarIssueType::EmptySensitive)
        .cloned()
        .collect();

    // Undefined variables are errors
    for entry in &undefined {
        result.push(
            ValidationIssue::error(
                "env_var_undefined",
                format!("environment variable ${{{0}}} is not defined", entry.var_name),
            )
            .with_hint("Set the variable or use a default: ${VAR:-default}"),
        );
    }

    // Empty sensitive variables are warnings
    for entry in &empty_sensitive {
        result.push(
            ValidationIssue::warning(
                "env_var_empty_sensitive",
                format!(
                    "sensitive environment variable ${{{0}}} is defined but empty",
                    entry.var_name
                ),
            )
            .with_hint("This may cause authentication failures"),
        );
    }

    // Add context if there are issues
    if !issues.is_empty() && let Some(first) = result.first_mut() {
        first.context = Some(IssueContext::EnvVarIssues(issues.to_vec()));
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_audit_undefined_var() {
        // Use a unique var name unlikely to be set
        let toml = r#"value = "${DBWARD_TEST_UNDEFINED_XYZ123}""#;
        // SAFETY: Test-only, single-threaded
        unsafe { env::remove_var("DBWARD_TEST_UNDEFINED_XYZ123") };

        let issues = audit_env_vars(toml);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].var_name, "DBWARD_TEST_UNDEFINED_XYZ123");
        assert_eq!(issues[0].issue_type, EnvVarIssueType::Undefined);
    }

    #[test]
    fn test_audit_with_default_skipped() {
        // Variables with defaults should be skipped
        let toml = r#"value = "${DBWARD_TEST_WITH_DEFAULT:-fallback}""#;
        // SAFETY: Test-only, single-threaded
        unsafe { env::remove_var("DBWARD_TEST_WITH_DEFAULT") };

        let issues = audit_env_vars(toml);
        assert!(issues.is_empty());
    }

    #[test]
    fn test_audit_sensitive_empty() {
        let var_name = "DBWARD_TEST_SECRET_TOKEN";
        // SAFETY: Test-only, single-threaded
        unsafe { env::set_var(var_name, "") };
        let toml = format!(r#"token = "${{{var_name}}}""#);

        let issues = audit_env_vars(&toml);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].var_name, var_name);
        assert_eq!(issues[0].issue_type, EnvVarIssueType::EmptySensitive);

        // SAFETY: Test-only, single-threaded
        unsafe { env::remove_var(var_name) };
    }

    #[test]
    fn test_audit_non_sensitive_empty_ok() {
        let var_name = "DBWARD_TEST_EMPTY_VALUE";
        // SAFETY: Test-only, single-threaded
        unsafe { env::set_var(var_name, "") };
        let toml = format!(r#"prefix = "${{{var_name}}}""#);

        let issues = audit_env_vars(&toml);
        // Non-sensitive empty is OK
        assert!(issues.is_empty());

        // SAFETY: Test-only, single-threaded
        unsafe { env::remove_var(var_name) };
    }

    #[test]
    fn test_audit_defined_var_ok() {
        let var_name = "DBWARD_TEST_DEFINED";
        // SAFETY: Test-only, single-threaded
        unsafe { env::set_var(var_name, "some_value") };
        let toml = format!(r#"value = "${{{var_name}}}""#);

        let issues = audit_env_vars(&toml);
        assert!(issues.is_empty());

        // SAFETY: Test-only, single-threaded
        unsafe { env::remove_var(var_name) };
    }

    #[test]
    fn test_is_sensitive_var() {
        assert!(is_sensitive_var("DB_PASSWORD"));
        assert!(is_sensitive_var("API_TOKEN"));
        assert!(is_sensitive_var("SECRET_KEY"));
        assert!(is_sensitive_var("my_credential"));
        assert!(!is_sensitive_var("DATABASE_URL"));
        assert!(!is_sensitive_var("PORT"));
    }

    #[test]
    fn test_env_issues_to_validation_issues() {
        let issues = vec![
            EnvVarIssueEntry {
                var_name: "MISSING_VAR".to_string(),
                issue_type: EnvVarIssueType::Undefined,
            },
            EnvVarIssueEntry {
                var_name: "EMPTY_TOKEN".to_string(),
                issue_type: EnvVarIssueType::EmptySensitive,
            },
        ];

        let validation_issues = env_issues_to_validation_issues(&issues);
        assert_eq!(validation_issues.len(), 2);
        assert!(validation_issues[0].is_error()); // undefined is error
        assert!(!validation_issues[1].is_error()); // empty sensitive is warning
    }
}
