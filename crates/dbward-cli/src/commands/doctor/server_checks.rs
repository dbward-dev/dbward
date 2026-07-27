//! Server configuration checks for doctor command.
//!
//! Uses `diagnose_server_config()` from dbward-app for full validation
//! (config-level + domain-level).
//! Runtime preflight checks (Slack, OIDC connectivity) are in `validate --preflight`.

use super::*;
use dbward_config::validation::{IssueContext, ValidationSeverity};

/// Run server configuration diagnostics.
///
/// This function is now sync since it only performs static validation.
/// Runtime preflight checks (Slack, OIDC) have been moved to `validate --preflight`.
pub(super) fn run_server_mode(ctx: &mut DoctorContext, path: &std::path::Path) {
    use dbward_app::config_diagnostics::diagnose_server_config;

    if !ctx.json_output {
        eprintln!("dbward doctor — Server configuration\n");
    }

    // Read file content
    let raw_content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            ctx.record(CheckResult {
                id: "file_read",
                status: Status::Fail,
                message: format!("failed to read {}: {e}", path.display()),
                hint: None,
                details: vec![],
            });
            return;
        }
    };

    // Run full diagnostics (config-level + domain-level)
    let result = diagnose_server_config(&raw_content, &path.display().to_string());

    // Convert ValidationIssues to CheckResults
    convert_issues_to_results(ctx, &result.issues);

    // Emit workflow_step_validity pass if no such issues were recorded and config has steps
    if let Some(ref cfg) = result.config {
        let has_step_issues = ctx.results.iter().any(|r| r.id == "workflow_step_validity");
        let non_auto_workflows = cfg.workflows.iter().filter(|w| !w.steps.is_empty()).count();
        if !has_step_issues && non_auto_workflows > 0 {
            ctx.record(CheckResult {
                id: "workflow_step_validity",
                status: Status::Pass,
                message: format!("{non_auto_workflows} workflows with steps, all valid"),
                hint: None,
                details: vec![],
            });
        }
    }

    // Record overall parse status
    if result.is_parseable() && !result.has_errors() {
        ctx.record(CheckResult {
            id: "config_valid",
            status: Status::Pass,
            message: format!("{}: configuration valid", path.display()),
            hint: None,
            details: vec![],
        });
    }
    // Note: Parse failures are already reported via issues
}

/// Convert ValidationIssues to DoctorContext CheckResults.
fn convert_issues_to_results(ctx: &mut DoctorContext, issues: &[dbward_config::ValidationIssue]) {
    for issue in issues {
        let status = match issue.severity {
            ValidationSeverity::Error => Status::Fail,
            ValidationSeverity::Warning => Status::Warn,
        };

        // Build details from context if available
        let details = match &issue.context {
            Some(IssueContext::WorkflowCoverage(entries)) => build_coverage_table(entries),
            Some(IssueContext::InvalidWorkflows(entries)) => entries
                .iter()
                .map(|e| {
                    format!(
                        "workflows[{}] ({}): {}",
                        e.workflow_index, e.workflow_name, e.reason
                    )
                })
                .collect(),
            Some(IssueContext::SqlReviewSafety(entries)) => entries
                .iter()
                .map(|e| format!("({}, {}): {}", e.database, e.environment, e.rule))
                .collect(),
            Some(IssueContext::EnvVarIssues(entries)) => entries
                .iter()
                .map(|e| format!("${{{}}}: {:?}", e.var_name, e.issue_type))
                .collect(),
            _ => vec![],
        };

        ctx.record(CheckResult {
            id: issue.id,
            status,
            message: issue.message.clone(),
            hint: issue.hint.clone(),
            details,
        });
    }
}

/// Build a coverage table from CoverageEntry items.
fn build_coverage_table(entries: &[dbward_config::validation::CoverageEntry]) -> Vec<String> {
    use crate::display::{display_width, sanitize_table_cell, truncate_table_cell};

    const COL_MAX: usize = 20;

    if entries.is_empty() {
        return vec![];
    }

    let headers = ["Database", "Environment", "Workflow", "Auto-Approve"];

    // Compute column widths
    let mut widths: [usize; 4] = [
        display_width(headers[0]),
        display_width(headers[1]),
        display_width(headers[2]),
        display_width(headers[3]),
    ];
    for r in entries {
        widths[0] = widths[0].max(display_width(&r.database)).min(COL_MAX);
        widths[1] = widths[1].max(display_width(&r.environment)).min(COL_MAX);
        let wf = r.workflow.as_deref().unwrap_or("✗ NO COVERAGE");
        widths[2] = widths[2].max(display_width(wf)).min(COL_MAX);
        let aa = r.auto_approve.as_deref().unwrap_or("—");
        widths[3] = widths[3].max(display_width(aa)).min(COL_MAX);
    }

    let mut lines = Vec::new();

    // Header
    lines.push(format!(
        "{}  {}  {}  {}",
        pad_col(headers[0], widths[0]),
        pad_col(headers[1], widths[1]),
        pad_col(headers[2], widths[2]),
        pad_col(headers[3], widths[3]),
    ));

    // Separator
    lines.push(format!(
        "{}  {}  {}  {}",
        "-".repeat(widths[0]),
        "-".repeat(widths[1]),
        "-".repeat(widths[2]),
        "-".repeat(widths[3]),
    ));

    // Data rows
    for r in entries {
        let wf = r.workflow.as_deref().unwrap_or("✗ NO COVERAGE");
        let aa = r.auto_approve.as_deref().unwrap_or("—");
        lines.push(format!(
            "{}  {}  {}  {}",
            pad_col(
                &truncate_table_cell(&sanitize_table_cell(&r.database), COL_MAX),
                widths[0]
            ),
            pad_col(
                &truncate_table_cell(&sanitize_table_cell(&r.environment), COL_MAX),
                widths[1]
            ),
            pad_col(&truncate_table_cell(wf, COL_MAX), widths[2]),
            pad_col(&truncate_table_cell(aa, COL_MAX), widths[3]),
        ));
    }

    lines
}

/// Pad a string to the given width (left-aligned).
fn pad_col(value: &str, width: usize) -> String {
    use crate::display::display_width;
    let padding = width.saturating_sub(display_width(value));
    format!("{value}{}", " ".repeat(padding))
}

/// Helper: check if a workflow pattern covers a specific (db, env) pair.
#[allow(dead_code)]
fn workflow_covers_scope(wf_db: &str, wf_env: &str, db: &str, env: &str) -> bool {
    let db_match = wf_db == "*" || wf_db == db;
    let env_match = wf_env == "*" || wf_env == env;
    db_match && env_match
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn server_cfg(toml: &str) -> dbward_config::ServerConfig {
        let full = format!("state_dir = \"/tmp/test\"\n{toml}");
        dbward_config::ServerConfig::from_str(&full, "test").unwrap()
    }

    fn diagnose(toml: &str) -> dbward_config::DiagnosticsResult {
        let full = format!("state_dir = \"/tmp/test\"\n{toml}");
        dbward_config::ServerConfig::diagnose_static(&full, "test")
    }

    #[test]
    fn workflow_refs_all_dead_is_error() {
        let result = diagnose(
            r#"
[[databases]]
name = "app"
environments = ["production"]

[[workflows]]
database = "nonexistent"
environment = "*"

[workflows.auto_approve]
mode = "always"
"#,
        );
        assert!(result.has_errors());
        assert!(
            result
                .issues
                .iter()
                .any(|i| i.id == "workflow_refs" && i.is_error())
        );
    }

    #[test]
    fn workflow_refs_partial_dead_is_warning() {
        let result = diagnose(
            r#"
[[databases]]
name = "app"
environments = ["production"]

[[workflows]]
database = "app"
environment = "*"

[workflows.auto_approve]
mode = "always"

[[workflows]]
database = "ghost"
environment = "*"

[workflows.auto_approve]
mode = "always"
"#,
        );
        // Partial dead should be warning, not error
        let warnings: Vec<_> = result.warnings().collect();
        assert!(warnings.iter().any(|w| w.id == "workflow_refs"));
    }

    #[test]
    fn workflow_refs_wildcard_passes() {
        let result = diagnose(
            r#"
[[databases]]
name = "app"
environments = ["production"]

[[workflows]]
database = "*"
environment = "*"

[workflows.auto_approve]
mode = "always"
"#,
        );
        // No workflow_refs issues expected
        assert!(!result.issues.iter().any(|i| i.id == "workflow_refs"));
    }

    #[test]
    fn workflow_step_validity_via_diagnose() {
        use dbward_app::config_diagnostics::diagnose_server_config;

        let toml = format!(
            r#"state_dir = "/tmp/test"

[[databases]]
name = "app"
environments = ["dev"]

[[workflows]]
database = "*"
environment = "*"

[[workflows.steps]]
type = "approval"
mode = "all"

[[workflows.steps.approvers]]
role = "approver"
min = 1
"#,
        );
        let result = diagnose_server_config(&toml, "test");
        // Should have no errors with valid step configuration
        assert!(result.config.is_some());
        assert!(
            !result.has_errors(),
            "Should have no errors. Issues: {:?}",
            result.issues
        );
    }

    #[test]
    fn workflow_step_validity_detects_min_zero() {
        use dbward_app::config_diagnostics::diagnose_server_config;
        use dbward_config::validation::ValidationSeverity;

        let toml = format!(
            r#"state_dir = "/tmp/test"

[[databases]]
name = "app"
environments = ["dev"]

[[workflows]]
database = "*"
environment = "*"

[[workflows.steps]]
type = "approval"
mode = "all"

[[workflows.steps.approvers]]
role = "approver"
min = 0
"#,
        );
        let result = diagnose_server_config(&toml, "test");
        // Should have an error for min=0
        assert!(result.config.is_some());
        let errors: Vec<_> = result
            .issues
            .iter()
            .filter(|i| i.severity == ValidationSeverity::Error)
            .collect();
        assert!(
            errors
                .iter()
                .any(|i| i.id == "workflow_step_validity" && i.message.contains("min=0")),
            "Should have workflow_step_validity error for min=0. Errors: {:?}",
            errors
        );
    }
}
