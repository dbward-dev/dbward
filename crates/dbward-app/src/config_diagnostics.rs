//! Unified config diagnostics API for dbward-server and dbward-cli.
//!
//! This module combines config-level validation from `dbward-config` with
//! domain-level validation from `dbward-domain` into a single API.
//!
//! Note: This is for "diagnostics" (collect all issues). The fail-fast
//! validation in `sync_config/convert.rs` is a separate concern and is not
//! replaced by this module.

use dbward_config::{
    ApproverSelectorType, DiagnosticsResult, ServerConfig, WorkflowStepDef, WorkflowStepModeDef,
    validation::ValidationIssue,
};
use dbward_domain::policies::workflow::{ApproverGroup, WorkflowStep, WorkflowStepMode};
use dbward_domain::services::workflow_validator;
use dbward_domain::values::Selector;

/// Full diagnostics for server configuration including domain-level checks.
///
/// This combines:
/// 1. `ServerConfig::diagnose_static()` - config-level validation (env vars, TOML parse, semantic checks)
/// 2. `workflow_validator` checks - domain-level step validation (min=0, cross-step deadlock, etc.)
///
/// Use this API instead of calling `diagnose_static()` directly to ensure all
/// validation layers are applied.
///
/// Note: This does NOT replace the fail-fast validation in `sync_config/convert.rs`.
/// That validation runs at server startup and is a separate concern.
pub fn diagnose_server_config(raw_content: &str, source: &str) -> DiagnosticsResult {
    let mut result = ServerConfig::diagnose_static(raw_content, source);

    if let Some(ref cfg) = result.config {
        let step_issues = validate_workflow_steps_domain(cfg);
        result.issues.extend(step_issues);
    }

    result
}

/// Domain-level workflow step validation.
///
/// Checks that aren't in `ServerConfig::diagnose_static()` because they require
/// domain types from `dbward-domain`:
/// - min=0 approvers (must be >= 1)
/// - Empty approvers list
/// - Cross-step deadlocks (same user in multiple steps with allow_same_approver_across_steps=false)
/// - Requester as approver (warning)
fn validate_workflow_steps_domain(cfg: &ServerConfig) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();

    for (wf_idx, wf) in cfg.workflows.iter().enumerate() {
        if wf.steps.is_empty() {
            continue; // auto-approve workflow, nothing to validate
        }

        // Convert WorkflowStepDef → WorkflowStep (domain type)
        // Filter out unknown step types (they are reported separately as warnings by diagnose_static)
        let steps: Vec<WorkflowStep> = wf
            .steps
            .iter()
            .filter(|step| step.step_type.is_supported())
            .map(convert_step_def_to_domain)
            .collect();

        let validator_issues =
            workflow_validator::validate_steps(&steps, wf.allow_same_approver_across_steps);

        for issue in validator_issues {
            let vi = match issue.severity {
                workflow_validator::Severity::Error => ValidationIssue::error(
                    "workflow_step_validity",
                    format!("workflows[{wf_idx}]: {}", issue.message),
                ),
                workflow_validator::Severity::Warning => ValidationIssue::warning(
                    "workflow_step_validity",
                    format!("workflows[{wf_idx}]: {}", issue.message),
                ),
            };

            issues.push(vi);
        }
    }

    issues
}

/// Convert a config-level WorkflowStepDef to a domain-level WorkflowStep.
fn convert_step_def_to_domain(step: &WorkflowStepDef) -> WorkflowStep {
    let mode = match step.mode {
        WorkflowStepModeDef::All => WorkflowStepMode::All,
        WorkflowStepModeDef::Any => WorkflowStepMode::Any,
    };

    let approvers: Vec<ApproverGroup> = step
        .approvers
        .iter()
        .map(|a| {
            let selector = match a.selector_type {
                ApproverSelectorType::Role => Selector::Role(a.value.clone()),
                ApproverSelectorType::Group => Selector::Group(a.value.clone()),
                ApproverSelectorType::User => Selector::User(a.value.clone()),
            };
            ApproverGroup {
                selector,
                min: a.min.unwrap_or(1),
            }
        })
        .collect();

    WorkflowStep { approvers, mode }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbward_config::validation::ValidationSeverity;

    fn make_config(toml: &str) -> String {
        format!(
            r#"state_dir = "/tmp/test"

[[databases]]
name = "app"
environments = ["production"]

{toml}"#
        )
    }

    #[test]
    fn diagnose_catches_domain_level_min_zero_error() {
        // This config passes TOML parsing but fails domain validation
        // because min=0 is not allowed
        let toml = make_config(
            r#"
[[workflows]]
database = "app"
environment = "production"

[[workflows.steps]]
type = "approval"
mode = "all"

[[workflows.steps.approvers]]
role = "dba"
min = 0
"#,
        );

        let result = diagnose_server_config(&toml, "test");

        // Config should parse successfully
        assert!(result.config.is_some(), "Config should parse");

        // But there should be a domain-level error
        let errors: Vec<_> = result
            .issues
            .iter()
            .filter(|i| i.severity == ValidationSeverity::Error)
            .collect();

        assert!(
            errors.iter().any(|i| i.id == "workflow_step_validity"
                && i.message.contains("min=0")),
            "Should have workflow_step_validity error for min=0. Errors: {:?}",
            errors
        );
    }

    #[test]
    fn diagnose_catches_cross_step_deadlock() {
        // Same user in multiple steps with allow_same_approver_across_steps=false
        let toml = make_config(
            r#"
[[workflows]]
database = "app"
environment = "production"
allow_same_approver_across_steps = false

[[workflows.steps]]
type = "approval"
mode = "all"

[[workflows.steps.approvers]]
user = "alice"

[[workflows.steps]]
type = "approval"
mode = "all"

[[workflows.steps.approvers]]
user = "alice"
"#,
        );

        let result = diagnose_server_config(&toml, "test");

        assert!(result.config.is_some(), "Config should parse");

        let errors: Vec<_> = result
            .issues
            .iter()
            .filter(|i| i.severity == ValidationSeverity::Error)
            .collect();

        assert!(
            errors.iter().any(|i| i.id == "workflow_step_validity"
                && i.message.contains("alice")
                && i.message.contains("deadlock")),
            "Should have deadlock error. Errors: {:?}",
            errors
        );
    }

    #[test]
    fn diagnose_valid_config_has_no_errors() {
        let toml = make_config(
            r#"
[[workflows]]
database = "app"
environment = "production"

[[workflows.steps]]
type = "approval"
mode = "all"

[[workflows.steps.approvers]]
role = "dba"
min = 1
"#,
        );

        let result = diagnose_server_config(&toml, "test");

        assert!(result.config.is_some(), "Config should parse");
        assert!(
            !result.has_errors(),
            "Should have no errors. Issues: {:?}",
            result.issues
        );
    }

    #[test]
    fn diagnose_includes_config_level_issues() {
        // Invalid TOML that fails parsing
        let result = diagnose_server_config("invalid toml [[[", "test");

        assert!(result.config.is_none(), "Config should fail to parse");
        assert!(result.has_errors(), "Should have parse error");
        assert!(
            result
                .issues
                .iter()
                .any(|i| i.id == "toml_parse"),
            "Should have toml_parse error"
        );
    }
}
