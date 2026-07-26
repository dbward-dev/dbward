//! Agent configuration checks for doctor command.
//!
//! Uses `AgentConfig::diagnose_static()` for static validation.
//! Runtime preflight checks (server connectivity, token validation) are in `validate --preflight`.

use super::*;
use dbward_config::validation::ValidationSeverity;

/// Run agent configuration diagnostics.
///
/// This function is now sync since it only performs static validation.
/// Runtime preflight checks (server, token) have been moved to `validate --preflight`.
pub(super) fn run_agent_mode(ctx: &mut DoctorContext, path: &std::path::Path) {
    if !ctx.json_output {
        eprintln!("dbward doctor — Agent configuration\n");
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

    // Run diagnose_static() to collect all issues
    let result =
        dbward_config::AgentConfig::diagnose_static(&raw_content, &path.display().to_string());

    // Convert ValidationIssues to CheckResults
    for issue in &result.issues {
        let status = match issue.severity {
            ValidationSeverity::Error => Status::Fail,
            ValidationSeverity::Warning => Status::Warn,
        };

        ctx.record(CheckResult {
            id: issue.id,
            status,
            message: issue.message.clone(),
            hint: issue.hint.clone(),
            details: vec![],
        });
    }

    // Record overall parse status
    if result.is_parseable() {
        if !result.has_errors() {
            ctx.record(CheckResult {
                id: "config_valid",
                status: Status::Pass,
                message: format!("{}: configuration valid", path.display()),
                hint: None,
                details: vec![],
            });
        }
    }
    // Parse failure is already reported via issues
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn diagnose(toml: &str) -> dbward_config::AgentDiagnosticsResult {
        dbward_config::AgentConfig::diagnose_static(toml, "test")
    }

    #[test]
    fn valid_config_no_errors() {
        let toml = r#"
[server]
url = "http://localhost:8080"
agent_token = "tok"

[databases.db.dev]
url = "postgres://localhost/x"
"#;
        let result = diagnose(toml);
        assert!(result.is_parseable());
        assert!(!result.has_errors());
    }

    #[test]
    fn invalid_server_url_scheme() {
        let toml = r#"
[server]
url = "localhost:8080"
agent_token = "tok"

[databases.db.dev]
url = "postgres://localhost/x"
"#;
        let result = diagnose(toml);
        assert!(result.is_parseable());
        assert!(result.has_errors());
        assert!(result.issues.iter().any(|i| i.id == "server_url_scheme"));
    }

    #[test]
    fn invalid_db_url_scheme() {
        let toml = r#"
[server]
url = "http://localhost:8080"
agent_token = "tok"

[databases.db.dev]
url = "invalid://localhost/x"
"#;
        let result = diagnose(toml);
        assert!(result.is_parseable());
        assert!(result.has_errors());
        assert!(result.issues.iter().any(|i| i.id == "db_url_scheme"));
    }
}
