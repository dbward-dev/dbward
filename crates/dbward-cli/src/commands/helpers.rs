use std::path::{Path, PathBuf};

use crate::output::CliError;

#[allow(dead_code)]
pub struct SubmissionSummary<'a> {
    pub operation: &'a str,
    pub database: &'a str,
    pub environment: &'a str,
    pub detail: &'a str,
    pub emergency: bool,
}

/// Display submission summary and prompt for confirmation.
/// Returns Ok(()) if confirmed, Err if rejected or non-interactive without skip.
#[allow(dead_code)]
pub fn confirm_submission(summary: &SubmissionSummary, skip: bool) -> Result<(), CliError> {
    if skip {
        if std::env::var_os("DBWARD_YES").is_some() {
            eprintln!("note: confirmation skipped (DBWARD_YES)");
        }
        return Ok(());
    }

    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return Err(CliError::Internal(
            "interactive confirmation required but stdin is not a terminal. Use --yes to skip."
                .into(),
        ));
    }

    eprintln!();
    eprintln!("  Operation:   {}", summary.operation);
    eprintln!("  Database:    {}", summary.database);
    eprintln!("  Environment: {}", summary.environment);
    if summary.emergency {
        eprintln!("  Mode:        \u{26a0} EMERGENCY (bypass approval)");
    }
    let detail_display = truncate_detail(summary.detail, 200);
    if !detail_display.is_empty() {
        eprintln!("  Detail:      {}", detail_display);
    }
    eprintln!();
    eprint!("Submit this request? [y/N] ");

    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .map_err(|e| CliError::Internal(format!("failed to read input: {e}")))?;

    match input.trim().to_lowercase().as_str() {
        "y" | "yes" => Ok(()),
        _ => Err(CliError::Internal("aborted by user".into())),
    }
}

fn truncate_detail(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let boundary = s
        .char_indices()
        .take_while(|(i, _)| *i <= max)
        .last()
        .map(|(i, _)| i)
        .unwrap_or(0);
    format!("{}…", &s[..boundary])
}

pub fn build_request_metadata(
    ticket: Option<&str>,
    repo: Option<&str>,
) -> Option<serde_json::Value> {
    let mut metadata = serde_json::Map::new();
    if let Some(ticket) = ticket.filter(|v| !v.is_empty()) {
        metadata.insert(
            "ticket".to_string(),
            serde_json::Value::String(ticket.to_string()),
        );
    }
    if let Some(repo) = repo.filter(|v| !v.is_empty()) {
        metadata.insert(
            "repo".to_string(),
            serde_json::Value::String(repo.to_string()),
        );
    }
    if metadata.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(metadata))
    }
}

pub fn save_result(
    request_id: &str,
    resp: &serde_json::Value,
    output: Option<&Path>,
    config_dir: Option<&Path>,
) -> Result<Option<PathBuf>, CliError> {
    let (path, explicit) = match output {
        Some(p) => (p.to_path_buf(), true),
        None => {
            let dir = match config_dir {
                Some(d) => d,
                None => return Ok(None),
            };
            if let Err(e) = std::fs::create_dir_all(dir) {
                return Err(CliError::Internal(format!(
                    "cannot create results dir {}: {e}",
                    dir.display()
                )));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
            }
            (dir.join(format!("{request_id}.json")), false)
        }
    };
    if explicit && path.is_dir() {
        return Err(CliError::Internal(format!(
            "--output path is a directory: {}",
            path.display()
        )));
    }
    let content = serde_json::to_string_pretty(resp).unwrap_or_default();
    match write_secure(&path, content.as_bytes()) {
        Ok(()) => Ok(Some(path)),
        Err(e) => {
            if explicit {
                Err(CliError::Internal(format!(
                    "failed to save result to {}: {e}",
                    path.display()
                )))
            } else {
                // Non-explicit save failure is non-fatal
                Ok(None)
            }
        }
    }
}

#[cfg(unix)]
fn write_secure(path: &Path, content: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?
        .write_all(content)
}

#[cfg(not(unix))]
fn write_secure(path: &Path, content: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, content)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_result() -> serde_json::Value {
        serde_json::json!({"success": true, "result": {"rows": []}})
    }

    #[test]
    fn confirm_submission_skip_true_returns_ok() {
        let summary = SubmissionSummary {
            operation: "execute_query",
            database: "app",
            environment: "production",
            detail: "SELECT 1",
            emergency: false,
        };
        assert!(confirm_submission(&summary, true).is_ok());
    }

    #[test]
    fn confirm_submission_non_tty_without_skip_returns_error() {
        // CI environments typically don't have a tty on stdin
        if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            // Skip in interactive terminals
            return;
        }
        let summary = SubmissionSummary {
            operation: "execute_query",
            database: "app",
            environment: "production",
            detail: "DELETE FROM users",
            emergency: true,
        };
        let result = confirm_submission(&summary, false);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("not a terminal"));
    }

    #[test]
    fn truncate_detail_short_string_unchanged() {
        assert_eq!(truncate_detail("hello", 200), "hello");
    }

    #[test]
    fn truncate_detail_long_string_truncated() {
        let long = "a".repeat(300);
        let result = truncate_detail(&long, 200);
        assert!(result.len() <= 204); // 200 + "…" (3 bytes)
        assert!(result.ends_with('…'));
    }

    #[test]
    fn truncate_detail_multibyte_boundary_safe() {
        // Japanese chars are 3 bytes each
        let jp = "あ".repeat(100); // 300 bytes
        let result = truncate_detail(&jp, 200);
        // Must be valid UTF-8 and end with …
        assert!(result.ends_with('…'));
        // The truncated part should be valid (no panics from mid-char slicing)
        assert!(result.len() <= 203);
    }

    #[test]
    fn no_output_no_config_returns_none() {
        let result = save_result("req_123", &sample_result(), None, None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn config_dir_saves_to_dir() {
        let dir = tempfile::tempdir().unwrap();
        let result = save_result("req_456", &sample_result(), None, Some(dir.path())).unwrap();
        assert!(result.is_some());
        let path = result.unwrap();
        assert_eq!(path, dir.path().join("req_456.json"));
        assert!(path.exists());
        let content: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(content["success"], true);
    }

    #[test]
    fn output_overrides_config_dir() {
        let config_dir = tempfile::tempdir().unwrap();
        let output_dir = tempfile::tempdir().unwrap();
        let output_path = output_dir.path().join("my-result.json");

        let result = save_result(
            "req_789",
            &sample_result(),
            Some(&output_path),
            Some(config_dir.path()),
        )
        .unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), output_path);
        assert!(output_path.exists());
        // config_dir should NOT have a file
        assert!(!config_dir.path().join("req_789.json").exists());
    }

    #[test]
    fn output_without_config_dir_still_saves() {
        let output_dir = tempfile::tempdir().unwrap();
        let output_path = output_dir.path().join("explicit.json");

        let result = save_result("req_abc", &sample_result(), Some(&output_path), None).unwrap();
        assert!(result.is_some());
        assert!(output_path.exists());
    }

    #[test]
    fn output_is_directory_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let result = save_result("req_dir", &sample_result(), Some(dir.path()), None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("directory"));
    }
}
