use std::path::{Path, PathBuf};

use crate::output::CliError;

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

/// Result of a save_result operation.
#[derive(Debug)]
#[allow(dead_code)]
pub struct SaveOutcome {
    /// Path where the result was saved, if successful.
    pub path: Option<PathBuf>,
    /// Warning message if config-dir auto-save failed (non-fatal).
    pub warning: Option<String>,
}

pub fn save_result(
    request_id: &str,
    resp: &serde_json::Value,
    output: Option<&Path>,
    config_dir: Option<&Path>,
) -> Result<SaveOutcome, CliError> {
    let (path, explicit) = match output {
        Some(p) => (p.to_path_buf(), true),
        None => {
            let dir = match config_dir {
                Some(d) => d,
                None => {
                    return Ok(SaveOutcome {
                        path: None,
                        warning: None,
                    });
                }
            };
            if let Err(e) = std::fs::create_dir_all(dir) {
                return Ok(SaveOutcome {
                    path: None,
                    warning: Some(format!(
                        "failed to create results dir {}: {e}",
                        dir.display()
                    )),
                });
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
        Ok(()) => Ok(SaveOutcome {
            path: Some(path),
            warning: None,
        }),
        Err(e) => {
            if explicit {
                Err(CliError::Internal(format!(
                    "failed to save result to {}: {e}",
                    path.display()
                )))
            } else {
                // Non-explicit save failure is non-fatal — return warning
                Ok(SaveOutcome {
                    path: None,
                    warning: Some(format!(
                        "failed to auto-save result to {}: {e}",
                        path.display()
                    )),
                })
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
    fn no_output_no_config_returns_none() {
        let result = save_result("req_123", &sample_result(), None, None).unwrap();
        assert!(result.path.is_none());
        assert!(result.warning.is_none());
    }

    #[test]
    fn config_dir_saves_to_dir() {
        let dir = tempfile::tempdir().unwrap();
        let result = save_result("req_456", &sample_result(), None, Some(dir.path())).unwrap();
        assert!(result.path.is_some());
        assert!(result.warning.is_none());
        let path = result.path.unwrap();
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
        assert!(result.path.is_some());
        assert_eq!(result.path.unwrap(), output_path);
        assert!(output_path.exists());
        // config_dir should NOT have a file
        assert!(!config_dir.path().join("req_789.json").exists());
    }

    #[test]
    fn output_without_config_dir_still_saves() {
        let output_dir = tempfile::tempdir().unwrap();
        let output_path = output_dir.path().join("explicit.json");

        let result = save_result("req_abc", &sample_result(), Some(&output_path), None).unwrap();
        assert!(result.path.is_some());
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
