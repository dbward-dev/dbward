use std::path::{Path, PathBuf};

use crate::error::CliError;

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
) -> Option<PathBuf> {
    let (path, explicit) = match output {
        Some(p) => (p.to_path_buf(), true),
        None => {
            let dir = config_dir?;
            if let Err(e) = std::fs::create_dir_all(dir) {
                eprintln!("Warning: cannot create results dir {}: {e}", dir.display());
                return None;
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
        eprintln!("Error: --output path is a directory: {}", path.display());
        std::process::exit(1);
    }
    let content = serde_json::to_string_pretty(resp).unwrap_or_default();
    match write_secure(&path, content.as_bytes()) {
        Ok(()) => {
            eprintln!("Result saved to {}", path.display());
            Some(path)
        }
        Err(e) => {
            if explicit {
                eprintln!("Error: failed to save result to {}: {e}", path.display());
                std::process::exit(1);
            }
            eprintln!("Warning: failed to save result to {}: {e}", path.display());
            None
        }
    }
}

pub fn load_result(
    request_id: &str,
    config_dir: Option<&Path>,
) -> Result<serde_json::Value, CliError> {
    let dir = config_dir.ok_or_else(|| {
        CliError::Server(format!(
            "No results dir configured. Cannot load local result for {request_id}. Try: dbward result get {request_id}"
        ))
    })?;
    let path = dir.join(format!("{request_id}.json"));
    let content = std::fs::read_to_string(&path).map_err(|_| {
        CliError::Server(format!(
            "No saved result for {request_id}. Path: {}",
            path.display()
        ))
    })?;
    serde_json::from_str(&content)
        .map_err(|e| CliError::Server(format!("Failed to parse saved result: {e}")))
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
        let result = save_result("req_123", &sample_result(), None, None);
        assert!(result.is_none());
    }

    #[test]
    fn config_dir_saves_to_dir() {
        let dir = tempfile::tempdir().unwrap();
        let result = save_result("req_456", &sample_result(), None, Some(dir.path()));
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
        );
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

        let result = save_result("req_abc", &sample_result(), Some(&output_path), None);
        assert!(result.is_some());
        assert!(output_path.exists());
    }

    #[test]
    fn load_result_from_config_dir() {
        let dir = tempfile::tempdir().unwrap();
        // Write a file
        save_result("req_load", &sample_result(), None, Some(dir.path()));
        // Load it back
        let loaded = load_result("req_load", Some(dir.path())).unwrap();
        assert_eq!(loaded["success"], true);
    }

    #[test]
    fn load_result_no_dir_returns_error() {
        let result = load_result("req_missing", None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No results dir"));
    }

    #[test]
    fn load_result_file_not_found_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let result = load_result("nonexistent", Some(dir.path()));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No saved result"));
    }
}
