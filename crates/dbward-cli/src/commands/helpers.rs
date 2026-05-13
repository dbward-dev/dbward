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
    no_save: bool,
) -> Option<PathBuf> {
    if no_save {
        return None;
    }
    let path = match output {
        Some(p) => p.to_path_buf(),
        None => {
            let dir = dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".dbward")
                .join("results");
            if std::fs::create_dir_all(&dir).is_err() {
                return None;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
            }
            dir.join(format!("{request_id}.json"))
        }
    };
    let content = serde_json::to_string_pretty(resp).unwrap_or_default();
    if write_secure(&path, content.as_bytes()).is_ok() {
        eprintln!("Result saved to {}", path.display());
        Some(path)
    } else {
        eprintln!("Warning: failed to save result to {}", path.display());
        None
    }
}

pub fn load_result(request_id: &str) -> Result<serde_json::Value, CliError> {
    let path = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".dbward")
        .join("results")
        .join(format!("{request_id}.json"));
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
