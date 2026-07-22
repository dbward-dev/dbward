//! Self-update: download and replace the dbward binary from GitHub Releases.
//!
//! Default behavior: target the connected server's version for compatibility.
//! Use `--latest` to explicitly update to the newest GitHub release.

use std::path::Path;

use serde::Serialize;

use crate::output::CliError;
use crate::output::{CliResponse, OutputMode, RenderPlan, StderrLine, StdoutRender};

const REPO_OWNER: &str = "dbward-dev";
const REPO_NAME: &str = "dbward";

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct UpdateOutput {
    pub from_version: String,
    pub to_version: String,
    pub already_at_target: bool,
    pub server_version: Option<String>,
    pub server_reachable: bool,
    pub target_source: TargetSource,
}

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TargetSource {
    Server,
    Latest,
    LatestFallback,
}

// ---------------------------------------------------------------------------
// Version helpers
// ---------------------------------------------------------------------------

fn parse_semver(s: &str) -> (u64, u64, u64) {
    let parts: Vec<u64> = s
        .split('.')
        .take(3)
        .map(|p| p.parse().unwrap_or(0))
        .collect();
    (
        parts.first().copied().unwrap_or(0),
        parts.get(1).copied().unwrap_or(0),
        parts.get(2).copied().unwrap_or(0),
    )
}

fn semver_gt(a: &str, b: &str) -> bool {
    parse_semver(a) > parse_semver(b)
}

fn same_minor(a: &str, b: &str) -> bool {
    let (a0, a1, _) = parse_semver(a);
    let (b0, b1, _) = parse_semver(b);
    a0 == b0 && a1 == b1
}

// ---------------------------------------------------------------------------
// Command implementation
// ---------------------------------------------------------------------------

pub async fn run_self_update(
    mode: OutputMode,
    yes: bool,
    latest: bool,
    config_path: Option<&Path>,
    merge_global: bool,
) -> Result<CliResponse<UpdateOutput>, CliError> {
    let current = env!("CARGO_PKG_VERSION").to_string();

    // Step 1: Determine target version
    let server_version = fetch_server_version(config_path, merge_global).await;
    let server_reachable = server_version.is_some();

    let (target, target_source) =
        determine_target(&current, server_version.as_deref(), latest).await?;

    // Step 2: Already at target → early return
    if target == current {
        let mut stderr = vec![StderrLine::Status(format!("Current version: v{current}"))];
        if server_reachable {
            stderr.push(StderrLine::Status(format!(
                "Already matches server (v{}).",
                server_version.as_deref().unwrap_or(&current)
            )));
        } else {
            stderr.push(StderrLine::Status("Already up to date.".into()));
        }
        // Hint about --latest if GitHub has a newer version
        if !latest
            && let Ok(gh_latest) = check_latest().await
            && semver_gt(&gh_latest, &current)
        {
            stderr.push(StderrLine::Hint(format!(
                "A newer version (v{gh_latest}) is available. Use --latest to update beyond server."
            )));
        }

        let output = UpdateOutput {
            from_version: current.clone(),
            to_version: target,
            already_at_target: true,
            server_version,
            server_reachable,
            target_source,
        };
        let render = RenderPlan {
            stdout: StdoutRender::None,
            stderr,
        };
        return Ok(CliResponse::ok(output, render));
    }

    // Step 3: Pre-prompt information (human mode only)
    if mode == OutputMode::Human {
        eprintln!("Current: v{current}");
        if let Some(ref sv) = server_version {
            eprintln!("Server:  v{sv}");
        } else {
            eprintln!("Server:  unreachable (using latest)");
        }
        let source_label = match target_source {
            TargetSource::Server => "matches server",
            TargetSource::Latest => "latest",
            TargetSource::LatestFallback => "latest, server unreachable",
        };
        eprintln!("Target:  v{target} ({source_label})");

        // Warn on minor version mismatch when using --latest
        if target_source == TargetSource::Latest
            && let Some(ref sv) = server_version
            && !same_minor(&target, sv)
        {
            eprintln!(
                "⚠ CLI will be ahead of server (v{sv}). Update server first per upgrade order."
            );
        }
        eprintln!();
    }

    // Step 4: Confirmation gate
    crate::output::confirm_or_reject(mode, yes)?;

    // Step 5: Download and install
    download_and_install(&current, &target).await?;

    // Step 6: Return result
    let output = UpdateOutput {
        from_version: current.clone(),
        to_version: target.clone(),
        already_at_target: false,
        server_version,
        server_reachable,
        target_source,
    };
    let render = RenderPlan {
        stdout: StdoutRender::None,
        stderr: vec![
            StderrLine::Status("✓ SHA256 verified".into()),
            StderrLine::Status(format!("✓ Updated to v{target}")),
        ],
    };
    Ok(CliResponse::ok(output, render))
}

// ---------------------------------------------------------------------------
// Target determination
// ---------------------------------------------------------------------------

async fn determine_target(
    current: &str,
    server_version: Option<&str>,
    use_latest: bool,
) -> Result<(String, TargetSource), CliError> {
    if use_latest {
        let latest = check_latest().await?;
        return Ok((latest, TargetSource::Latest));
    }

    match server_version {
        Some(sv) => {
            // Server reachable: target = server version (but never downgrade within same minor)
            if same_minor(sv, current) && semver_gt(current, sv) {
                // CLI is already ahead of server within same minor → no-op
                Ok((current.to_string(), TargetSource::Server))
            } else {
                Ok((sv.to_string(), TargetSource::Server))
            }
        }
        None => {
            // Server unreachable → fallback to GitHub latest
            let latest = check_latest().await?;
            Ok((latest, TargetSource::LatestFallback))
        }
    }
}

// ---------------------------------------------------------------------------
// Server version fetch (best-effort, self-contained)
// ---------------------------------------------------------------------------

async fn fetch_server_version(config_path: Option<&Path>, merge_global: bool) -> Option<String> {
    // If user explicitly specified --config, use exactly their merge_global setting.
    // If no explicit config, allow auto-detection with global merge.
    let use_merge = if config_path.is_some() {
        merge_global
    } else {
        true
    };
    let merged = crate::config::load_resolved(config_path, use_merge).ok()?;
    let url = format!("{}/health", merged.config.server.url.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .connect_timeout(std::time::Duration::from_secs(3))
        .build()
        .ok()?;
    let resp: serde_json::Value = client.get(&url).send().await.ok()?.json().await.ok()?;
    let version = resp["version"].as_str()?;
    // Strip leading 'v' if present (server should not include it, but be defensive)
    Some(version.strip_prefix('v').unwrap_or(version).to_string())
}

// ---------------------------------------------------------------------------
// GitHub latest version
// ---------------------------------------------------------------------------

async fn check_latest() -> Result<String, CliError> {
    let client = reqwest::Client::builder()
        .user_agent(format!("dbward/{}", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| CliError::Network(e.to_string()))?;

    let url = format!("https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/releases/latest");
    let resp: serde_json::Value = client
        .get(&url)
        .send()
        .await
        .map_err(|e| CliError::Network(format!("failed to check for updates: {e}")))?
        .error_for_status()
        .map_err(|e| CliError::Network(format!("GitHub API error: {e}")))?
        .json()
        .await
        .map_err(|e| CliError::Network(e.to_string()))?;

    let tag = resp["tag_name"]
        .as_str()
        .ok_or_else(|| CliError::Internal("could not determine latest version".into()))?;

    Ok(tag.strip_prefix('v').unwrap_or(tag).to_string())
}

// ---------------------------------------------------------------------------
// Download + install (extracted from old implementation)
// ---------------------------------------------------------------------------

async fn download_and_install(current: &str, target: &str) -> Result<(), CliError> {
    let arch_target = get_target();
    let asset_name = format!("dbward-v{target}-{arch_target}.tar.gz");
    let sha_name = format!("{asset_name}.sha256");

    let client = reqwest::Client::builder()
        .user_agent(format!("dbward/{current}"))
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| CliError::Network(e.to_string()))?;

    // Get release assets
    let release_url =
        format!("https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/releases/tags/v{target}");
    let release: serde_json::Value = client
        .get(&release_url)
        .send()
        .await
        .map_err(|e| CliError::Network(e.to_string()))?
        .json()
        .await
        .map_err(|e| CliError::Network(format!("failed to parse release response: {e}")))?;

    // Handle "release not found" (e.g. custom/self-hosted build)
    if release.get("message").and_then(|m| m.as_str()) == Some("Not Found") {
        return Err(CliError::Internal(format!(
            "Release v{target} not found on GitHub. \
             This may be a self-hosted build. Use --latest to update to the latest public release."
        )));
    }

    let assets = release["assets"]
        .as_array()
        .ok_or_else(|| CliError::Internal("no assets in release".into()))?;

    let asset_url = assets
        .iter()
        .find(|a| a["name"].as_str() == Some(&asset_name))
        .and_then(|a| a["browser_download_url"].as_str())
        .ok_or_else(|| CliError::Internal(format!("asset {asset_name} not found in release")))?;

    let sha_url = assets
        .iter()
        .find(|a| a["name"].as_str() == Some(&sha_name))
        .and_then(|a| a["browser_download_url"].as_str());

    // Download binary
    let binary_bytes = client
        .get(asset_url)
        .send()
        .await
        .map_err(|e| CliError::Network(e.to_string()))?
        .error_for_status()
        .map_err(|e| CliError::Network(format!("failed to download binary: {e}")))?
        .bytes()
        .await
        .map_err(|e| CliError::Network(e.to_string()))?;

    // Verify SHA256 (required)
    let sha_url = match sha_url {
        Some(url) => url,
        None => {
            return Err(CliError::Internal(format!(
                "SHA256 checksum file ({sha_name}) not found in release. Aborting."
            )));
        }
    };
    let expected_sha = client
        .get(sha_url)
        .send()
        .await
        .map_err(|e| CliError::Network(e.to_string()))?
        .error_for_status()
        .map_err(|e| CliError::Network(format!("failed to download checksum: {e}")))?
        .text()
        .await
        .map_err(|e| CliError::Network(e.to_string()))?;
    let expected_sha = expected_sha.split_whitespace().next().unwrap_or("").trim();

    use sha2::{Digest, Sha256};
    let actual_sha = format!("{:x}", Sha256::digest(&binary_bytes));

    if actual_sha != expected_sha {
        return Err(CliError::Internal(format!(
            "SHA256 mismatch: expected {expected_sha}, got {actual_sha}"
        )));
    }

    // Extract tar.gz with path traversal protection
    let tmp_dir = tempfile::tempdir().map_err(|e| CliError::Internal(e.to_string()))?;
    let tar_gz = flate2::read::GzDecoder::new(&binary_bytes[..]);
    let mut archive = tar::Archive::new(tar_gz);
    for entry in archive
        .entries()
        .map_err(|e| CliError::Internal(e.to_string()))?
    {
        let mut entry = entry.map_err(|e| CliError::Internal(e.to_string()))?;
        let path = entry
            .path()
            .map_err(|e| CliError::Internal(e.to_string()))?;
        if path
            .components()
            .any(|c| c == std::path::Component::ParentDir)
        {
            return Err(CliError::Internal(format!(
                "archive contains path traversal: {}",
                path.display()
            )));
        }
        entry
            .unpack_in(tmp_dir.path())
            .map_err(|e| CliError::Internal(format!("failed to extract: {e}")))?;
    }

    let extracted_binary = tmp_dir.path().join("dbward");
    if !extracted_binary.exists() {
        return Err(CliError::Internal(
            "extracted binary not found in archive".into(),
        ));
    }

    // Atomic replacement
    let current_exe = std::env::current_exe().map_err(|e| CliError::Internal(e.to_string()))?;
    let new_path = current_exe.with_extension("new");

    std::fs::copy(&extracted_binary, &new_path)
        .map_err(|e| CliError::Internal(format!("failed to write new binary: {e}")))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&new_path, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| CliError::Internal(format!("failed to set permissions: {e}")))?;
    }

    std::fs::rename(&new_path, &current_exe)
        .map_err(|e| CliError::Internal(format!("failed to replace binary: {e}")))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Platform target
// ---------------------------------------------------------------------------

fn get_target() -> &'static str {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        "aarch64-apple-darwin"
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        "x86_64-apple-darwin"
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        "x86_64-unknown-linux-gnu"
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        "aarch64-unknown-linux-gnu"
    }
    #[cfg(not(any(
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64"),
    )))]
    {
        "unknown"
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_semver() {
        assert_eq!(parse_semver("1.2.3"), (1, 2, 3));
        assert_eq!(parse_semver("0.2.0"), (0, 2, 0));
        assert_eq!(parse_semver("10.20.30"), (10, 20, 30));
        assert_eq!(parse_semver(""), (0, 0, 0));
        assert_eq!(parse_semver("1"), (1, 0, 0));
        assert_eq!(parse_semver("1.2"), (1, 2, 0));
    }

    #[test]
    fn test_semver_gt() {
        assert!(semver_gt("0.2.1", "0.2.0"));
        assert!(semver_gt("0.3.0", "0.2.9"));
        assert!(semver_gt("1.0.0", "0.99.99"));
        assert!(!semver_gt("0.2.0", "0.2.0"));
        assert!(!semver_gt("0.2.0", "0.2.1"));
    }

    #[test]
    fn test_same_minor() {
        assert!(same_minor("0.2.0", "0.2.1"));
        assert!(same_minor("0.2.5", "0.2.0"));
        assert!(same_minor("1.3.0", "1.3.9"));
        assert!(!same_minor("0.2.0", "0.3.0"));
        assert!(!same_minor("1.0.0", "2.0.0"));
    }

    #[test]
    fn test_determine_target_server_ahead() {
        // Server v0.2.1, CLI v0.2.0 → target = server
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (target, source) = rt
            .block_on(determine_target("0.2.0", Some("0.2.1"), false))
            .unwrap();
        assert_eq!(target, "0.2.1");
        assert_eq!(source, TargetSource::Server);
    }

    #[test]
    fn test_determine_target_cli_ahead_same_minor() {
        // CLI v0.2.2, Server v0.2.1 → no-op (returns current)
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (target, source) = rt
            .block_on(determine_target("0.2.2", Some("0.2.1"), false))
            .unwrap();
        assert_eq!(target, "0.2.2");
        assert_eq!(source, TargetSource::Server);
    }

    #[test]
    fn test_determine_target_different_minor() {
        // CLI v0.2.0, Server v0.3.0 → target = server (minor upgrade)
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (target, source) = rt
            .block_on(determine_target("0.2.0", Some("0.3.0"), false))
            .unwrap();
        assert_eq!(target, "0.3.0");
        assert_eq!(source, TargetSource::Server);
    }

    #[test]
    fn test_update_output_serialization() {
        let output = UpdateOutput {
            from_version: "0.2.0".into(),
            to_version: "0.2.1".into(),
            already_at_target: false,
            server_version: Some("0.2.1".into()),
            server_reachable: true,
            target_source: TargetSource::Server,
        };
        let json = serde_json::to_value(&output).unwrap();
        assert_eq!(json["target_source"], "server");
        assert_eq!(json["already_at_target"], false);
        assert_eq!(json["server_reachable"], true);
    }

    #[test]
    fn test_update_output_latest_fallback() {
        let output = UpdateOutput {
            from_version: "0.2.0".into(),
            to_version: "0.2.2".into(),
            already_at_target: false,
            server_version: None,
            server_reachable: false,
            target_source: TargetSource::LatestFallback,
        };
        let json = serde_json::to_value(&output).unwrap();
        assert_eq!(json["target_source"], "latest_fallback");
        assert_eq!(json["server_version"], serde_json::Value::Null);
    }

    #[test]
    fn test_determine_target_same_version() {
        // CLI v0.2.1, Server v0.2.1 → no-op (target = current)
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (target, source) = rt
            .block_on(determine_target("0.2.1", Some("0.2.1"), false))
            .unwrap();
        assert_eq!(target, "0.2.1");
        assert_eq!(source, TargetSource::Server);
    }

    #[test]
    fn test_determine_target_cli_ahead_different_minor() {
        // CLI v0.3.0, Server v0.2.5 → target = server (cross-minor, not no-op)
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (target, source) = rt
            .block_on(determine_target("0.3.0", Some("0.2.5"), false))
            .unwrap();
        // Different minor: CLI is ahead but different minor → target = server
        // (This is intentional: server dictates version regardless of direction when minor differs)
        assert_eq!(target, "0.2.5");
        assert_eq!(source, TargetSource::Server);
    }

    #[test]
    fn test_parse_semver_with_prefix() {
        // parse_semver should handle clean versions; v-prefix is stripped by caller
        assert_eq!(parse_semver("0.2.1"), (0, 2, 1));
        // If somehow a v gets through: "v0" parses as 0 (unwrap_or(0))
        assert_eq!(parse_semver("v0.2.1"), (0, 2, 1));
    }

    #[test]
    fn test_same_minor_edge_cases() {
        assert!(same_minor("0.0.0", "0.0.1"));
        assert!(!same_minor("0.1.0", "1.1.0"));
        assert!(same_minor("1.0.0", "1.0.99"));
    }
}
