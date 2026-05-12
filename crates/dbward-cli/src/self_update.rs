//! Self-update: download and replace the dbward binary from GitHub Releases.

use crate::error::CliError as Error;

const REPO_OWNER: &str = "metapox";
const REPO_NAME: &str = "dbward";

pub async fn run_self_update() -> Result<(), Error> {
    let current = env!("CARGO_PKG_VERSION");
    eprintln!("Current version: v{current}");

    let latest = check_latest().await?;
    if latest == current {
        eprintln!("Already up to date.");
        return Ok(());
    }
    eprintln!("Latest version:  v{latest}");
    eprintln!();

    let target = get_target();
    let asset_name = format!("dbward-v{latest}-{target}.tar.gz");
    let sha_name = format!("{asset_name}.sha256");

    eprintln!("Downloading {asset_name}...");

    let client = reqwest::Client::builder()
        .user_agent(format!("dbward/{current}"))
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| Error::Server(e.to_string()))?;

    // Get release assets
    let release_url =
        format!("https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/releases/tags/v{latest}");
    let release: serde_json::Value = client
        .get(&release_url)
        .send()
        .await
        .map_err(|e| Error::Server(e.to_string()))?
        .json()
        .await
        .map_err(|e| Error::Server(e.to_string()))?;

    let assets = release["assets"]
        .as_array()
        .ok_or_else(|| Error::Server("no assets in release".into()))?;

    let asset_url = assets
        .iter()
        .find(|a| a["name"].as_str() == Some(&asset_name))
        .and_then(|a| a["browser_download_url"].as_str())
        .ok_or_else(|| Error::Server(format!("asset {asset_name} not found in release")))?;

    let sha_url = assets
        .iter()
        .find(|a| a["name"].as_str() == Some(&sha_name))
        .and_then(|a| a["browser_download_url"].as_str());

    // Download binary
    let binary_bytes = client
        .get(asset_url)
        .send()
        .await
        .map_err(|e| Error::Server(e.to_string()))?
        .bytes()
        .await
        .map_err(|e| Error::Server(e.to_string()))?;

    // Verify SHA256 (required)
    let sha_url = match sha_url {
        Some(url) => url,
        None => {
            return Err(Error::Server(format!(
                "SHA256 checksum file ({sha_name}) not found in release. Aborting."
            )));
        }
    };
    let expected_sha = client
        .get(sha_url)
        .send()
        .await
        .map_err(|e| Error::Server(e.to_string()))?
        .text()
        .await
        .map_err(|e| Error::Server(e.to_string()))?;
    let expected_sha = expected_sha.split_whitespace().next().unwrap_or("").trim();

    use sha2::{Digest, Sha256};
    let actual_sha = format!("{:x}", Sha256::digest(&binary_bytes));

    if actual_sha != expected_sha {
        return Err(Error::Server(format!(
            "SHA256 mismatch: expected {expected_sha}, got {actual_sha}"
        )));
    }
    eprintln!("✓ SHA256 verified");

    // Extract tar.gz with path traversal protection
    let tmp_dir = tempfile::tempdir().map_err(|e| Error::Server(e.to_string()))?;
    let tar_gz = flate2::read::GzDecoder::new(&binary_bytes[..]);
    let mut archive = tar::Archive::new(tar_gz);
    for entry in archive
        .entries()
        .map_err(|e| Error::Server(e.to_string()))?
    {
        let mut entry = entry.map_err(|e| Error::Server(e.to_string()))?;
        let path = entry.path().map_err(|e| Error::Server(e.to_string()))?;
        // Reject path traversal
        if path
            .components()
            .any(|c| c == std::path::Component::ParentDir)
        {
            return Err(Error::Server(format!(
                "archive contains path traversal: {}",
                path.display()
            )));
        }
        entry
            .unpack_in(tmp_dir.path())
            .map_err(|e| Error::Server(format!("failed to extract: {e}")))?;
    }

    let extracted_binary = tmp_dir.path().join("dbward");
    if !extracted_binary.exists() {
        return Err(Error::Server(
            "extracted binary not found in archive".into(),
        ));
    }

    // Atomic replacement: write to .new, then rename over current
    let current_exe = std::env::current_exe().map_err(|e| Error::Server(e.to_string()))?;
    let new_path = current_exe.with_extension("new");

    std::fs::copy(&extracted_binary, &new_path)
        .map_err(|e| Error::Server(format!("failed to write new binary: {e}")))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&new_path, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| Error::Server(format!("failed to set permissions: {e}")))?;
    }

    std::fs::rename(&new_path, &current_exe)
        .map_err(|e| Error::Server(format!("failed to replace binary: {e}")))?;

    eprintln!("✓ Updated to v{latest}");
    eprintln!();
    eprintln!("Note: Restart server/agent to apply:");
    eprintln!("  docker compose pull && docker compose up -d");
    eprintln!("  # or");
    eprintln!("  systemctl restart dbward-server dbward-agent");

    Ok(())
}

async fn check_latest() -> Result<String, Error> {
    let client = reqwest::Client::builder()
        .user_agent(format!("dbward/{}", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| Error::Server(e.to_string()))?;

    let url = format!("https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/releases/latest");
    let resp: serde_json::Value = client
        .get(&url)
        .send()
        .await
        .map_err(|e| Error::Server(format!("failed to check for updates: {e}")))?
        .json()
        .await
        .map_err(|e| Error::Server(e.to_string()))?;

    let tag = resp["tag_name"]
        .as_str()
        .ok_or_else(|| Error::Server("could not determine latest version".into()))?;

    Ok(tag.strip_prefix('v').unwrap_or(tag).to_string())
}

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
