//! Background update checker — polls GitHub Releases for new versions.

use std::sync::Arc;
use tokio::sync::Mutex;

const GITHUB_RELEASES_URL: &str =
    "https://api.github.com/repos/metapox/dbward/releases/latest";
const CHECK_INTERVAL_SECS: u64 = 6 * 3600; // 6 hours

/// Spawn background task that periodically checks for updates.
/// Does nothing if `enabled` is false.
pub fn spawn_update_checker(enabled: bool, update_available: Arc<Mutex<Option<String>>>) {
    if !enabled {
        return;
    }
    tokio::spawn(async move {
        // Initial check after 10s delay (let server finish startup)
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        loop {
            if let Some(latest) = check_latest_version().await {
                let current = crate::VERSION;
                if is_newer(&latest, current) {
                    *update_available.lock().await = Some(latest);
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(CHECK_INTERVAL_SECS)).await;
        }
    });
}

async fn check_latest_version() -> Option<String> {
    let client = reqwest::Client::builder()
        .user_agent(format!("dbward/{}", crate::VERSION))
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .ok()?;

    let resp = client.get(GITHUB_RELEASES_URL).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body: serde_json::Value = resp.json().await.ok()?;
    let tag = body["tag_name"].as_str()?;
    // Strip leading 'v' if present
    Some(tag.strip_prefix('v').unwrap_or(tag).to_string())
}

/// Simple semver comparison: "0.1.2" > "0.1.0"
fn is_newer(latest: &str, current: &str) -> bool {
    let parse = |s: &str| -> (u32, u32, u32) {
        let parts: Vec<u32> = s.split('.').filter_map(|p| p.parse().ok()).collect();
        (
            parts.first().copied().unwrap_or(0),
            parts.get(1).copied().unwrap_or(0),
            parts.get(2).copied().unwrap_or(0),
        )
    };
    parse(latest) > parse(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_newer_works() {
        assert!(is_newer("0.1.2", "0.1.0"));
        assert!(is_newer("0.2.0", "0.1.9"));
        assert!(is_newer("1.0.0", "0.9.9"));
        assert!(!is_newer("0.1.0", "0.1.0"));
        assert!(!is_newer("0.1.0", "0.1.1"));
    }
}
