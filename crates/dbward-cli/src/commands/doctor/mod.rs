mod agent_checks;
mod cli_checks;
mod server_checks;

use std::path::PathBuf;
use std::time::Duration;

use crate::error::CliError;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Pass,
    Warn,
    Fail,
    Skip,
}

pub struct CheckResult {
    pub id: &'static str,
    pub status: Status,
    pub message: String,
    pub hint: Option<String>,
}

pub(super) struct DoctorContext {
    results: Vec<CheckResult>,
    json_output: bool,
    timeout: Duration,
}

impl DoctorContext {
    pub(super) fn record(&mut self, r: CheckResult) {
        self.results.push(r);
    }

    pub(super) fn last_failed(&self, id: &str) -> bool {
        self.results
            .iter()
            .rfind(|r| r.id == id)
            .is_some_and(|r| r.status == Status::Fail)
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub async fn run(
    config_path: Option<&std::path::Path>,
    agent_config: Option<PathBuf>,
    server_config: Option<PathBuf>,
    json_output: bool,
    timeout_secs: u64,
) -> Result<(), CliError> {
    if agent_config.is_some() && server_config.is_some() {
        eprintln!("error: --agent and --server are mutually exclusive");
        std::process::exit(2);
    }

    let mut ctx = DoctorContext {
        results: Vec::new(),
        json_output,
        timeout: Duration::from_secs(timeout_secs),
    };

    if let Some(path) = agent_config {
        agent_checks::run_agent_mode(&mut ctx, &path).await;
    } else if let Some(path) = server_config {
        server_checks::run_server_mode(&mut ctx, &path);
    } else {
        cli_checks::run_cli_mode(&mut ctx, config_path).await;
    }

    print_results(&ctx);
    let has_failure = ctx.results.iter().any(|r| r.status == Status::Fail);
    if has_failure {
        std::process::exit(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Strip credentials from a URL for safe display.
pub(super) fn redact_url(url: &str) -> String {
    if let Ok(mut parsed) = reqwest::Url::parse(url) {
        if !parsed.username().is_empty() || parsed.password().is_some() {
            let _ = parsed.set_username("");
            let _ = parsed.set_password(None);
        }
        parsed.to_string()
    } else {
        url.to_string()
    }
}

/// Simple semver comparison: returns true if a > b.
pub(super) fn semver_gt(a: &str, b: &str) -> bool {
    let parse = |s: &str| -> (u64, u64, u64) {
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
    };
    parse(a) > parse(b)
}

/// Scope matching using domain types (same as runtime's workflow_matcher).
pub(super) fn workflow_covers_scope(
    wf_db: &str,
    wf_env: &str,
    req_db: &str,
    req_env: &str,
) -> bool {
    use dbward_domain::values::{DatabaseName, Environment};
    let Ok(policy_db) = DatabaseName::new(wf_db) else {
        return false;
    };
    let Ok(policy_env) = Environment::new(wf_env) else {
        return false;
    };
    let Ok(request_db) = DatabaseName::new(req_db) else {
        return false;
    };
    let Ok(request_env) = Environment::new(req_env) else {
        return false;
    };
    (policy_db.is_wildcard() || policy_db == request_db)
        && (policy_env.is_wildcard() || policy_env == request_env)
}

pub(super) async fn check_server_health(
    url: &str,
    timeout: Duration,
) -> Result<(String, String), String> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout)
        .build()
        .map_err(|e| e.to_string())?;

    let resp = client
        .get(format!("{}/health", url.trim_end_matches('/')))
        .send()
        .await
        .map_err(|e| {
            if e.is_timeout() {
                "connection timed out".to_string()
            } else if e.is_connect() {
                "connection refused".to_string()
            } else {
                e.to_string()
            }
        })?;

    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }

    let body: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    let version = body["version"].as_str().unwrap_or("unknown").to_string();
    let min_agent = body["min_agent_version"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    Ok((version, min_agent))
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

fn print_results(ctx: &DoctorContext) {
    if ctx.json_output {
        print_json(ctx);
    } else {
        print_human(ctx);
    }
}

fn print_human(ctx: &DoctorContext) {
    for r in &ctx.results {
        let icon = match r.status {
            Status::Pass => "  \x1b[32m✓\x1b[0m",
            Status::Warn => "  \x1b[33m⚠\x1b[0m",
            Status::Fail => "  \x1b[31m✗\x1b[0m",
            Status::Skip => "  \x1b[90m-\x1b[0m",
        };
        println!("{} {:<24} {}", icon, r.id, r.message);
        if let Some(ref hint) = r.hint {
            println!("    {}", hint);
        }
    }

    let (pass, warn, fail, skip) = count_results(ctx);
    println!(
        "\n  {} passed, {} warnings, {} failed, {} skipped",
        pass, warn, fail, skip
    );
}

fn print_json(ctx: &DoctorContext) {
    let checks: Vec<serde_json::Value> = ctx
        .results
        .iter()
        .map(|r| {
            let mut obj = serde_json::json!({
                "id": r.id,
                "status": match r.status {
                    Status::Pass => "pass",
                    Status::Warn => "warn",
                    Status::Fail => "fail",
                    Status::Skip => "skip",
                },
                "message": r.message,
            });
            if let Some(ref hint) = r.hint {
                obj["hint"] = serde_json::Value::String(hint.clone());
            }
            obj
        })
        .collect();

    let (pass, warn, fail, skip) = count_results(ctx);
    let output = serde_json::json!({
        "checks": checks,
        "summary": {
            "passed": pass,
            "warnings": warn,
            "failed": fail,
            "skipped": skip,
        }
    });
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

fn count_results(ctx: &DoctorContext) -> (usize, usize, usize, usize) {
    let pass = ctx
        .results
        .iter()
        .filter(|r| r.status == Status::Pass)
        .count();
    let warn = ctx
        .results
        .iter()
        .filter(|r| r.status == Status::Warn)
        .count();
    let fail = ctx
        .results
        .iter()
        .filter(|r| r.status == Status::Fail)
        .count();
    let skip = ctx
        .results
        .iter()
        .filter(|r| r.status == Status::Skip)
        .count();
    (pass, warn, fail, skip)
}
