mod agent_checks;
mod cli_checks;
mod server_checks;

use std::path::PathBuf;
use std::time::Duration;

use serde::Serialize;

use crate::output::CliError;
use crate::output::{CliResponse, Column, RenderPlan, StderrLine, StdoutRender};

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
    pub details: Vec<String>,
}

pub(super) struct DoctorContext {
    results: Vec<CheckResult>,
    /// Suppress progress messages (true in json/quiet mode).
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
// Output type
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct DoctorOutput {
    pub checks: Vec<DoctorCheck>,
    pub summary: DoctorSummary,
}

#[derive(Serialize)]
pub struct DoctorCheck {
    pub id: String,
    pub status: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<String>,
}

#[derive(Serialize)]
pub struct DoctorSummary {
    pub passed: usize,
    pub warnings: usize,
    pub failed: usize,
    pub skipped: usize,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub async fn run(
    config_path: Option<&std::path::Path>,
    agent_config: Option<PathBuf>,
    server_config: Option<PathBuf>,
    suppress_progress: bool,
    timeout_secs: u64,
) -> Result<CliResponse<DoctorOutput>, CliError> {
    if agent_config.is_some() && server_config.is_some() {
        return Err(CliError::Config(
            "--agent and --server are mutually exclusive".into(),
        ));
    }

    let mut ctx = DoctorContext {
        results: Vec::new(),
        json_output: suppress_progress,
        timeout: Duration::from_secs(timeout_secs),
    };

    if let Some(path) = agent_config {
        agent_checks::run_agent_mode(&mut ctx, &path).await;
    } else if let Some(path) = server_config {
        server_checks::run_server_mode(&mut ctx, &path).await;
    } else {
        cli_checks::run_cli_mode(&mut ctx, config_path).await;
    }

    build_response(&ctx)
}

fn build_response(ctx: &DoctorContext) -> Result<CliResponse<DoctorOutput>, CliError> {
    let (pass, warn, fail, skip) = count_results(ctx);

    let checks: Vec<DoctorCheck> = ctx
        .results
        .iter()
        .map(|r| DoctorCheck {
            id: r.id.to_string(),
            status: match r.status {
                Status::Pass => "pass",
                Status::Warn => "warn",
                Status::Fail => "fail",
                Status::Skip => "skip",
            }
            .to_string(),
            message: r.message.clone(),
            hint: r.hint.clone(),
            details: r.details.clone(),
        })
        .collect();

    let summary = DoctorSummary {
        passed: pass,
        warnings: warn,
        failed: fail,
        skipped: skip,
    };

    let output = DoctorOutput { checks, summary };

    // Build table render
    let columns = vec![
        Column::new(" ").with_max_width(3),
        Column::new("CHECK").with_max_width(24),
        Column::new("MESSAGE"),
    ];

    let mut rows: Vec<Vec<String>> = ctx
        .results
        .iter()
        .map(|r| {
            let icon = match r.status {
                Status::Pass => "✅",
                Status::Warn => "⚠️",
                Status::Fail => "❌",
                Status::Skip => "⏭️",
            };
            vec![icon.to_string(), r.id.to_string(), r.message.clone()]
        })
        .collect();

    // Add summary row
    rows.push(vec![String::new(), String::new(), String::new()]);
    rows.push(vec![
        String::new(),
        "TOTAL".into(),
        format!("{pass} passed, {warn} warnings, {fail} failed, {skip} skipped"),
    ]);

    // Collect hints for stderr
    let mut stderr_lines: Vec<StderrLine> = Vec::new();
    for r in &ctx.results {
        if let Some(ref hint) = r.hint {
            stderr_lines.push(StderrLine::Hint(format!("{}: {hint}", r.id)));
        }
        for line in &r.details {
            stderr_lines.push(StderrLine::Info(r.id.to_string(), line.clone()));
        }
    }

    let render = RenderPlan {
        stdout: StdoutRender::Table { columns, rows },
        stderr: stderr_lines,
    };

    let has_failure = fail > 0;
    let resp = CliResponse::ok(output, render);
    if has_failure {
        Ok(resp.with_issues(2, "doctor_issues_found", format!("{fail} check(s) failed")))
    } else {
        Ok(resp)
    }
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
// Internal helpers
// ---------------------------------------------------------------------------

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
