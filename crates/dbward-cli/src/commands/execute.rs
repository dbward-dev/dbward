use std::path::Path;

use serde_json::Value;

use crate::error::CliError;
use crate::output::{CliResponse, OutputMode, RenderPlan, StderrLine, StdoutRender};
use crate::server_client::{CreateRequest, ServerClient};

use super::helpers::{build_request_metadata, save_result};
use super::workflow::{self, Outcome};

// ---------------------------------------------------------------------------
// Command implementation
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub async fn run_execute(
    sc: &ServerClient,
    db_name: &str,
    env_str: &str,
    mode: OutputMode,
    sql: &str,
    emergency: bool,
    allow_ddl: bool,
    reason: Option<&str>,
    output: Option<&Path>,
    config_results_dir: Option<&Path>,
    ticket: Option<&str>,
    repo: Option<&str>,
    idempotency_key: Option<&str>,
    share_with: &[String],
    no_result_store: bool,
    _result_format: crate::display::ResultFormat,
    timeout: Option<u64>,
    yes: bool,
) -> Result<CliResponse<Value>, CliError> {
    if emergency && reason.is_none() {
        return Err(CliError::Config("--emergency requires --reason".into()));
    }

    let mut warnings: Vec<String> = Vec::new();
    if no_result_store {
        warnings.push(
            "--no-result-store: query result will not be stored. If you disconnect, it cannot be recovered. \
             Note: request metadata and SQL text are always retained for audit/approval.".to_string()
        );
    }

    // Confirmation: use confirm_or_reject for non-interactive safety
    crate::output::confirm_or_reject(mode, yes).map_err(|e| match e {
        crate::output::CliError::Blocked { reason } => CliError::Other(reason),
        other => CliError::Other(other.to_string()),
    })?;

    let metadata = build_request_metadata(ticket, repo);
    let sw = if share_with.is_empty() {
        None
    } else {
        Some(share_with)
    };

    let request = CreateRequest {
        operation: "execute_query",
        environment: env_str,
        database: db_name,
        detail: sql,
        emergency,
        allow_ddl,
        reason,
        metadata: metadata.as_ref(),
        idempotency_key,
        share_with: sw,
        no_result_store,
    };

    let outcome = if let Some(secs) = timeout {
        tokio::select! {
            result = workflow::submit_and_orchestrate(sc, request, true) => result?,
            _ = tokio::signal::ctrl_c() => {
                let output = serde_json::json!({
                    "interrupted": true,
                    "message": "If a request was created, check: dbward request list"
                });
                let render = RenderPlan {
                    stdout: StdoutRender::None,
                    stderr: vec![
                        StderrLine::Warn("Interrupted.".into()),
                        StderrLine::Hint("If a request was created, check: dbward request list".into()),
                    ],
                };
                let mut resp = CliResponse::ok(output, render)
                    .with_issues(130, "interrupted", "operation interrupted by user");
                for w in &warnings {
                    resp = resp.with_warning(w.clone());
                }
                return Ok(resp);
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(secs)) => {
                return Err(CliError::Other(format!(
                    "timed out after {secs}s waiting for completion. \
                     Request may still be in progress. Check: dbward request list"
                )));
            }
        }
    } else {
        tokio::select! {
            result = workflow::submit_and_orchestrate(sc, request, true) => result?,
            _ = tokio::signal::ctrl_c() => {
                let output = serde_json::json!({
                    "interrupted": true,
                    "message": "If a request was created, check: dbward request list"
                });
                let render = RenderPlan {
                    stdout: StdoutRender::None,
                    stderr: vec![
                        StderrLine::Warn("Interrupted.".into()),
                        StderrLine::Hint("If a request was created, check: dbward request list".into()),
                    ],
                };
                let mut resp = CliResponse::ok(output, render)
                    .with_issues(130, "interrupted", "operation interrupted by user");
                for w in &warnings {
                    resp = resp.with_warning(w.clone());
                }
                return Ok(resp);
            }
        }
    };

    let resp = match outcome {
        Outcome::Completed { request_id, result } => {
            save_result(&request_id, &result, output, config_results_dir);
            let pretty = serde_json::to_string_pretty(&result).unwrap_or_default();
            let render = RenderPlan {
                stdout: StdoutRender::Raw { value: pretty },
                stderr: vec![],
            };
            CliResponse::ok(result, render)
        }
        Outcome::Pending {
            request_id,
            approvers,
        } => {
            let output = serde_json::json!({
                "request_id": request_id,
                "status": "pending_approval",
                "approvers": approvers,
            });
            let mut stderr = vec![
                StderrLine::Status(format!("Request {request_id} requires approval.")),
            ];
            if !approvers.is_empty() {
                stderr.push(StderrLine::Info("Approvers".into(), approvers.join(", ")));
            }
            stderr.push(StderrLine::Hint(format!("Run: dbward request resume {request_id}")));

            let render = RenderPlan {
                stdout: StdoutRender::None,
                stderr,
            };
            CliResponse::ok(output, render)
                .with_issues(2, "pending_approval", format!("request {request_id} requires approval"))
        }
        Outcome::Approved { request_id } => {
            let output = serde_json::json!({
                "request_id": request_id,
                "status": "approved",
            });
            let render = RenderPlan {
                stdout: StdoutRender::None,
                stderr: vec![
                    StderrLine::Status(format!("Request {request_id} is approved but not yet resumed.")),
                    StderrLine::Hint(format!("Run: dbward request resume {request_id}")),
                ],
            };
            CliResponse::ok(output, render)
        }
    };

    let mut resp = resp;
    for w in warnings {
        resp = resp.with_warning(w);
    }
    Ok(resp)
}
