use std::path::Path;
use std::time::Duration;

use dbward_api_types::requests::RequestStatus;
use serde_json::Value;

use crate::output::CliError;
use crate::output::{CliResponse, OutputMode, ProgressSink, RenderPlan, StderrLine, StdoutRender};
use crate::server_client::{CreateRequest, ServerClient};

use super::helpers::{build_request_metadata, save_result};
use super::workflow;

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
    result_format: crate::display::ResultFormat,
    timeout: Option<u64>,
    yes: bool,
    progress: &ProgressSink,
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
    crate::output::confirm_or_reject(mode, yes)?;

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

    // WHY: ctrl_c() future resolves only once. Pin and share via &mut across
    // two sequential select! blocks so Ctrl-C during either create or wait is caught.
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    // -----------------------------------------------------------------------
    // Step 1: Create request (with Ctrl-C escape for server-down scenarios)
    // -----------------------------------------------------------------------
    let cr = tokio::select! {
        result = workflow::create_request(sc, request) => result?,
        _ = &mut ctrl_c => {
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
    };
    let request_id = &cr.request_id;

    // -----------------------------------------------------------------------
    // Step 2: Exhaustive status branch (handles idempotency returning any state)
    // -----------------------------------------------------------------------
    match cr.status {
        // States that require waiting → proceed to Step 3
        RequestStatus::Dispatched
        | RequestStatus::Running
        | RequestStatus::AutoApproved
        | RequestStatus::BreakGlass => {}

        // Already terminal → resolve result immediately
        RequestStatus::Executed | RequestStatus::Failed => {
            let result = workflow::resolve_terminal_result(sc, request_id).await?;
            let save = save_result(request_id, &result, output, config_results_dir)?;
            if let Some(w) = save.warning {
                warnings.push(w);
            }
            let view = crate::output::views::QueryResultView::from_server_response(&result);
            let stdout = view.to_stdout_render(result_format);
            let render = RenderPlan {
                stdout,
                stderr: vec![],
            };
            let mut resp = CliResponse::ok(result, render);
            for w in warnings {
                resp = resp.with_warning(w);
            }
            return Ok(resp);
        }

        // Pending approval → inform user
        RequestStatus::Pending => {
            let output = serde_json::json!({
                "request_id": request_id,
                "status": "pending_approval",
                "approvers": cr.approvers,
            });
            let mut stderr = vec![StderrLine::Status(format!(
                "Request {request_id} requires approval."
            ))];
            if !cr.approvers.is_empty() {
                stderr.push(StderrLine::Info(
                    "Approvers".into(),
                    cr.approvers.join(", "),
                ));
            }
            stderr.push(StderrLine::Hint(format!(
                "Run: dbward request resume {request_id}"
            )));
            let render = RenderPlan {
                stdout: StdoutRender::None,
                stderr,
            };
            let mut resp = CliResponse::ok(output, render).with_issues(
                2,
                "pending_approval",
                format!("request {request_id} requires approval"),
            );
            for w in warnings {
                resp = resp.with_warning(w);
            }
            return Ok(resp);
        }

        // Approved but not yet resumed
        RequestStatus::Approved => {
            let output = serde_json::json!({
                "request_id": request_id,
                "status": "approved",
            });
            let render = RenderPlan {
                stdout: StdoutRender::None,
                stderr: vec![
                    StderrLine::Status(format!(
                        "Request {request_id} is approved but not yet resumed."
                    )),
                    StderrLine::Hint(format!("Run: dbward request resume {request_id}")),
                ],
            };
            let mut resp = CliResponse::ok(output, render).with_issues(
                2,
                "approved_pending_resume",
                format!("request {request_id} is approved but not yet resumed"),
            );
            for w in warnings {
                resp = resp.with_warning(w);
            }
            return Ok(resp);
        }

        // Terminal failure states (idempotency may return these)
        RequestStatus::Rejected => {
            let output = serde_json::json!({ "request_id": request_id, "status": "rejected" });
            let render = RenderPlan {
                stdout: StdoutRender::None,
                stderr: vec![StderrLine::Warn(format!(
                    "Request {request_id} was rejected."
                ))],
            };
            let mut resp =
                CliResponse::ok(output, render).with_issues(1, "rejected", "request was rejected");
            for w in warnings {
                resp = resp.with_warning(w);
            }
            return Ok(resp);
        }
        RequestStatus::Cancelled => {
            let output = serde_json::json!({ "request_id": request_id, "status": "cancelled" });
            let render = RenderPlan {
                stdout: StdoutRender::None,
                stderr: vec![StderrLine::Warn(format!(
                    "Request {request_id} was already cancelled."
                ))],
            };
            let mut resp = CliResponse::ok(output, render).with_issues(
                1,
                "cancelled",
                "request was cancelled",
            );
            for w in warnings {
                resp = resp.with_warning(w);
            }
            return Ok(resp);
        }
        RequestStatus::Expired => {
            let output = serde_json::json!({ "request_id": request_id, "status": "expired" });
            let render = RenderPlan {
                stdout: StdoutRender::None,
                stderr: vec![StderrLine::Warn(format!(
                    "Request {request_id} has expired."
                ))],
            };
            let mut resp =
                CliResponse::ok(output, render).with_issues(1, "expired", "request has expired");
            for w in warnings {
                resp = resp.with_warning(w);
            }
            return Ok(resp);
        }
        RequestStatus::ExecutionLost => {
            let output =
                serde_json::json!({ "request_id": request_id, "status": "execution_lost" });
            let render = RenderPlan {
                stdout: StdoutRender::None,
                stderr: vec![
                    StderrLine::Warn(format!("Request {request_id} execution was lost.")),
                    StderrLine::Hint(format!("Re-resume: dbward request resume {request_id}")),
                ],
            };
            let mut resp = CliResponse::ok(output, render).with_issues(
                1,
                "execution_lost",
                "execution was lost",
            );
            for w in warnings {
                resp = resp.with_warning(w);
            }
            return Ok(resp);
        }

        // Unknown status from newer server
        _ => {
            return Err(CliError::Api {
                code: "server_error".into(),
                message: format!("unexpected status from create_request: {}", cr.status),
            });
        }
    }

    // -----------------------------------------------------------------------
    // Step 3: Wait for completion with Ctrl-C and optional timeout
    // -----------------------------------------------------------------------
    let result = if let Some(secs) = timeout {
        tokio::select! {
            result = workflow::wait_for_completion(sc, request_id, cr.status, true, progress) => result?,
            _ = &mut ctrl_c => {
                return Ok(workflow::handle_interrupt(sc, request_id, mode, &warnings, true).await);
            }
            _ = tokio::time::sleep(Duration::from_secs(secs)) => {
                let output = serde_json::json!({
                    "request_id": request_id,
                    "timed_out": true,
                });
                let render = RenderPlan {
                    stdout: StdoutRender::None,
                    stderr: vec![
                        StderrLine::Warn(format!("Timed out after {secs}s. Request: {request_id}")),
                        StderrLine::Hint(format!("Check: dbward request show {request_id}")),
                        StderrLine::Hint(format!("Cancel: dbward request cancel {request_id}")),
                    ],
                };
                let mut resp = CliResponse::ok(output, render)
                    .with_issues(124, "timeout", format!("timed out after {secs}s"));
                for w in &warnings {
                    resp = resp.with_warning(w.clone());
                }
                return Ok(resp);
            }
        }
    } else {
        tokio::select! {
            result = workflow::wait_for_completion(sc, request_id, cr.status, true, progress) => result?,
            _ = &mut ctrl_c => {
                return Ok(workflow::handle_interrupt(sc, request_id, mode, &warnings, true).await);
            }
        }
    };

    // -----------------------------------------------------------------------
    // Step 4: Process completed result
    // -----------------------------------------------------------------------
    let save = save_result(request_id, &result, output, config_results_dir)?;
    if let Some(w) = save.warning {
        warnings.push(w);
    }
    let view = crate::output::views::QueryResultView::from_server_response(&result);
    let stdout = view.to_stdout_render(result_format);
    let render = RenderPlan {
        stdout,
        stderr: vec![],
    };
    let mut resp = CliResponse::ok(result, render);
    for w in warnings {
        resp = resp.with_warning(w);
    }
    Ok(resp)
}
