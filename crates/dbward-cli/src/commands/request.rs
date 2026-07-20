use std::path::{Path, PathBuf};

use clap::Subcommand;
use serde::Serialize;
use serde_json::Value;

use crate::display::ResultFormat;
use crate::display::{format_created_time, short_request_id, truncate_table_cell};
use crate::output::CliError;
use crate::output::{
    CliResponse, Column, OutputMode, RenderPlan, StderrLine, StdoutRender, confirm_or_reject,
};
use crate::server_client::ServerClient;

use super::helpers::save_result;
use super::workflow;

const LIST_DETAIL_WIDTH: usize = 30;

#[derive(Subcommand)]
pub enum RequestAction {
    List {
        #[arg(long)]
        limit: Option<u32>,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        pending_for_me: bool,
        #[arg(long)]
        user: Option<String>,
    },
    Show {
        id: String,
    },
    Approve {
        id: String,
        #[arg(long)]
        comment: Option<String>,
        /// Approve as a specific selector (e.g. role:dba). Required when you match multiple groups.
        #[arg(long = "as")]
        selector: Option<String>,
    },
    Reject {
        id: String,
        #[arg(long, alias = "comment")]
        reason: Option<String>,
    },
    Cancel {
        id: String,
        #[arg(long)]
        reason: Option<String>,
    },
    Resume {
        id: String,
        #[arg(long)]
        output: Option<PathBuf>,
        /// Result display format
        #[arg(long, value_enum)]
        result_format: Option<ResultFormat>,
        /// Reason for resuming (required when resuming another user's request)
        #[arg(long)]
        reason: Option<String>,
    },
    Result {
        id: String,
        /// List execution history for this request
        #[arg(long, conflicts_with_all = ["execution", "output", "result_format"])]
        list: bool,
        /// Specific execution ID (default: latest terminal)
        #[arg(long, conflicts_with = "list")]
        execution: Option<String>,
        /// Save result to a specific file
        #[arg(long, conflicts_with = "list")]
        output: Option<PathBuf>,
        /// Result display format
        #[arg(long, value_enum, conflicts_with = "list")]
        result_format: Option<ResultFormat>,
        /// Limit for --list
        #[arg(long, default_value = "20", requires = "list")]
        limit: u32,
    },
    /// List shared results
    Results {
        #[arg(long, default_value = "50")]
        limit: u32,
    },
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct RequestListOutput {
    pub requests: Vec<RequestSummary>,
}

#[derive(Serialize)]
pub struct RequestSummary {
    pub id: String,
    pub status: String,
    pub requester: String,
    pub environment: String,
    pub operation: String,
    pub detail: String,
    pub reason: String,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct RequestShowOutput(pub Value);

#[derive(Serialize)]
pub struct RequestApproveOutput {
    pub id: String,
    pub step: u64,
    pub total_steps: u64,
    pub fully_approved: bool,
    pub matched_selector: String,
}

#[derive(Serialize)]
pub struct RequestRejectOutput {
    pub id: String,
}

#[derive(Serialize)]
pub struct RequestCancelOutput {
    pub id: String,
}

#[derive(Serialize)]
pub struct RequestResumeOutput(pub Value);

#[derive(Serialize)]
pub struct RequestResultOutput(pub Value);

#[derive(Serialize)]
pub struct RequestResultsOutput {
    pub results: Vec<ResultSummary>,
}

#[derive(Serialize)]
pub struct ResultSummary {
    pub request_id: String,
    pub environment: String,
    pub database: String,
    pub operation: String,
    pub stored_at: String,
}

#[derive(Serialize)]
pub struct ExecutionListOutput {
    pub executions: Vec<ExecutionSummary>,
}

#[derive(Serialize)]
pub struct ExecutionSummary {
    pub id: String,
    pub status: String,
    pub has_stored_result: bool,
    pub finished_at: String,
    pub error_message: String,
}

// ---------------------------------------------------------------------------
// Main dispatch (new path — returns CliResponse)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub async fn run_request_cmd(
    sc: &ServerClient,
    action: &RequestAction,
    database: Option<&str>,
    environment: Option<&str>,
    config_results_dir: Option<&Path>,
    default_format: ResultFormat,
    yes: bool,
    mode: OutputMode,
) -> Result<crate::output::CliOutcome, CliError> {
    match action {
        RequestAction::Approve {
            id,
            comment,
            selector,
        } => {
            let resolved = resolve_request_id(sc, id).await?;
            let resp = run_approve(sc, &resolved, comment.as_deref(), selector.as_deref()).await?;
            Ok(resp.into())
        }
        RequestAction::Reject { id, reason } => {
            let resolved = resolve_request_id(sc, id).await?;
            let resp = run_reject(sc, &resolved, reason.as_deref()).await?;
            Ok(resp.into())
        }
        RequestAction::Cancel { id, reason } => {
            let resolved = resolve_request_id(sc, id).await?;
            let resp = run_cancel(sc, &resolved, reason.as_deref(), yes, mode).await?;
            Ok(resp.into())
        }
        RequestAction::List {
            limit,
            status,
            pending_for_me,
            user,
        } => {
            let resp = run_list(
                sc,
                *limit,
                status.as_deref(),
                *pending_for_me,
                user.as_deref(),
                database,
                environment,
            )
            .await?;
            Ok(resp.into())
        }
        RequestAction::Show { id } => {
            let resolved = resolve_request_id(sc, id).await?;
            let resp = run_show(sc, &resolved).await?;
            Ok(resp.into())
        }
        RequestAction::Resume {
            id,
            output,
            result_format,
            reason,
        } => {
            let resolved = resolve_request_id(sc, id).await?;
            let resp = run_resume(
                sc,
                &resolved,
                output.as_deref(),
                config_results_dir,
                result_format.unwrap_or(default_format),
                yes,
                reason.as_deref(),
                mode,
            )
            .await?;
            Ok(resp.into())
        }
        RequestAction::Result {
            id,
            list,
            execution,
            output,
            result_format,
            limit,
        } => {
            let resolved = resolve_request_id(sc, id).await?;
            if *list {
                let resp = run_executions(sc, &resolved, *limit).await?;
                Ok(resp.into())
            } else {
                let resp = run_result(
                    sc,
                    &resolved,
                    execution.as_deref(),
                    output.as_deref(),
                    config_results_dir,
                    result_format.unwrap_or(default_format),
                )
                .await?;
                Ok(resp.into())
            }
        }
        RequestAction::Results { limit } => {
            let resp = run_results(sc, *limit).await?;
            Ok(resp.into())
        }
    }
}

// ---------------------------------------------------------------------------
// Individual command implementations
// ---------------------------------------------------------------------------

async fn run_approve(
    sc: &ServerClient,
    id: &str,
    comment: Option<&str>,
    selector: Option<&str>,
) -> Result<CliResponse<RequestApproveOutput>, CliError> {
    match sc.approve(id, comment, selector).await {
        Ok(body) => {
            let step = body["current_step"]
                .as_u64()
                .or_else(|| body["step_completed"].as_u64().map(|v| v + 1))
                .unwrap_or(0);
            let total = body["total_steps"].as_u64().unwrap_or(0);
            let status = dbward_api_types::requests::RequestStatus::from_json(&body["status"]);
            let matched_selector = body["matched_selector"]
                .as_str()
                .unwrap_or("unknown")
                .to_string();
            let fully_approved = matches!(
                status,
                dbward_api_types::requests::RequestStatus::Approved
                    | dbward_api_types::requests::RequestStatus::Dispatched
            );

            let short_id = short_request_id(id);

            let mut stderr = vec![
                StderrLine::Status(format!(
                    "Approved as {matched_selector} (step {step}/{total})"
                )),
                StderrLine::Info("Request".into(), short_id.to_string()),
            ];
            if fully_approved {
                stderr.push(StderrLine::Hint(format!(
                    "All steps complete. Resume: dbward request resume {short_id}"
                )));
            } else {
                stderr.push(StderrLine::Status("Waiting for further approvals.".into()));
            }

            let output = RequestApproveOutput {
                id: id.to_string(),
                step,
                total_steps: total,
                fully_approved,
                matched_selector,
            };
            let render = RenderPlan {
                stdout: StdoutRender::None,
                stderr,
            };
            Ok(CliResponse::ok(output, render))
        }
        Err(e) => {
            if e.status == 404 {
                return Err(CliError::Api {
                    code: "not_found".into(),
                    message: format!("Request {id} not found"),
                });
            }
            let body_lower = e.body.to_lowercase();
            if e.status == 409
                && (body_lower.contains("already approved")
                    || body_lower.contains("already dispatched"))
            {
                return Err(CliError::Api {
                    code: "already_approved".into(),
                    message: format!(
                        "Request is already approved. The requester can resume with: dbward request resume {id}"
                    ),
                });
            }
            if e.status == 403 {
                return Err(CliError::Api {
                    code: "forbidden".into(),
                    message: e.body,
                });
            }
            Err(e.into_cli_error("approve"))
        }
    }
}

async fn run_reject(
    sc: &ServerClient,
    id: &str,
    reason: Option<&str>,
) -> Result<CliResponse<RequestRejectOutput>, CliError> {
    match sc.reject(id, reason).await {
        Ok(_body) => {
            let output = RequestRejectOutput { id: id.to_string() };
            let render = RenderPlan::status(format!("Rejected: {id}"));
            Ok(CliResponse::ok(output, render))
        }
        Err(e) => {
            if e.status == 404 {
                return Err(CliError::Api {
                    code: "not_found".into(),
                    message: format!("Request {id} not found"),
                });
            }
            if e.status == 403 {
                return Err(CliError::Api {
                    code: "forbidden".into(),
                    message: e.body,
                });
            }
            Err(e.into_cli_error("reject"))
        }
    }
}

async fn run_cancel(
    sc: &ServerClient,
    id: &str,
    reason: Option<&str>,
    yes: bool,
    mode: OutputMode,
) -> Result<CliResponse<RequestCancelOutput>, CliError> {
    // Check if query is running and needs confirmation
    let req_info = sc.get_json(&format!("/api/requests/{id}")).await;
    if !yes
        && let Ok(info) = &req_info
        && dbward_api_types::requests::RequestStatus::from_json(&info["status"])
            == dbward_api_types::requests::RequestStatus::Running
    {
        eprintln!("⚠ Query is currently executing on the database.");
        eprintln!("  Cancelling will kill the running query and roll back any changes.");
        if confirm_or_reject(mode, false).is_err() {
            return Err(CliError::Internal("aborted by user".into()));
        }
    }

    match sc.cancel_request(id, reason).await {
        Ok(_body) => {
            let output = RequestCancelOutput { id: id.to_string() };
            let render = RenderPlan::status(format!("Cancelled: {id}"));
            Ok(CliResponse::ok(output, render))
        }
        Err(e) => {
            if e.status == 404 {
                return Err(CliError::Api {
                    code: "not_found".into(),
                    message: format!("Request {id} not found"),
                });
            }
            if e.status == 403 {
                return Err(CliError::Api {
                    code: "forbidden".into(),
                    message: e.body,
                });
            }
            Err(e.into_cli_error("cancel"))
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_list(
    sc: &ServerClient,
    limit: Option<u32>,
    status: Option<&str>,
    pending_for_me: bool,
    user: Option<&str>,
    database: Option<&str>,
    environment: Option<&str>,
) -> Result<CliResponse<RequestListOutput>, CliError> {
    let body = if pending_for_me {
        sc.list_pending_for_me(limit).await?
    } else {
        sc.list_requests(limit, status, database, environment, user)
            .await?
    };

    let empty = vec![];
    let requests = body["requests"]
        .as_array()
        .or_else(|| body.as_array())
        .unwrap_or(&empty);

    if requests.is_empty() {
        let output = RequestListOutput { requests: vec![] };
        let render = RenderPlan::empty_list("requests");
        return Ok(CliResponse::ok(output, render));
    }

    let summaries: Vec<RequestSummary> = requests
        .iter()
        .map(|r| RequestSummary {
            id: r["id"].as_str().unwrap_or("?").to_string(),
            status: r["status"].as_str().unwrap_or("?").to_string(),
            requester: r["requester"].as_str().unwrap_or("?").to_string(),
            environment: r["environment"].as_str().unwrap_or("?").to_string(),
            operation: r["operation"].as_str().unwrap_or("?").to_string(),
            detail: r["detail"].as_str().unwrap_or("").to_string(),
            reason: r["reason"].as_str().unwrap_or("").to_string(),
            created_at: r["created_at"].as_str().unwrap_or("").to_string(),
        })
        .collect();

    let has_reason = summaries.iter().any(|r| !r.reason.is_empty());

    let mut columns = vec![
        Column::new("ID").with_max_width(8),
        Column::new("STATUS").with_max_width(16),
        Column::new("TIME").with_max_width(8),
        Column::new("USER").with_max_width(12),
        Column::new("ENV").with_max_width(12),
        Column::new("OP").with_max_width(16),
        Column::new("DETAIL").with_max_width(LIST_DETAIL_WIDTH),
    ];
    if has_reason {
        columns.push(Column::new("REASON"));
    }

    let rows: Vec<Vec<String>> = summaries
        .iter()
        .map(|r| {
            let short_id = r.id[..r.id.len().min(8)].to_string();
            let short_time = format_created_time(&r.created_at);
            let short_detail = truncate_table_cell(&r.detail, LIST_DETAIL_WIDTH);
            let mut row = vec![
                short_id,
                r.status.clone(),
                short_time,
                r.requester.clone(),
                r.environment.clone(),
                r.operation.clone(),
                short_detail,
            ];
            if has_reason {
                row.push(r.reason.clone());
            }
            row
        })
        .collect();

    let render = RenderPlan::table(columns, rows);
    Ok(CliResponse::ok(
        RequestListOutput {
            requests: summaries,
        },
        render,
    ))
}

async fn run_show(sc: &ServerClient, id: &str) -> Result<CliResponse<RequestShowOutput>, CliError> {
    let body = sc.get_request(id).await?;

    // Build key-value pairs for human display
    let pairs = build_show_pairs(&body);

    let output = RequestShowOutput(body);
    let render = RenderPlan::key_value(pairs);
    Ok(CliResponse::ok(output, render))
}

fn build_show_pairs(body: &Value) -> Vec<(String, String)> {
    let id = body["id"].as_str().unwrap_or("?");
    let status = body["status"].as_str().unwrap_or("?");
    let op = body["operation"].as_str().unwrap_or("?");
    let detail = body["detail"].as_str().unwrap_or("");
    let env = body["environment"].as_str().unwrap_or("?");
    let db = body["database"].as_str().unwrap_or("?");
    let user = body["requester"].as_str().unwrap_or("?");
    let created = body["created_at"].as_str().unwrap_or("?");
    let updated = body["updated_at"].as_str().unwrap_or("?");

    let mut pairs = vec![
        ("Request".into(), id.to_string()),
        ("Status".into(), status.to_string()),
        ("Operation".into(), op.to_string()),
        ("Detail".into(), detail.to_string()),
        ("Environment".into(), env.to_string()),
        ("Database".into(), db.to_string()),
    ];

    if let Some(r) = body["reason"].as_str() {
        pairs.push(("Reason".into(), r.to_string()));
    }
    if let Some(key) = body["idempotency_key"].as_str() {
        pairs.push(("Idempotency".into(), key.to_string()));
    }
    if !body["metadata"].is_null() {
        pairs.push((
            "Metadata".into(),
            serde_json::to_string(&body["metadata"]).unwrap_or_else(|_| "{}".to_string()),
        ));
    }
    pairs.push(("Created by".into(), user.to_string()));
    pairs.push(("Created at".into(), created.to_string()));
    pairs.push(("Updated at".into(), updated.to_string()));
    if let Some(resolved) = body["resolved_at"].as_str() {
        pairs.push(("Resolved at".into(), resolved.to_string()));
    }
    if body.get("execution_token").is_some() {
        pairs.push((
            "Ready".into(),
            format!("dbward request resume {}", short_request_id(id)),
        ));
    }

    // Context (risk, sql_review, explain)
    if let Some(ctx) = body.get("context").filter(|v| !v.is_null()) {
        let ctx_status = ctx["status"].as_str().unwrap_or("");
        if ctx_status == "collecting" {
            pairs.push(("Context".into(), "(collecting...)".to_string()));
        } else {
            // Risk
            if let Some(risk) = ctx.get("risk").filter(|v| !v.is_null()) {
                let level = risk["level"].as_str().unwrap_or("?");
                let factors: Vec<String> = risk["factors"]
                    .as_array()
                    .map(|arr| dbward_app::services::risk_display::format_risk_factors(arr))
                    .unwrap_or_default();
                let risk_str = if factors.is_empty() {
                    level.to_string()
                } else {
                    format!("{level} ({})", factors.join(", "))
                };
                pairs.push(("Risk".into(), risk_str));
            }
            // SQL Review
            if let Some(review) = ctx.get("sql_review").filter(|v| !v.is_null()) {
                let findings = review["findings"].as_array().map(|a| a.len()).unwrap_or(0);
                let review_str = if findings == 0 {
                    "passed".to_string()
                } else {
                    format!("{findings} warning{}", if findings > 1 { "s" } else { "" })
                };
                pairs.push(("SQL Review".into(), review_str));
            }
            // Tables
            if let Some(tables_val) = ctx.get("tables").filter(|v| !v.is_null()) {
                let json_str = serde_json::to_string(tables_val).unwrap_or_default();
                let entries =
                    dbward_app::services::tables_display::parse_tables_json(Some(&json_str));
                if !entries.is_empty() {
                    let display: Vec<String> = entries
                        .iter()
                        .map(|e| {
                            let name = match &e.schema_name {
                                Some(s) if s != "public" => format!("{}.{}", s, e.name),
                                _ => e.name.clone(),
                            };
                            match e.estimated_rows {
                                Some(r) if r > 0 => format!("{name} (~{r} rows)"),
                                _ => name,
                            }
                        })
                        .collect();
                    pairs.push(("Tables".into(), display.join(", ")));
                }
            }
            // Schema snapshot
            if let Some(ts) = ctx["schema_snapshot_collected_at"].as_str() {
                let short_ts = if ts.len() >= 19 { &ts[..19] } else { ts };
                pairs.push(("Schema".into(), format!("synced at {short_ts}")));
            }
            // Explain
            if let Some(explain) = ctx.get("explain").filter(|v| !v.is_null()) {
                if let Some(arr) = explain.as_array() {
                    if arr.is_empty() {
                        pairs.push(("Explain".into(), "(no plan available)".to_string()));
                    } else {
                        let lines = format_explain_entries(arr);
                        pairs.push(("Explain".into(), lines.join("\n")));
                    }
                }
            } else if ctx_status == "ready" {
                pairs.push(("Explain".into(), "(no plan available)".to_string()));
            }
        }
    }

    // Approval progress
    if let Some(progress) = body.get("approval_progress").filter(|v| !v.is_null()) {
        let current = progress["current_step"].as_u64().unwrap_or(0);
        let total = progress["total_steps"].as_u64().unwrap_or(0);
        let progress_str = format_approval_progress(progress, current, total);
        pairs.push(("Approval".into(), progress_str));
    }

    // Decision trace
    if let Some(trace) = body.get("decision_trace").filter(|v| !v.is_null()) {
        let decision_str = format_decision_trace(trace);
        pairs.push(("Decision".into(), decision_str));
    }

    pairs
}

fn format_explain_entries(arr: &[Value]) -> Vec<String> {
    let mut lines = Vec::new();
    let multi = arr.len() > 1;
    for (i, entry) in arr.iter().enumerate() {
        if let Some(err) = entry["error"].as_str() {
            let prefix = if multi {
                format!("[{}] ", i + 1)
            } else {
                String::new()
            };
            let hint = entry["hint"]
                .as_str()
                .map(|h| format!(" ({h})"))
                .unwrap_or_default();
            lines.push(format!("{prefix}(error: {err}{hint})"));
            continue;
        }
        let tree_lines = dbward_app::services::explain_formatter::format_explain_tree(
            entry,
            &dbward_app::services::explain_formatter::FormatOptions::cli(),
        );
        for (li, line) in tree_lines.iter().enumerate() {
            let prefix = if multi && li == 0 {
                format!("[{}] ", i + 1)
            } else if multi {
                "    ".to_string()
            } else {
                String::new()
            };
            lines.push(format!("{prefix}{line}"));
        }
    }
    lines
}

fn format_approval_progress(progress: &Value, current: u64, total: u64) -> String {
    let mut lines = vec![format!("{current}/{total} complete")];
    if let Some(steps) = progress["steps"].as_array() {
        for step in steps {
            let idx = step["index"].as_u64().unwrap_or(0);
            let mode_str = step["mode"].as_str().unwrap_or("all");
            let satisfied = step["satisfied"].as_bool().unwrap_or(false);
            let marker = if satisfied { "[ok]" } else { "[wait]" };
            let approvers_desc: Vec<String> = step["approvers_required"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|a| {
                            let target = a["selector"].as_str()?;
                            let min = a["min"].as_u64().unwrap_or(1);
                            let cur = a["current"].as_u64().unwrap_or(0);
                            let status_icon = if cur >= min { "✓" } else { "⏳" };
                            Some(format!("{target} {status_icon} {cur}/{min}"))
                        })
                        .collect()
                })
                .unwrap_or_default();
            let joiner = if mode_str == "any" { " | " } else { " + " };
            let desc = if approvers_desc.is_empty() {
                "(no approvers configured)".to_string()
            } else {
                approvers_desc.join(joiner)
            };
            lines.push(format!("  {marker} Step {} [{mode_str}]: {desc}", idx + 1));
            if let Some(approvals) = step["approvals"].as_array() {
                for a in approvals {
                    let who = a["user"].as_str().unwrap_or("?");
                    let at = a["at"].as_str().unwrap_or("");
                    let action = a["action"].as_str().unwrap_or("approve");
                    let verb = if action == "reject" {
                        "rejected by"
                    } else {
                        "approved by"
                    };
                    let short_time = if at.len() >= 16 { &at[11..16] } else { at };
                    let comment_part =
                        if let Some(c) = a["comment"].as_str().filter(|c| !c.is_empty()) {
                            format!(" - {c}")
                        } else {
                            String::new()
                        };
                    lines.push(format!(
                        "         {verb} {who} ({short_time}){comment_part}"
                    ));
                }
            }
        }
    }
    lines.join("\n")
}

fn format_decision_trace(trace: &Value) -> String {
    let mut lines = Vec::new();

    if let Some(op) = trace["classification"]["resolved_operation"].as_str() {
        lines.push(format!("Operation: {op}"));
    }
    // SQL Review
    let parse_failed = trace["sql_review"]["parse_failed"]
        .as_bool()
        .unwrap_or(false);
    let findings = trace["sql_review"]["findings_count"].as_u64().unwrap_or(0);
    if parse_failed {
        lines.push("SQL Review: skipped (parse failed)".to_string());
    } else if findings == 0 {
        lines.push("SQL Review: passed".to_string());
    } else {
        lines.push(format!(
            "SQL Review: {findings} warning{}",
            if findings > 1 { "s" } else { "" }
        ));
    }
    // Risk
    let level = trace["risk"]["level"].as_str().unwrap_or("?");
    let factors: Vec<&str> = trace["risk"]["factors"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    let threshold = trace["decision"]["auto_approve_threshold"].as_str();
    let risk_str = if factors.is_empty() {
        match threshold {
            Some(t) => format!("{level} (threshold: {t})"),
            None => level.to_string(),
        }
    } else {
        let factors_str = factors.join(", ");
        match threshold {
            Some(t) => format!("{level} ({factors_str}) (threshold: {t})"),
            None => format!("{level} ({factors_str})"),
        }
    };
    lines.push(format!("Risk: {risk_str}"));
    // Workflow
    if let Some(wf) = trace["workflow"]["matched"].as_object() {
        let wf_id = wf.get("id").and_then(|v| v.as_str()).unwrap_or("?");
        let db = wf.get("database").and_then(|v| v.as_str()).unwrap_or("*");
        let env = wf
            .get("environment")
            .and_then(|v| v.as_str())
            .unwrap_or("*");
        let steps = wf.get("step_count").and_then(|v| v.as_u64()).unwrap_or(0);
        lines.push(format!(
            "Workflow: {wf_id} ({db}:{env}, {steps} step{})",
            if steps != 1 { "s" } else { "" }
        ));
    } else {
        lines.push("Workflow: none".to_string());
    }
    // Outcome
    let outcome = trace["decision"]["outcome"].as_str().unwrap_or("?");
    let reasons: Vec<&str> = trace["decision"]["reasons"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    if reasons.is_empty() {
        lines.push(format!("Outcome: {outcome}"));
    } else {
        lines.push(format!("Outcome: {outcome} [{}]", reasons.join(", ")));
    }

    lines.join("\n")
}

#[allow(clippy::too_many_arguments)]
async fn run_resume(
    sc: &ServerClient,
    id: &str,
    output: Option<&Path>,
    config_results_dir: Option<&Path>,
    result_format: ResultFormat,
    yes: bool,
    reason: Option<&str>,
    mode: OutputMode,
) -> Result<CliResponse<RequestResumeOutput>, CliError> {
    // DML re-resume warning
    let req = sc.get_request(id).await?;
    let status = dbward_api_types::requests::RequestStatus::from_json(&req["status"]);
    let operation = req["operation"].as_str().unwrap_or("");
    if !yes
        && mode == OutputMode::Human
        && status == dbward_api_types::requests::RequestStatus::ExecutionLost
        && operation == "execute_query"
    {
        if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            return Err(CliError::Internal(
                "interactive confirmation required but stdin is not a terminal. Use --yes to skip."
                    .into(),
            ));
        }
        let detail = req["detail"].as_str().unwrap_or("");
        eprintln!("⚠️  WARNING: This request previously failed with execution_lost.");
        eprintln!("   The previous execution may have partially completed.");
        let sql_preview: String = detail.chars().take(80).collect();
        eprintln!("   SQL: {sql_preview}");
        eprintln!("   Re-resuming may cause DUPLICATE execution.");
        eprint!("   Continue? [y/N] ");
        std::io::Write::flush(&mut std::io::stderr()).ok();
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).ok();
        if !input.trim().eq_ignore_ascii_case("y") {
            eprintln!("Aborted.");
            let render = RenderPlan::status("Aborted.");
            return Ok(CliResponse::empty(render));
        }
    }

    if let Err(e) = sc.resume(id, reason).await {
        if e.status == 409 {
            // Fetch current status for a helpful message
            let hint = if let Ok(req) = sc.get_request(id).await {
                use dbward_api_types::requests::RequestStatus;
                let status = RequestStatus::from_json(&req["status"]);
                match status {
                    RequestStatus::Executed => {
                        format!("Already executed. Run: dbward request result {id}")
                    }
                    RequestStatus::Failed => {
                        format!("Request failed. Run: dbward request show {id}")
                    }
                    RequestStatus::Cancelled => "Request was cancelled.".to_string(),
                    RequestStatus::Dispatched | RequestStatus::Running => {
                        "Already resumed. Waiting for agent...".to_string()
                    }
                    RequestStatus::ExecutionLost => {
                        format!("Execution lost. Retry: dbward request resume {id}")
                    }
                    RequestStatus::Pending => "Still pending approval.".to_string(),
                    _ => {
                        format!("Request {id} cannot be resumed (status: {status}).")
                    }
                }
            } else {
                format!("Request {id} cannot be resumed yet (may still be pending approval).")
            };
            return Err(CliError::Api {
                code: "not_ready".into(),
                message: format!("{hint}\n  Check status: dbward request show {id}"),
            });
        }
        return Err(e.into_cli_error("resume"));
    }

    let resp = tokio::select! {
        r = workflow::wait_and_resolve(sc, id, true) => r?,
        _ = tokio::signal::ctrl_c() => {
            let stderr = vec![
                StderrLine::Status("Request is still running.".into()),
                StderrLine::Hint(format!("Check later: dbward request show {id}")),
                StderrLine::Hint(format!("Resume: dbward request resume {id}")),
                StderrLine::Hint(format!("Cancel: dbward request cancel {id}")),
            ];
            let render = RenderPlan { stdout: StdoutRender::None, stderr };
            return Ok(CliResponse::<RequestResumeOutput>::empty(render)
                .with_issues(130, "interrupted", "interrupted by user"));
        }
    };

    // Save result (maintains backward compatibility)
    save_result(id, &resp, output, config_results_dir)?;

    // For human mode: use the existing formatted display via Raw
    let human_display = format_execution_result_as_string(&resp, result_format);
    let render = RenderPlan {
        stdout: StdoutRender::Raw {
            value: human_display,
        },
        stderr: vec![],
    };

    Ok(CliResponse::ok(RequestResumeOutput(resp), render))
}

async fn run_result(
    sc: &ServerClient,
    id: &str,
    execution_id: Option<&str>,
    output: Option<&Path>,
    config_results_dir: Option<&Path>,
    result_format: ResultFormat,
) -> Result<CliResponse<RequestResultOutput>, CliError> {
    let resp = sc.get_result_content(id, execution_id).await?;

    // Save result (maintains backward compatibility)
    save_result(id, &resp, output, config_results_dir)?;

    // For human mode: use the existing formatted display via Raw
    let human_display = format_execution_result_as_string(&resp, result_format);
    let render = RenderPlan {
        stdout: StdoutRender::Raw {
            value: human_display,
        },
        stderr: vec![],
    };

    Ok(CliResponse::ok(RequestResultOutput(resp), render))
}

async fn run_executions(
    sc: &ServerClient,
    id: &str,
    limit: u32,
) -> Result<CliResponse<ExecutionListOutput>, CliError> {
    let body = sc.get_executions(id, limit).await?;

    let executions_arr = body["executions"].as_array().cloned().unwrap_or_default();

    if executions_arr.is_empty() {
        let output = ExecutionListOutput { executions: vec![] };
        let render = RenderPlan::empty_list("executions");
        return Ok(CliResponse::ok(output, render));
    }

    let summaries: Vec<ExecutionSummary> = executions_arr
        .iter()
        .map(|e| ExecutionSummary {
            id: e["id"].as_str().unwrap_or("").to_string(),
            status: e["status"].as_str().unwrap_or("").to_string(),
            has_stored_result: e["has_stored_result"].as_bool().unwrap_or(false),
            finished_at: e["finished_at"].as_str().unwrap_or("-").to_string(),
            error_message: e["error_message"].as_str().unwrap_or("").to_string(),
        })
        .collect();

    let columns = vec![
        Column::new("ID").with_max_width(12),
        Column::new("STATUS").with_max_width(12),
        Column::new("STORED").with_max_width(6),
        Column::new("FINISHED").with_max_width(24),
        Column::new("ERROR"),
    ];

    let rows: Vec<Vec<String>> = summaries
        .iter()
        .map(|e| {
            vec![
                e.id[..12.min(e.id.len())].to_string(),
                e.status.clone(),
                if e.has_stored_result {
                    "yes".to_string()
                } else {
                    "no".to_string()
                },
                e.finished_at.clone(),
                e.error_message.clone(),
            ]
        })
        .collect();

    let render = RenderPlan::table(columns, rows);
    Ok(CliResponse::ok(
        ExecutionListOutput {
            executions: summaries,
        },
        render,
    ))
}

async fn run_results(
    sc: &ServerClient,
    limit: u32,
) -> Result<CliResponse<RequestResultsOutput>, CliError> {
    let body = sc.list_results(limit).await?;

    let results_arr = body["results"].as_array().cloned().unwrap_or_default();

    if results_arr.is_empty() {
        let output = RequestResultsOutput { results: vec![] };
        let render = RenderPlan::empty_list("shared results");
        return Ok(CliResponse::ok(output, render));
    }

    let summaries: Vec<ResultSummary> = results_arr
        .iter()
        .map(|r| ResultSummary {
            request_id: r["request_id"].as_str().unwrap_or("").to_string(),
            environment: r["environment"].as_str().unwrap_or("").to_string(),
            database: r["database"].as_str().unwrap_or("").to_string(),
            operation: r["operation"].as_str().unwrap_or("").to_string(),
            stored_at: r["stored_at"].as_str().unwrap_or("").to_string(),
        })
        .collect();

    let columns = vec![
        Column::new("ID").with_max_width(10),
        Column::new("ENV").with_max_width(10),
        Column::new("DB").with_max_width(12),
        Column::new("OPERATION").with_max_width(16),
        Column::new("STORED AT"),
    ];

    let rows: Vec<Vec<String>> = summaries
        .iter()
        .map(|r| {
            vec![
                r.request_id[..8.min(r.request_id.len())].to_string(),
                r.environment.clone(),
                r.database.clone(),
                r.operation.clone(),
                r.stored_at.clone(),
            ]
        })
        .collect();

    let render = RenderPlan::table(columns, rows);
    Ok(CliResponse::ok(
        RequestResultsOutput { results: summaries },
        render,
    ))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Format execution result as a string for human display.
fn format_execution_result_as_string(resp: &Value, _format: ResultFormat) -> String {
    use crate::output::views::QueryResultView;

    let view = QueryResultView::from_server_response(resp);

    // Query results with actual rows or rows_affected -> structured view
    if view.rows.as_ref().is_some_and(|r| !r.is_empty()) || view.rows_affected.is_some() {
        return serde_json::to_string_pretty(&view).unwrap_or_default();
    }

    // Non-tabular results (migrate, etc.) -> pretty-print raw data
    let result = if !resp["result"].is_null() {
        &resp["result"]
    } else if !resp["result_data"].is_null() {
        &resp["result_data"]
    } else {
        return "Executed successfully.".to_string();
    };

    if let Some(text) = result.as_str() {
        text.to_string()
    } else {
        serde_json::to_string_pretty(result).unwrap_or_default()
    }
}

/// Resolve a potentially shortened request ID to a full UUID via prefix match.
/// If the ID is already a full UUID (36 chars), return as-is.
async fn resolve_request_id(sc: &ServerClient, id: &str) -> Result<String, CliError> {
    if looks_like_full_uuid(id) {
        return Ok(id.to_string());
    }
    let resp = sc.list_requests(Some(100), None, None, None, None).await?;
    let requests = resp["requests"].as_array().ok_or_else(|| CliError::Api {
        code: "server_error".into(),
        message: "unexpected response from list_requests".into(),
    })?;
    let matches: Vec<&str> = requests
        .iter()
        .filter_map(|r| r["id"].as_str())
        .filter(|full_id| full_id.starts_with(id))
        .collect();
    match matches.len() {
        0 => {
            let hint = if requests.len() >= 100 {
                " (searched last 100 requests; older requests not checked)"
            } else {
                ""
            };
            Err(CliError::Api {
                code: "not_found".into(),
                message: format!("no request found matching prefix '{id}'{hint}"),
            })
        }
        1 => Ok(matches[0].to_string()),
        _ => Err(CliError::Api {
            code: "ambiguous".into(),
            message: format!(
                "ambiguous prefix '{id}': matches {} requests. Use a longer prefix.",
                matches.len()
            ),
        }),
    }
}

fn looks_like_full_uuid(s: &str) -> bool {
    s.len() == 36
        && s.as_bytes()[8] == b'-'
        && s.as_bytes()[13] == b'-'
        && s.as_bytes()[18] == b'-'
        && s.as_bytes()[23] == b'-'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_uuid_detected() {
        assert!(looks_like_full_uuid("550e8400-e29b-41d4-a716-446655440000"));
        assert!(looks_like_full_uuid("818ed6c0-1234-5678-9abc-def012345678"));
    }

    #[test]
    fn short_prefix_not_uuid() {
        assert!(!looks_like_full_uuid("818ed6c0"));
        assert!(!looks_like_full_uuid("550e8400-e29b"));
    }

    #[test]
    fn wrong_format_not_uuid() {
        assert!(!looks_like_full_uuid(
            "550e8400xe29bx41d4xa716x446655440000"
        ));
        assert!(!looks_like_full_uuid(
            "550e8400-e29b-41d4-a716-4466554400001"
        ));
    }

    #[test]
    fn build_show_pairs_basic() {
        let body = serde_json::json!({
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "status": "pending",
            "operation": "execute_query",
            "detail": "SELECT 1",
            "environment": "production",
            "database": "primary",
            "requester": "alice",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:01:00Z",
        });
        let pairs = build_show_pairs(&body);
        assert!(
            pairs
                .iter()
                .any(|(k, v)| k == "Request" && v.contains("550e8400"))
        );
        assert!(pairs.iter().any(|(k, v)| k == "Status" && v == "pending"));
        assert!(
            pairs
                .iter()
                .any(|(k, v)| k == "Operation" && v == "execute_query")
        );
    }

    #[test]
    fn format_decision_trace_basic() {
        let trace = serde_json::json!({
            "classification": {"resolved_operation": "execute_select"},
            "sql_review": {"parse_failed": false, "findings_count": 0},
            "risk": {"level": "low", "factors": []},
            "workflow": {"matched": {"id": "wf1", "database": "*", "environment": "production", "step_count": 1}},
            "decision": {"outcome": "auto_approved", "reasons": ["risk_below_threshold"]}
        });
        let output = format_decision_trace(&trace);
        assert!(output.contains("Operation: execute_select"));
        assert!(output.contains("SQL Review: passed"));
        assert!(output.contains("Risk: low"));
        assert!(output.contains("Outcome: auto_approved"));
    }
}
