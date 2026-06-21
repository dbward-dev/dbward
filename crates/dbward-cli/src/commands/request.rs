use std::path::{Path, PathBuf};

use clap::Subcommand;

use crate::display::*;
use crate::error::CliError;
use crate::server_client::ServerClient;

use super::helpers::save_result;
use super::workflow;

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

pub async fn run_request(
    sc: &ServerClient,
    json_output: bool,
    action: RequestAction,
    database: Option<&str>,
    environment: Option<&str>,
    config_results_dir: Option<&Path>,
    default_format: ResultFormat,
) -> Result<(), CliError> {
    match action {
        RequestAction::Approve {
            id,
            comment,
            selector,
        } => {
            let resolved = resolve_request_id(sc, &id).await?;
            run_approve(
                sc,
                json_output,
                &resolved,
                comment.as_deref(),
                selector.as_deref(),
            )
            .await
        }
        RequestAction::Reject { id, reason } => {
            let resolved = resolve_request_id(sc, &id).await?;
            run_reject(sc, json_output, &resolved, reason.as_deref()).await
        }
        RequestAction::Cancel { id, reason } => {
            let resolved = resolve_request_id(sc, &id).await?;
            run_cancel(sc, json_output, &resolved, reason.as_deref()).await
        }
        RequestAction::List {
            limit,
            status,
            pending_for_me,
            user,
        } => {
            run_list(
                sc,
                json_output,
                limit,
                status.as_deref(),
                pending_for_me,
                user.as_deref(),
                database,
                environment,
            )
            .await
        }
        RequestAction::Show { id } => {
            let resolved = resolve_request_id(sc, &id).await?;
            run_show(sc, json_output, &resolved).await
        }
        RequestAction::Resume {
            id,
            output,
            result_format,
        } => {
            let resolved = resolve_request_id(sc, &id).await?;
            run_resume(
                sc,
                json_output,
                &resolved,
                output.as_deref(),
                config_results_dir,
                result_format.unwrap_or(default_format),
            )
            .await
        }
        RequestAction::Result {
            id,
            list,
            execution,
            output,
            result_format,
            limit,
        } => {
            let resolved = resolve_request_id(sc, &id).await?;
            if list {
                run_executions(sc, json_output, &resolved, limit).await
            } else {
                run_result(
                    sc,
                    json_output,
                    &resolved,
                    execution.as_deref(),
                    output.as_deref(),
                    config_results_dir,
                    result_format.unwrap_or(default_format),
                )
                .await
            }
        }
        RequestAction::Results { limit } => run_results(sc, json_output, limit).await,
    }
}

async fn run_approve(
    sc: &ServerClient,
    json_output: bool,
    id: &str,
    comment: Option<&str>,
    selector: Option<&str>,
) -> Result<(), CliError> {
    match sc.approve(id, comment, selector).await {
        Ok(body) => {
            if json_output {
                println!("{}", serde_json::to_string_pretty(&body)?);
            } else {
                print_approve_result(&body, id);
            }
            Ok(())
        }
        Err(e) => {
            if e.status == 404 {
                return Err(CliError::Server(format!("Request {id} not found")));
            }
            let body_lower = e.body.to_lowercase();
            if e.status == 409
                && (body_lower.contains("already approved")
                    || body_lower.contains("already dispatched"))
            {
                return Err(CliError::Server(format!(
                    "Request is already approved. Run: dbward request resume {id}"
                )));
            }
            if e.status == 403 {
                return Err(CliError::Server(e.body));
            }
            Err(e.into_cli_error("approve"))
        }
    }
}

async fn run_reject(
    sc: &ServerClient,
    json_output: bool,
    id: &str,
    reason: Option<&str>,
) -> Result<(), CliError> {
    match sc.reject(id, reason).await {
        Ok(body) => {
            if json_output {
                println!("{}", serde_json::to_string_pretty(&body)?);
            } else {
                println!("Rejected: {id}");
            }
            Ok(())
        }
        Err(e) => {
            if e.status == 404 {
                return Err(CliError::Server(format!("Request {id} not found")));
            }
            if e.status == 403 {
                return Err(CliError::Server(e.body));
            }
            Err(e.into_cli_error("reject"))
        }
    }
}

#[allow(clippy::collapsible_if)]
async fn run_cancel(
    sc: &ServerClient,
    json_output: bool,
    id: &str,
    reason: Option<&str>,
) -> Result<(), CliError> {
    let req_info = sc.get_json(&format!("/api/requests/{id}")).await;
    if !json_output {
        if let Ok(info) = &req_info {
            if dbward_api_types::requests::RequestStatus::from_json(&info["status"])
                == dbward_api_types::requests::RequestStatus::Running
            {
                eprintln!("⚠ Query is currently executing on the database.");
                eprintln!("  Cancelling will kill the running query and roll back any changes.");
                eprint!("  Continue? [y/N] ");
                let mut input = String::new();
                std::io::stdin().read_line(&mut input).unwrap_or(0);
                if !input.trim().eq_ignore_ascii_case("y") {
                    eprintln!("Aborted.");
                    return Ok(());
                }
            }
        }
    }
    match sc.cancel_request(id, reason).await {
        Ok(body) => {
            if json_output {
                println!("{}", serde_json::to_string_pretty(&body)?);
            } else {
                println!("Cancelled: {id}");
            }
            Ok(())
        }
        Err(e) => {
            if e.status == 404 {
                return Err(CliError::Server(format!("Request {id} not found")));
            }
            if e.status == 403 {
                return Err(CliError::Server(e.body));
            }
            Err(e.into_cli_error("cancel"))
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_list(
    sc: &ServerClient,
    json_output: bool,
    limit: Option<u32>,
    status: Option<&str>,
    pending_for_me: bool,
    user: Option<&str>,
    database: Option<&str>,
    environment: Option<&str>,
) -> Result<(), CliError> {
    let body = if pending_for_me {
        sc.list_pending_for_me(limit).await?
    } else {
        sc.list_requests(limit, status, database, environment, user)
            .await?
    };
    if json_output {
        println!("{}", serde_json::to_string_pretty(&body)?);
        return Ok(());
    }
    let empty = vec![];
    let requests = body["requests"]
        .as_array()
        .or_else(|| body.as_array())
        .unwrap_or(&empty);
    if requests.is_empty() {
        println!("No requests.");
    } else {
        print_request_list(requests);
    }
    Ok(())
}

async fn run_show(sc: &ServerClient, json_output: bool, id: &str) -> Result<(), CliError> {
    let body = sc.get_request(id).await?;
    if json_output {
        println!("{}", serde_json::to_string_pretty(&body)?);
    } else {
        print_request_detail(&body);
    }
    Ok(())
}

async fn run_resume(
    sc: &ServerClient,
    json_output: bool,
    id: &str,
    output: Option<&std::path::Path>,
    config_results_dir: Option<&Path>,
    result_format: ResultFormat,
) -> Result<(), CliError> {
    // DML re-resume warning
    let req = sc.get_request(id).await?;
    let status = dbward_api_types::requests::RequestStatus::from_json(&req["status"]);
    let operation = req["operation"].as_str().unwrap_or("");
    if !json_output
        && status == dbward_api_types::requests::RequestStatus::ExecutionLost
        && operation == "execute_query"
    {
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
            return Ok(());
        }
    }

    if let Err(e) = sc.resume(id).await {
        if e.status == 409 {
            // Fetch current status for a helpful message
            if let Ok(req) = sc.get_request(id).await {
                use dbward_api_types::requests::RequestStatus;
                let status = RequestStatus::from_json(&req["status"]);
                match status {
                    RequestStatus::Executed => {
                        eprintln!("Already executed. Run: dbward request result {id}");
                    }
                    RequestStatus::Failed => {
                        eprintln!("Request failed. Run: dbward request show {id}");
                    }
                    RequestStatus::Cancelled => {
                        eprintln!("Request was cancelled.");
                    }
                    RequestStatus::Dispatched | RequestStatus::Running => {
                        eprintln!("Already resumed. Waiting for agent...");
                    }
                    RequestStatus::ExecutionLost => {
                        eprintln!("Execution lost. Retry: dbward request resume {id}");
                    }
                    RequestStatus::Pending => {
                        eprintln!("Still pending approval.");
                    }
                    _ => {
                        eprintln!("Request {id} cannot be resumed (status: {status}).");
                    }
                }
            } else {
                eprintln!("Request {id} cannot be resumed yet (may still be pending approval).");
            }
            eprintln!("Check status: dbward request show {id}");
            return Err(CliError::Server("request not ready for resume".into()));
        }
        return Err(e.into_cli_error("resume"));
    }
    let resp = tokio::select! {
        r = workflow::wait_and_resolve(sc, id, true) => r?,
        _ = tokio::signal::ctrl_c() => {
            eprintln!("\nRequest is still running. To check later:");
            eprintln!("  dbward request show {id}");
            eprintln!("  dbward request resume {id}");
            eprintln!("\nTo cancel (if not yet executing):");
            eprintln!("  dbward request cancel {id}");
            return Ok(());
        }
    };
    if json_output {
        println!("{}", serde_json::to_string_pretty(&resp)?);
    } else {
        print_execution_result_formatted(&resp, result_format);
    }
    save_result(id, &resp, output, config_results_dir);
    Ok(())
}

async fn run_result(
    sc: &ServerClient,
    json_output: bool,
    id: &str,
    execution_id: Option<&str>,
    output: Option<&std::path::Path>,
    config_results_dir: Option<&Path>,
    result_format: ResultFormat,
) -> Result<(), CliError> {
    let resp = sc.get_result_content(id, execution_id).await?;
    if json_output {
        println!("{}", serde_json::to_string_pretty(&resp)?);
    } else {
        print_execution_result_formatted(&resp, result_format);
    }
    save_result(id, &resp, output, config_results_dir);
    Ok(())
}

async fn run_executions(
    sc: &ServerClient,
    json_output: bool,
    id: &str,
    limit: u32,
) -> Result<(), CliError> {
    let body = sc.get_executions(id, limit).await?;
    if json_output {
        println!("{}", serde_json::to_string_pretty(&body)?);
    } else if let Some(executions) = body["executions"].as_array() {
        if executions.is_empty() {
            println!("No executions.");
        } else {
            println!(
                "{:<12} {:<12} {:<6} {:<24} ERROR",
                "ID", "STATUS", "STORED", "FINISHED"
            );
            for e in executions {
                let eid = e["id"].as_str().unwrap_or("");
                let stored = if e["has_stored_result"].as_bool().unwrap_or(false) {
                    "yes"
                } else {
                    "no"
                };
                println!(
                    "{:<12} {:<12} {:<6} {:<24} {}",
                    &eid[..12.min(eid.len())],
                    e["status"].as_str().unwrap_or(""),
                    stored,
                    e["finished_at"].as_str().unwrap_or("-"),
                    e["error_message"].as_str().unwrap_or(""),
                );
            }
        }
    }
    Ok(())
}

async fn run_results(sc: &ServerClient, json_output: bool, limit: u32) -> Result<(), CliError> {
    let body = sc.list_results(limit).await?;
    if json_output {
        println!("{}", serde_json::to_string_pretty(&body)?);
    } else if let Some(results) = body["results"].as_array() {
        if results.is_empty() {
            println!("No shared results.");
        } else {
            println!(
                "{:<10} {:<10} {:<12} {:<16} STORED AT",
                "ID", "ENV", "DB", "OPERATION"
            );
            for r in results {
                let rid = r["request_id"].as_str().unwrap_or("");
                println!(
                    "{:<10} {:<10} {:<12} {:<16} {}",
                    &rid[..8.min(rid.len())],
                    r["environment"].as_str().unwrap_or(""),
                    r["database"].as_str().unwrap_or(""),
                    r["operation"].as_str().unwrap_or(""),
                    r["stored_at"].as_str().unwrap_or(""),
                );
            }
        }
    }
    Ok(())
}

/// Resolve a potentially shortened request ID to a full UUID via prefix match.
/// If the ID is already a full UUID (36 chars), return as-is.
async fn resolve_request_id(sc: &ServerClient, id: &str) -> Result<String, CliError> {
    if looks_like_full_uuid(id) {
        return Ok(id.to_string());
    }
    let resp = sc.list_requests(Some(100), None, None, None, None).await?;
    let requests = resp["requests"]
        .as_array()
        .ok_or_else(|| CliError::Server("unexpected response from list_requests".into()))?;
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
            Err(CliError::Server(format!(
                "no request found matching prefix '{id}'{hint}"
            )))
        }
        1 => Ok(matches[0].to_string()),
        _ => Err(CliError::Server(format!(
            "ambiguous prefix '{id}': matches {} requests. Use a longer prefix.",
            matches.len()
        ))),
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
        // 36 chars but no hyphens at right positions
        assert!(!looks_like_full_uuid(
            "550e8400xe29bx41d4xa716x446655440000"
        ));
        // Too long
        assert!(!looks_like_full_uuid(
            "550e8400-e29b-41d4-a716-4466554400001"
        ));
    }
}
