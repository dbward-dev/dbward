use std::path::PathBuf;

use clap::Subcommand;

use crate::display::*;
use crate::error::CliError;
use crate::server_client::ServerClient;

use super::helpers::{load_result, save_result};

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
    Show { id: String },
    Approve {
        id: String,
        #[arg(long)]
        comment: Option<String>,
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
        #[arg(long)]
        no_save: bool,
    },
    Result { id: String },
}

pub async fn run_request(
    sc: &ServerClient,
    json_output: bool,
    action: RequestAction,
    database: Option<&str>,
    environment: Option<&str>,
) -> Result<(), CliError> {
    match action {
        RequestAction::Approve { id, comment } => run_approve(sc, json_output, &id, comment.as_deref()).await,
        RequestAction::Reject { id, reason } => run_reject(sc, json_output, &id, reason.as_deref()).await,
        RequestAction::Cancel { id, reason } => run_cancel(sc, json_output, &id, reason.as_deref()).await,
        RequestAction::List { limit, status, pending_for_me, user } => {
            run_list(sc, json_output, limit, status.as_deref(), pending_for_me, user.as_deref(), database, environment).await
        }
        RequestAction::Show { id } => run_show(sc, json_output, &id).await,
        RequestAction::Resume { id, output, no_save } => run_resume(sc, json_output, &id, output.as_deref(), no_save).await,
        RequestAction::Result { id } => run_result(sc, json_output, &id).await,
    }
}

async fn run_approve(sc: &ServerClient, json_output: bool, id: &str, comment: Option<&str>) -> Result<(), CliError> {
    match sc.approve(id, comment).await {
        Ok(body) => {
            if json_output {
                println!("{}", serde_json::to_string_pretty(&body)?);
            } else {
                print_approve_result(&body, id);
            }
            Ok(())
        }
        Err(e) => {
            if e.status == 404 { return Err(CliError::Server(format!("Request {id} not found"))); }
            let body_lower = e.body.to_lowercase();
            if e.status == 409 && (body_lower.contains("already approved") || body_lower.contains("already dispatched")) {
                return Err(CliError::Server(format!("Request is already approved. Run: dbward request resume {id}")));
            }
            if e.status == 403 { return Err(CliError::Server(e.body)); }
            Err(e.into_cli_error("approve"))
        }
    }
}

async fn run_reject(sc: &ServerClient, json_output: bool, id: &str, reason: Option<&str>) -> Result<(), CliError> {
    match sc.reject(id, reason).await {
        Ok(body) => {
            if json_output { println!("{}", serde_json::to_string_pretty(&body)?); }
            else { println!("Rejected: {id}"); }
            Ok(())
        }
        Err(e) => {
            if e.status == 404 { return Err(CliError::Server(format!("Request {id} not found"))); }
            if e.status == 403 { return Err(CliError::Server(e.body)); }
            Err(e.into_cli_error("reject"))
        }
    }
}

#[allow(clippy::collapsible_if)]
async fn run_cancel(sc: &ServerClient, json_output: bool, id: &str, reason: Option<&str>) -> Result<(), CliError> {
    let req_info = sc.get_json(&format!("/api/requests/{id}")).await;
    if !json_output {
        if let Ok(info) = &req_info {
            if info["status"].as_str() == Some("running") {
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
            if json_output { println!("{}", serde_json::to_string_pretty(&body)?); }
            else { println!("Cancelled: {id}"); }
            Ok(())
        }
        Err(e) => {
            if e.status == 404 { return Err(CliError::Server(format!("Request {id} not found"))); }
            if e.status == 403 { return Err(CliError::Server(e.body)); }
            Err(e.into_cli_error("cancel"))
        }
    }
}

async fn run_list(sc: &ServerClient, json_output: bool, limit: Option<u32>, status: Option<&str>, pending_for_me: bool, user: Option<&str>, database: Option<&str>, environment: Option<&str>) -> Result<(), CliError> {
    let body = if pending_for_me {
        sc.list_pending_for_me(limit).await?
    } else {
        sc.list_requests(limit, status, database, environment, user).await?
    };
    if json_output {
        println!("{}", serde_json::to_string_pretty(&body)?);
        return Ok(());
    }
    let empty = vec![];
    let requests = body["requests"].as_array().or_else(|| body.as_array()).unwrap_or(&empty);
    if requests.is_empty() { println!("No requests."); } else { print_request_list(requests); }
    Ok(())
}

async fn run_show(sc: &ServerClient, json_output: bool, id: &str) -> Result<(), CliError> {
    let body = sc.get_request(id).await?;
    if json_output { println!("{}", serde_json::to_string_pretty(&body)?); }
    else { print_request_detail(&body); }
    Ok(())
}

async fn run_resume(sc: &ServerClient, json_output: bool, id: &str, output: Option<&std::path::Path>, no_save: bool) -> Result<(), CliError> {
    // DML re-dispatch warning
    let req = sc.get_request(id).await?;
    let status = req["status"].as_str().unwrap_or("");
    let operation = req["operation"].as_str().unwrap_or("");
    if !json_output && status == "execution_lost" && operation == "execute_query" {
        let detail = req["detail"].as_str().unwrap_or("");
        eprintln!("⚠️  WARNING: This request previously failed with execution_lost.");
        eprintln!("   The previous execution may have partially completed.");
        let sql_preview: String = detail.chars().take(80).collect();
        eprintln!("   SQL: {sql_preview}");
        eprintln!("   Re-dispatching may cause DUPLICATE execution.");
        eprint!("   Continue? [y/N] ");
        std::io::Write::flush(&mut std::io::stderr()).ok();
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).ok();
        if !input.trim().eq_ignore_ascii_case("y") {
            eprintln!("Aborted.");
            return Ok(());
        }
    }

    if let Err(e) = sc.dispatch(id).await {
        if e.status == 409 {
            eprintln!("Request {id} cannot be dispatched yet (may still be pending approval).");
            eprintln!("Check status: dbward request show {id}");
            return Err(CliError::Server("request not ready for dispatch".into()));
        }
        return Err(e.into_cli_error("dispatch"));
    }
    let resp = sc.wait_for_result(id).await?;
    if json_output { println!("{}", serde_json::to_string_pretty(&resp)?); }
    else { print_execution_result(&resp); }
    save_result(id, &resp, output, no_save);
    Ok(())
}

async fn run_result(sc: &ServerClient, json_output: bool, id: &str) -> Result<(), CliError> {
    match load_result(id) {
        Ok(resp) => {
            if json_output { println!("{}", serde_json::to_string_pretty(&resp)?); }
            else { print_execution_result(&resp); }
        }
        Err(_) => {
            let resp = sc.get_result_content(id).await?;
            if json_output { println!("{}", serde_json::to_string_pretty(&resp)?); }
            else {
                let wrapped = serde_json::json!({"success": true, "result": resp});
                print_execution_result(&wrapped);
            }
        }
    }
    Ok(())
}
