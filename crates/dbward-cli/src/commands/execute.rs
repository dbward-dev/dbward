use std::path::Path;

use crate::display::*;
use crate::error::CliError;
use crate::server_client::{CreateRequest, ServerClient};

use super::helpers::{build_request_metadata, save_result};
use super::workflow::{self, Outcome};

#[allow(clippy::too_many_arguments)]
pub async fn run_execute(
    sc: &ServerClient,
    db_name: &str,
    env_str: &str,
    json_output: bool,
    sql: &str,
    emergency: bool,
    reason: Option<&str>,
    output: Option<&Path>,
    no_save: bool,
    ticket: Option<&str>,
    repo: Option<&str>,
    idempotency_key: Option<&str>,
    share_with: &[String],
    no_persist: bool,
    result_format: ResultFormat,
    timeout: Option<u64>,
) -> Result<(), CliError> {
    if emergency && reason.is_none() {
        return Err(CliError::Config("--emergency requires --reason".into()));
    }
    if no_persist {
        eprintln!(
            "⚠ --no-persist: result will not be persisted. If you disconnect, it cannot be recovered."
        );
    }

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
        reason,
        metadata: metadata.as_ref(),
        idempotency_key,
        share_with: sw,
        no_store: no_persist,
    };

    let outcome = if let Some(secs) = timeout {
        tokio::select! {
            result = workflow::submit_and_orchestrate(sc, request, true) => result?,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\nInterrupted. If a request was created, check: dbward request list");
                return Ok(());
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(secs)) => {
                eprintln!("Timed out after {secs}s waiting for completion.");
                eprintln!("Request may still be in progress. Check: dbward request list");
                eprintln!("Use --timeout to increase the wait time.");
                std::process::exit(124);
            }
        }
    } else {
        tokio::select! {
            result = workflow::submit_and_orchestrate(sc, request, true) => result?,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\nInterrupted. If a request was created, check: dbward request list");
                return Ok(());
            }
        }
    };

    match outcome {
        Outcome::Completed { request_id, result } => {
            if json_output {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                print_execution_result_formatted(&result, result_format);
            }
            save_result(&request_id, &result, output, no_save);
        }
        Outcome::Pending {
            request_id,
            approvers,
        } => {
            eprintln!("Request {request_id} requires approval.");
            if !approvers.is_empty() {
                eprintln!("  Approvers: {}", approvers.join(", "));
            }
            eprintln!("Run: dbward request resume {request_id}");
            std::process::exit(2);
        }
        Outcome::Approved { request_id } => {
            eprintln!("Request {request_id} is approved but not yet resumed.");
            eprintln!("Run: dbward request resume {request_id}");
        }
        Outcome::TimedOut { request_id, .. } => {
            eprintln!("Request {request_id} is still executing (timed out).");
            eprintln!("Run: dbward request resume {request_id}");
        }
    }
    Ok(())
}
