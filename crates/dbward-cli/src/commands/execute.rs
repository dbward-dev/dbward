use std::path::Path;

use crate::display::*;
use crate::error::CliError;
use crate::server_client::{CreateRequest, ServerClient};

use super::helpers::{self, build_request_metadata, save_result};
use super::workflow::{self, Outcome};

#[allow(clippy::too_many_arguments)]
pub async fn run_execute(
    sc: &ServerClient,
    db_name: &str,
    env_str: &str,
    json_output: bool,
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
    result_format: ResultFormat,
    timeout: Option<u64>,
    yes: bool,
) -> Result<(), CliError> {
    if emergency && reason.is_none() {
        return Err(CliError::Config("--emergency requires --reason".into()));
    }
    if no_result_store {
        eprintln!(
            "⚠ --no-result-store: query result will not be stored. If you disconnect, it cannot be recovered.
  Note: request metadata and SQL text are always retained for audit/approval."
        );
    }

    helpers::confirm_submission(
        &helpers::SubmissionSummary {
            operation: "execute_query",
            database: db_name,
            environment: env_str,
            detail: sql,
            emergency,
        },
        yes || json_output,
    )?;

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
            save_result(&request_id, &result, output, config_results_dir);
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
    }
    Ok(())
}
