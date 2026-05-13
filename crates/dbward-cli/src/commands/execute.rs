use std::path::Path;

use crate::display::*;
use crate::error::CliError;
use crate::server_client::{CreateRequest, ServerClient};

use super::helpers::{build_request_metadata, save_result};

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
    no_store: bool,
) -> Result<(), CliError> {
    if emergency && reason.is_none() {
        return Err(CliError::Config("--emergency requires --reason".into()));
    }
    let metadata = build_request_metadata(ticket, repo);
    let sw = if share_with.is_empty() {
        None
    } else {
        Some(share_with)
    };
    let (id, status, approvers) = sc
        .create_request(CreateRequest {
            operation: "execute_query",
            environment: env_str,
            database: db_name,
            detail: sql,
            emergency,
            reason,
            metadata: metadata.as_ref(),
            idempotency_key,
            share_with: sw,
            no_store,
        })
        .await?;
    if no_store {
        eprintln!(
            "⚠ --no-store: result will not be persisted. If you disconnect, it cannot be recovered."
        );
    }

    match status.as_str() {
        "dispatched" | "break_glass" | "running" => {
            let resp = sc.wait_for_result(&id).await?;
            if json_output {
                println!("{}", serde_json::to_string_pretty(&resp)?);
            } else {
                print_execution_result(&resp);
            }
            save_result(&id, &resp, output, no_save);
        }
        "executed" | "failed" => {
            let resp = sc.get_terminal_result(&id).await?;
            if json_output {
                println!("{}", serde_json::to_string_pretty(&resp)?);
            } else {
                print_execution_result(&resp);
            }
            save_result(&id, &resp, output, no_save);
        }
        "approved" | "auto_approved" => {
            eprintln!("Request {id} is approved but not yet dispatched.");
            eprintln!("Run: dbward request resume {id}");
        }
        "pending" => {
            eprintln!("Request {id} requires approval.");
            if !approvers.is_empty() {
                eprintln!("  Approvers: {}", approvers.join(", "));
            }
            eprintln!("Run: dbward request resume {id}");
            std::process::exit(2);
        }
        _ => {
            return Err(CliError::Server(format!("unexpected status: {status}")));
        }
    }
    Ok(())
}
