use clap::Subcommand;

use crate::display::{ResultFormat, print_execution_result_formatted};
use crate::error::CliError;
use crate::server_client::ServerClient;

#[derive(Subcommand)]
pub enum ResultAction {
    List,
    Get {
        id: String,
        /// Result display format
        #[arg(long, value_enum, default_value = "table")]
        result_format: ResultFormat,
    },
}

pub async fn run_result(
    sc: &ServerClient,
    json_output: bool,
    action: ResultAction,
) -> Result<(), CliError> {
    match action {
        ResultAction::List => {
            let body = sc.list_results().await?;
            if json_output {
                println!("{}", serde_json::to_string_pretty(&body)?);
            } else if let Some(results) = body["results"].as_array() {
                if results.is_empty() {
                    println!("No shared results.");
                } else {
                    println!(
                        "{:<10} {:<12} {:<10} {:<12} DETAIL",
                        "ID", "USER", "ENV", "DB"
                    );
                    for r in results {
                        let rid = r["request_id"].as_str().unwrap_or("");
                        println!(
                            "{:<10} {:<12} {:<10} {:<12} {}",
                            &rid[..8.min(rid.len())],
                            r["created_by"].as_str().unwrap_or(""),
                            r["environment"].as_str().unwrap_or(""),
                            r["database"].as_str().unwrap_or(""),
                            r["detail"].as_str().unwrap_or(""),
                        );
                    }
                }
            }
            Ok(())
        }
        ResultAction::Get {
            ref id,
            result_format,
        } => {
            let body = sc.get_result_content(id).await?;
            if json_output {
                println!("{}", serde_json::to_string_pretty(&body)?);
            } else {
                let resp = if body.get("success").is_some() {
                    body
                } else {
                    serde_json::json!({"success": true, "result": body})
                };
                print_execution_result_formatted(&resp, result_format);
            }
            Ok(())
        }
    }
}
