use clap::Subcommand;

use crate::error::CliError;
use crate::server_client::ServerClient;

#[derive(Subcommand)]
pub enum ResultAction {
    List,
    Get { id: String },
}

pub async fn run_result(sc: &ServerClient, json_output: bool, action: ResultAction) -> Result<(), CliError> {
    match action {
        ResultAction::List => {
            let body = sc.list_results().await?;
            if json_output {
                println!("{}", serde_json::to_string_pretty(&body)?);
            } else if let Some(results) = body["results"].as_array() {
                if results.is_empty() {
                    println!("No shared results.");
                } else {
                    println!("{:<10} {:<12} {:<10} {:<12} DETAIL", "ID", "USER", "ENV", "DB");
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
        ResultAction::Get { ref id } => {
            let body = sc.get_result_content(id).await?;
            println!("{}", serde_json::to_string_pretty(&body)?);
            Ok(())
        }
    }
}
