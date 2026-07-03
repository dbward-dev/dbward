use clap::Subcommand;

use crate::error::CliError;
use crate::server_client::ServerClient;

#[derive(Subcommand)]
pub enum GroupAction {
    /// List all groups
    List,
    /// Show group members
    Show {
        /// Group name
        name: String,
    },
}

pub async fn run_group(sc: &ServerClient, action: GroupAction) -> Result<(), CliError> {
    match action {
        GroupAction::List => {
            let resp: serde_json::Value = sc.get("/api/groups").await?;
            if let Some(groups) = resp.get("groups").and_then(|v| v.as_array()) {
                for g in groups {
                    if let Some(name) = g.as_str() {
                        println!("{name}");
                    }
                }
            }
            Ok(())
        }
        GroupAction::Show { name } => {
            let resp: serde_json::Value = sc.get(&format!("/api/groups/{name}")).await?;
            println!("{}", serde_json::to_string_pretty(&resp).unwrap());
            Ok(())
        }
    }
}
