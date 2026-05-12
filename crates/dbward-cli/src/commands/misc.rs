use crate::display::*;
use crate::error::CliError;
use crate::server_client::ServerClient;

pub async fn run_databases(sc: &ServerClient, _json_output: bool) -> Result<(), CliError> {
    let resp = sc.get_json("/api/databases").await?;
    if let Some(dbs) = resp["databases"].as_array() {
        if dbs.is_empty() {
            eprintln!("No databases registered.");
        } else {
            println!("{:<20} ENVIRONMENTS", "NAME");
            println!("{:<20} {}", "----", "------------");
            for db in dbs {
                let name = db["name"].as_str().unwrap_or("");
                let envs: Vec<&str> = db["environments"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
                    .unwrap_or_default();
                println!("{:<20} {}", name, envs.join(", "));
            }
        }
    }
    Ok(())
}

pub async fn run_agents(sc: &ServerClient, json_output: bool) -> Result<(), CliError> {
    let body = sc.get_json("/api/agents").await?;
    if json_output {
        println!("{}", serde_json::to_string_pretty(&body)?);
    } else {
        print_agents_status(&body);
    }
    Ok(())
}
