use crate::display::*;
use crate::error::CliError;
use crate::server_client::ServerClient;

pub async fn run_databases(sc: &ServerClient, _json_output: bool) -> Result<(), CliError> {
    let resp = sc.get_json("/api/databases").await?;
    if let Some(dbs) = resp["databases"].as_array() {
        if dbs.is_empty() {
            eprintln!("No databases registered.");
        } else {
            // Group by database name to collect environments
            use std::collections::BTreeMap;
            let mut grouped: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
            for db in dbs {
                let name = db["database"].as_str().unwrap_or("");
                let env = db["environment"].as_str().unwrap_or("");
                grouped.entry(name).or_default().push(env);
            }
            println!("{:<20} ENVIRONMENTS", "NAME");
            println!("{:<20} {}", "----", "------------");
            for (name, envs) in &grouped {
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
