use std::collections::BTreeMap;

use serde::Serialize;

use crate::display::{format_duration_ago, format_duration_short};
use crate::output::CliError;
use crate::output::{CliResponse, Column, RenderPlan, StderrLine, StdoutRender};
use crate::server_client::ServerClient;

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct DatabasesOutput {
    pub databases: Vec<DatabaseEntry>,
}

#[derive(Serialize)]
pub struct DatabaseEntry {
    pub name: String,
    pub environments: Vec<String>,
}

#[derive(Serialize)]
pub struct AgentsOutput {
    pub agents: Vec<AgentEntry>,
}

#[derive(Serialize)]
pub struct AgentEntry {
    pub id: String,
    pub status: String,
    pub in_flight: i64,
    pub max_concurrent: i64,
    pub last_poll_ago_secs: i64,
    pub uptime_secs: i64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub active_jobs: Vec<AgentJob>,
}

#[derive(Serialize)]
pub struct AgentJob {
    pub request_id: String,
    pub operation: String,
}

// ---------------------------------------------------------------------------
// Command implementations
// ---------------------------------------------------------------------------

pub async fn run_databases(sc: &ServerClient) -> Result<CliResponse<DatabasesOutput>, CliError> {
    let resp = sc.get_json("/api/databases").await?;
    let dbs = resp["databases"].as_array().cloned().unwrap_or_default();

    if dbs.is_empty() {
        let output = DatabasesOutput { databases: vec![] };
        let render = RenderPlan::empty_list("databases");
        return Ok(CliResponse::ok(output, render));
    }

    let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for db in &dbs {
        let name = db["database"].as_str().unwrap_or("").to_string();
        let env = db["environment"].as_str().unwrap_or("").to_string();
        grouped.entry(name).or_default().push(env);
    }

    let databases: Vec<DatabaseEntry> = grouped
        .into_iter()
        .map(|(name, environments)| DatabaseEntry { name, environments })
        .collect();

    let columns = vec![
        Column::new("NAME").with_max_width(20),
        Column::new("ENVIRONMENTS"),
    ];
    let rows: Vec<Vec<String>> = databases
        .iter()
        .map(|d| vec![d.name.clone(), d.environments.join(", ")])
        .collect();
    let render = RenderPlan::table(columns, rows);

    Ok(CliResponse::ok(DatabasesOutput { databases }, render))
}

pub async fn run_agents(sc: &ServerClient) -> Result<CliResponse<AgentsOutput>, CliError> {
    let body = sc.get_json("/api/agents").await?;
    let agents_arr = body["agents"].as_array().cloned().unwrap_or_default();

    if agents_arr.is_empty() {
        let output = AgentsOutput { agents: vec![] };
        let render = RenderPlan::empty_list("agents");
        return Ok(CliResponse::ok(output, render));
    }

    let agents: Vec<AgentEntry> = agents_arr
        .iter()
        .map(|a| {
            let active_jobs = a["active_jobs"]
                .as_array()
                .map(|jobs| {
                    jobs.iter()
                        .map(|j| AgentJob {
                            request_id: j["request_id"].as_str().unwrap_or("?").to_string(),
                            operation: j["operation"].as_str().unwrap_or("?").to_string(),
                        })
                        .collect()
                })
                .unwrap_or_default();

            AgentEntry {
                id: a["id"].as_str().unwrap_or("?").to_string(),
                status: a["status"].as_str().unwrap_or("?").to_string(),
                in_flight: a["in_flight"].as_i64().unwrap_or(0),
                max_concurrent: a["max_concurrent"].as_i64().unwrap_or(1),
                last_poll_ago_secs: a["last_poll_ago_secs"].as_i64().unwrap_or(9999),
                uptime_secs: a["uptime_secs"].as_i64().unwrap_or(0),
                active_jobs,
            }
        })
        .collect();

    let columns = vec![
        Column::new("AGENT").with_max_width(20),
        Column::new("STATUS").with_max_width(10),
        Column::new("LOAD").with_max_width(7),
        Column::new("LAST SEEN").with_max_width(12),
        Column::new("UPTIME").with_max_width(10),
    ];
    let rows: Vec<Vec<String>> = agents
        .iter()
        .map(|a| {
            vec![
                a.id.clone(),
                a.status.clone(),
                format!("{}/{}", a.in_flight, a.max_concurrent),
                format_duration_ago(a.last_poll_ago_secs),
                format_duration_short(a.uptime_secs),
            ]
        })
        .collect();

    // Build active jobs section as extra stderr lines
    let mut stderr = Vec::new();
    let has_active: Vec<&AgentEntry> = agents
        .iter()
        .filter(|a| !a.active_jobs.is_empty())
        .collect();
    if !has_active.is_empty() {
        stderr.push(StderrLine::Status("\nActive jobs:".into()));
        for a in has_active {
            stderr.push(StderrLine::Status(format!("  {}:", a.id)));
            for j in &a.active_jobs {
                let short_id: String = j.request_id.chars().take(8).collect();
                stderr.push(StderrLine::Status(format!(
                    "    {}  {}",
                    short_id, j.operation
                )));
            }
        }
    }

    let render = RenderPlan {
        stdout: StdoutRender::Table { columns, rows },
        stderr,
    };

    Ok(CliResponse::ok(AgentsOutput { agents }, render))
}
