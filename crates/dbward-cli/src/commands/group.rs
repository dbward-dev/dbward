use clap::Subcommand;
use serde::Serialize;

use crate::error::CliError;
use crate::output::{CliResponse, Column, RenderPlan};
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

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct GroupListOutput {
    pub groups: Vec<String>,
}

#[derive(Serialize)]
pub struct GroupShowOutput {
    pub name: String,
    pub members: Vec<String>,
    #[serde(flatten)]
    pub details: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Command implementations
// ---------------------------------------------------------------------------

pub async fn run_group_list(
    sc: &ServerClient,
) -> Result<CliResponse<GroupListOutput>, CliError> {
    let resp: serde_json::Value = sc.get("/api/groups").await?;
    let groups: Vec<String> = resp
        .get("groups")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let render = if groups.is_empty() {
        RenderPlan::empty_list("groups")
    } else {
        let columns = vec![Column::new("NAME")];
        let rows: Vec<Vec<String>> = groups.iter().map(|g| vec![g.clone()]).collect();
        RenderPlan::table(columns, rows)
    };

    Ok(CliResponse::ok(GroupListOutput { groups }, render))
}

pub async fn run_group_show(
    sc: &ServerClient,
    name: &str,
) -> Result<CliResponse<GroupShowOutput>, CliError> {
    let resp: serde_json::Value = sc.get(&format!("/api/groups/{name}")).await?;

    let members: Vec<String> = resp
        .get("members")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let mut pairs = vec![("Name".into(), name.to_string())];
    if members.is_empty() {
        pairs.push(("Members".into(), "(none)".into()));
    } else {
        pairs.push(("Members".into(), members.join(", ")));
    }

    let output = GroupShowOutput {
        name: name.to_string(),
        members,
        details: resp,
    };

    let render = RenderPlan::key_value(pairs);
    Ok(CliResponse::ok(output, render))
}
