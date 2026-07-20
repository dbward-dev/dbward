use clap::Subcommand;
use serde::Serialize;

use crate::error::CliError;
use crate::output::{CliResponse, Column, RenderPlan, StderrLine};
use crate::server_client::ServerClient;

#[derive(Subcommand)]
pub enum UserAction {
    /// Create a new user and generate an initial token
    Add {
        /// User ID
        id: String,
        /// Roles to assign (comma-separated)
        #[arg(long, value_delimiter = ',')]
        role: Vec<String>,
        /// Groups to add to (comma-separated)
        #[arg(long, value_delimiter = ',')]
        group: Vec<String>,
    },
    /// Update user roles/groups
    Update {
        /// User ID
        id: String,
        /// Set roles (full replace, comma-separated)
        #[arg(long, value_delimiter = ',')]
        role: Vec<String>,
        /// Add roles
        #[arg(long, value_delimiter = ',')]
        add_role: Vec<String>,
        /// Remove roles
        #[arg(long, value_delimiter = ',')]
        rm_role: Vec<String>,
        /// Add to groups
        #[arg(long, value_delimiter = ',')]
        add_group: Vec<String>,
        /// Remove from groups
        #[arg(long, value_delimiter = ',')]
        rm_group: Vec<String>,
        /// Link Slack user ID
        #[arg(long)]
        slack_user_id: Option<String>,
    },
    /// Show user details
    Show {
        /// User ID
        id: String,
    },
    /// List users
    List,
    /// Suspend a user (revokes all tokens)
    Suspend {
        /// User ID
        id: String,
    },
    /// Activate a suspended user
    Activate {
        /// User ID
        id: String,
    },
    /// Remove a user (soft delete)
    Rm {
        /// User ID
        id: String,
    },
    /// Reissue a user's initial token (admin only)
    ReissueInitialToken {
        /// User ID
        id: String,
    },
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct UserAddOutput {
    pub token: String,
    pub id: String,
    pub roles: Vec<String>,
    pub groups: Vec<String>,
}

#[derive(Serialize)]
pub struct UserListOutput {
    pub users: Vec<UserSummary>,
}

#[derive(Serialize)]
pub struct UserSummary {
    pub id: String,
    pub status: String,
}

#[derive(Serialize)]
pub struct UserShowOutput {
    pub id: String,
    #[serde(flatten)]
    pub details: serde_json::Value,
}

#[derive(Serialize)]
pub struct UserSuspendOutput {
    pub id: String,
    pub revoked_tokens: u64,
}

#[derive(Serialize)]
pub struct UserActivateOutput {
    pub id: String,
}

#[derive(Serialize)]
pub struct UserUpdateOutput {
    pub id: String,
}

#[derive(Serialize)]
pub struct UserRmOutput {
    pub id: String,
}

#[derive(Serialize)]
pub struct UserReissueTokenOutput {
    pub id: String,
    pub token: Option<String>,
    pub delivery_status: String,
    pub reissued_token_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Command implementations
// ---------------------------------------------------------------------------

pub async fn run_user_add(
    sc: &ServerClient,
    id: &str,
    role: &[String],
    group: &[String],
) -> Result<CliResponse<UserAddOutput>, CliError> {
    let body = serde_json::json!({
        "id": id,
        "roles": role,
        "groups": group,
    });
    let resp: serde_json::Value = sc.post("/api/users", &body).await?;

    let token = resp
        .get("token")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let roles: Vec<String> = resp["roles"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let groups: Vec<String> = resp["groups"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let output = UserAddOutput {
        token: token.clone(),
        id: id.to_string(),
        roles: roles.clone(),
        groups: groups.clone(),
    };

    let mut stderr = vec![StderrLine::Status(format!("User '{id}' created."))];
    if !roles.is_empty() {
        stderr.push(StderrLine::Info("Roles".into(), roles.join(", ")));
    }
    if !groups.is_empty() {
        stderr.push(StderrLine::Info("Groups".into(), groups.join(", ")));
    }

    let render = RenderPlan::raw_with_info(token, stderr);
    Ok(CliResponse::ok(output, render))
}

pub async fn run_user_list(
    sc: &ServerClient,
) -> Result<CliResponse<UserListOutput>, CliError> {
    let resp: serde_json::Value = sc.get("/api/users").await?;
    let users_arr = resp
        .get("users")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let summaries: Vec<UserSummary> = users_arr
        .iter()
        .map(|u| UserSummary {
            id: u.get("id").and_then(|v| v.as_str()).unwrap_or("?").to_string(),
            status: u.get("status").and_then(|v| v.as_str()).unwrap_or("?").to_string(),
        })
        .collect();

    let render = if summaries.is_empty() {
        RenderPlan::empty_list("users")
    } else {
        let columns = vec![
            Column::new("ID").with_max_width(30),
            Column::new("Status").with_max_width(12),
        ];
        let rows: Vec<Vec<String>> = summaries
            .iter()
            .map(|u| vec![u.id.clone(), u.status.clone()])
            .collect();
        RenderPlan::table(columns, rows)
    };

    Ok(CliResponse::ok(UserListOutput { users: summaries }, render))
}

pub async fn run_user_show(
    sc: &ServerClient,
    id: &str,
) -> Result<CliResponse<UserShowOutput>, CliError> {
    let resp: serde_json::Value = sc.get(&format!("/api/users/{id}")).await?;

    let mut pairs = vec![("ID".into(), id.to_string())];

    if let Some(status) = resp.get("status").and_then(|v| v.as_str()) {
        pairs.push(("Status".into(), status.to_string()));
    }
    if let Some(roles) = resp.get("roles").and_then(|v| v.as_array()) {
        let role_strs: Vec<&str> = roles.iter().filter_map(|v| v.as_str()).collect();
        if !role_strs.is_empty() {
            pairs.push(("Roles".into(), role_strs.join(", ")));
        }
    }
    if let Some(groups) = resp.get("groups").and_then(|v| v.as_array()) {
        let group_strs: Vec<&str> = groups.iter().filter_map(|v| v.as_str()).collect();
        if !group_strs.is_empty() {
            pairs.push(("Groups".into(), group_strs.join(", ")));
        }
    }
    if let Some(slack) = resp.get("slack_user_id").and_then(|v| v.as_str()) {
        pairs.push(("Slack".into(), slack.to_string()));
    }
    if let Some(created) = resp.get("created_at").and_then(|v| v.as_str()) {
        pairs.push(("Created".into(), created.to_string()));
    }

    let output = UserShowOutput {
        id: id.to_string(),
        details: resp,
    };

    let render = RenderPlan::key_value(pairs);
    Ok(CliResponse::ok(output, render))
}

#[allow(clippy::too_many_arguments)]
pub async fn run_user_update(
    sc: &ServerClient,
    id: &str,
    role: &[String],
    add_role: &[String],
    rm_role: &[String],
    add_group: &[String],
    rm_group: &[String],
    slack_user_id: Option<&str>,
) -> Result<CliResponse<UserUpdateOutput>, CliError> {
    let mut body = serde_json::Map::new();
    if !role.is_empty() {
        body.insert("roles".into(), serde_json::json!(role));
    }
    if !add_role.is_empty() {
        body.insert("add_roles".into(), serde_json::json!(add_role));
    }
    if !rm_role.is_empty() {
        body.insert("rm_roles".into(), serde_json::json!(rm_role));
    }
    if !add_group.is_empty() {
        body.insert("add_groups".into(), serde_json::json!(add_group));
    }
    if !rm_group.is_empty() {
        body.insert("rm_groups".into(), serde_json::json!(rm_group));
    }
    if let Some(sid) = slack_user_id {
        body.insert("slack_user_id".into(), serde_json::json!(sid));
    }

    if body.is_empty() {
        return Err(CliError::Config("no fields to update".into()));
    }

    sc.patch(&format!("/api/users/{id}"), &body).await?;

    let output = UserUpdateOutput { id: id.to_string() };
    let render = RenderPlan::status(format!("User '{id}' updated."));
    Ok(CliResponse::ok(output, render))
}

pub async fn run_user_suspend(
    sc: &ServerClient,
    id: &str,
) -> Result<CliResponse<UserSuspendOutput>, CliError> {
    let resp: serde_json::Value = sc
        .post(&format!("/api/users/{id}/suspend"), &serde_json::json!({}))
        .await?;
    let revoked = resp
        .get("revoked_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let output = UserSuspendOutput {
        id: id.to_string(),
        revoked_tokens: revoked,
    };
    let render = RenderPlan::status(format!(
        "User '{id}' suspended. {revoked} token(s) revoked."
    ));
    Ok(CliResponse::ok(output, render))
}

pub async fn run_user_activate(
    sc: &ServerClient,
    id: &str,
) -> Result<CliResponse<UserActivateOutput>, CliError> {
    sc.post(&format!("/api/users/{id}/activate"), &serde_json::json!({}))
        .await?;

    let output = UserActivateOutput { id: id.to_string() };
    let render = RenderPlan::status(format!("User '{id}' activated."));
    Ok(CliResponse::ok(output, render))
}

pub async fn run_user_rm(
    sc: &ServerClient,
    id: &str,
) -> Result<CliResponse<UserRmOutput>, CliError> {
    sc.delete(&format!("/api/users/{id}")).await?;

    let output = UserRmOutput { id: id.to_string() };
    let render = RenderPlan::status(format!("User '{id}' deleted."));
    Ok(CliResponse::ok(output, render))
}

#[allow(clippy::collapsible_if)]
pub async fn run_user_reissue_token(
    sc: &ServerClient,
    id: &str,
) -> Result<CliResponse<UserReissueTokenOutput>, CliError> {
    let resp: serde_json::Value = sc
        .post(
            &format!("/api/users/{id}/reissue-initial-token"),
            &serde_json::json!({}),
        )
        .await?;

    let delivery = resp
        .get("delivery_status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let token = resp.get("token").and_then(|v| v.as_str()).map(String::from);
    let reissued_token_id = resp
        .get("reissued_token_id")
        .and_then(|v| v.as_str())
        .map(String::from);

    let output = UserReissueTokenOutput {
        id: id.to_string(),
        token: token.clone(),
        delivery_status: delivery.clone(),
        reissued_token_id: reissued_token_id.clone(),
    };

    let mut stderr = vec![StderrLine::Status(format!(
        "Initial token reissued for user '{id}'."
    ))];

    if delivery == "delivered" {
        stderr.push(StderrLine::Info(
            "Delivery".into(),
            "Slack DM sent successfully.".into(),
        ));
    } else if delivery == "failed" {
        stderr.push(StderrLine::Warn("Slack DM delivery failed.".into()));
    } else {
        stderr.push(StderrLine::Info("Delivery".into(), "Slack not configured.".into()));
    }

    if let Some(ref tid) = reissued_token_id {
        stderr.push(StderrLine::Info("Token ID".into(), tid.clone()));
    }

    if delivery != "delivered" {
        if let Some(ref t) = token {
            stderr.push(StderrLine::Hint(
                "Configure: export DBWARD_API_TOKEN=<token above>".into(),
            ));
            let render = RenderPlan::raw_with_info(t.clone(), stderr);
            return Ok(CliResponse::ok(output, render));
        }
    }

    let render = RenderPlan {
        stdout: crate::output::StdoutRender::None,
        stderr,
    };
    Ok(CliResponse::ok(output, render))
}
