use clap::Subcommand;

use crate::error::CliError;
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

pub async fn run_user(sc: &ServerClient, action: UserAction) -> Result<(), CliError> {
    match action {
        UserAction::Add { id, role, group } => {
            let body = serde_json::json!({
                "id": id,
                "roles": role,
                "groups": group,
            });
            let resp: serde_json::Value = sc.post("/api/users", &body).await?;
            if let Some(token) = resp.get("token").and_then(|v| v.as_str()) {
                println!("{token}");
            }
            if let Some(roles) = resp.get("roles") {
                eprintln!("Roles: {roles}");
            }
            if let Some(groups) = resp.get("groups") {
                eprintln!("Groups: {groups}");
            }
            Ok(())
        }
        UserAction::Update {
            id,
            role,
            add_role,
            rm_role,
            add_group,
            rm_group,
            slack_user_id,
        } => {
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
            if let Some(ref sid) = slack_user_id {
                body.insert("slack_user_id".into(), serde_json::json!(sid));
            }

            if body.is_empty() {
                return Err(CliError::Config("no fields to update".into()));
            }

            sc.patch(&format!("/api/users/{id}"), &body).await?;
            eprintln!("User '{id}' updated.");
            Ok(())
        }
        UserAction::Show { id } => {
            let resp: serde_json::Value = sc.get(&format!("/api/users/{id}")).await?;
            println!("{}", serde_json::to_string_pretty(&resp).unwrap());
            Ok(())
        }
        UserAction::List => {
            let resp: serde_json::Value = sc.get("/api/users").await?;
            if let Some(users) = resp.get("users").and_then(|v| v.as_array()) {
                for u in users {
                    let id = u.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                    let status = u.get("status").and_then(|v| v.as_str()).unwrap_or("?");
                    println!("{id}\t{status}");
                }
            }
            Ok(())
        }
        UserAction::Suspend { id } => {
            let resp: serde_json::Value = sc
                .post(&format!("/api/users/{id}/suspend"), &serde_json::json!({}))
                .await?;
            let revoked = resp
                .get("revoked_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            eprintln!("User '{id}' suspended. {revoked} token(s) revoked.");
            Ok(())
        }
        UserAction::Activate { id } => {
            sc.post(&format!("/api/users/{id}/activate"), &serde_json::json!({}))
                .await?;
            eprintln!("User '{id}' activated.");
            Ok(())
        }
        UserAction::Rm { id } => {
            sc.delete(&format!("/api/users/{id}")).await?;
            eprintln!("User '{id}' deleted.");
            Ok(())
        }
        UserAction::ReissueInitialToken { id } => {
            let resp: serde_json::Value = sc
                .post(
                    &format!("/api/users/{id}/reissue-initial-token"),
                    &serde_json::json!({}),
                )
                .await?;

            let delivery = resp
                .get("delivery_status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            eprintln!("Initial token reissued for user '{id}'.");

            if delivery == "delivered" {
                eprintln!("  Delivery: Slack DM sent successfully.");
            } else if let Some(token) = resp.get("token").and_then(|v| v.as_str()) {
                if delivery == "failed" {
                    eprintln!("  ⚠ Slack DM delivery failed.");
                } else {
                    eprintln!("  Slack not configured.");
                }
                println!("{token}");
                eprintln!("  Configure: export DBWARD_API_TOKEN=<token above>");
            }

            if let Some(token_id) = resp.get("reissued_token_id").and_then(|v| v.as_str()) {
                eprintln!("  Token ID: {token_id}");
            }

            Ok(())
        }
    }
}
