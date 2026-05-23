use clap::Subcommand;

use crate::error::CliError;
use crate::server_client::ServerClient;

#[derive(Subcommand)]
pub enum UserAction {
    /// Update your user profile
    Update {
        /// Link your Slack user ID (e.g. U02CR3TMKKJ)
        #[arg(long)]
        slack_user_id: Option<String>,
    },
}

pub async fn run_user(sc: &ServerClient, action: UserAction) -> Result<(), CliError> {
    match action {
        UserAction::Update { slack_user_id } => {
            if slack_user_id.is_none() {
                return Err(CliError::Config(
                    "no fields to update (use --slack-user-id)".into(),
                ));
            }

            // GET /api/me to get subject_id
            let me: serde_json::Value = sc.get("/api/me").await?;
            let subject_id = me["subject_id"]
                .as_str()
                .ok_or_else(|| CliError::Server("missing subject_id in /api/me".into()))?;

            // PATCH /api/users/{id}
            let mut body = serde_json::Map::new();
            if let Some(ref sid) = slack_user_id {
                body.insert(
                    "slack_user_id".into(),
                    serde_json::Value::String(sid.clone()),
                );
            }

            let resp: serde_json::Value =
                sc.patch(&format!("/api/users/{subject_id}"), &body).await?;

            if let Some(sid) = resp.get("slack_user_id").and_then(|v| v.as_str()) {
                eprintln!("Slack user ID linked: {sid}");
            } else {
                eprintln!("User updated.");
            }

            Ok(())
        }
    }
}
