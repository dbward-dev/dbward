use chrono::{NaiveDate, Utc};
use clap::Subcommand;
use serde_json::{Value, json};

use crate::error::CliError;
use crate::server_client::ServerClient;

fn parse_subject_type(s: &str) -> Result<String, String> {
    match s {
        "user" | "agent" => Ok(s.to_string()),
        _ => Err("must be 'user' or 'agent'".into()),
    }
}

fn parse_status(s: &str) -> Result<String, String> {
    match s {
        "active" | "revoked" => Ok(s.to_string()),
        _ => Err("must be 'active' or 'revoked'".into()),
    }
}

#[derive(Subcommand)]
pub enum TokenAction {
    /// Create a new API token
    Create {
        #[arg(long)]
        subject: String,
        #[arg(long, default_value = "user", value_parser = parse_subject_type)]
        subject_type: String,
        #[arg(long)]
        role: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, value_delimiter = ',')]
        groups: Vec<String>,
        #[arg(long)]
        expires: Option<String>,
    },
    /// List API tokens
    List {
        #[arg(long)]
        subject: Option<String>,
        #[arg(long, value_parser = parse_status)]
        status: Option<String>,
        #[arg(long = "type", value_parser = parse_subject_type)]
        subject_type: Option<String>,
    },
    /// Revoke an API token
    Revoke {
        /// Token ID to revoke
        id: String,
    },
}

pub async fn run_token_command(
    action: &TokenAction,
    client: &ServerClient,
    json_output: bool,
) -> Result<(), CliError> {
    match action {
        TokenAction::Create {
            subject,
            subject_type,
            role,
            name,
            groups,
            expires,
        } => {
            let expires_at = match expires.as_deref() {
                Some(s) => Some(parse_expires(s)?),
                None => None,
            };
            let groups: Vec<String> = {
                let mut seen = std::collections::HashSet::new();
                groups
                    .iter()
                    .map(|g| g.trim().to_string())
                    .filter(|g| !g.is_empty() && seen.insert(g.clone()))
                    .collect()
            };

            let body = json!({
                "subject_id": subject,
                "subject_type": subject_type,
                "name": name,
                "roles": [role],
                "groups": groups,
                "expires_at": expires_at,
            });
            let resp = client.create_token(&body).await?;

            if json_output {
                let mut out = resp.clone();
                out["subject_type"] = json!(subject_type);
                out["role"] = json!(role);
                println!("{}", serde_json::to_string(&out).unwrap_or_default());
            } else {
                println!("Token created successfully.\n");
                println!("  ID:      {}", resp["id"].as_str().unwrap_or("-"));
                println!("  Token:   {}", resp["token"].as_str().unwrap_or("-"));
                println!("  Prefix:  {}", resp["prefix"].as_str().unwrap_or("-"));
                println!("  Subject: {} ({})", subject, subject_type);
                println!("  Role:    {}", role);
                if let Some(exp) = resp["expires_at"].as_str() {
                    println!("  Expires: {}", exp);
                } else {
                    println!("  Expires: never");
                }
                println!("\n⚠ Save this token now. It cannot be retrieved later.");
            }
        }
        TokenAction::List {
            subject,
            status,
            subject_type,
        } => {
            let resp = client.list_tokens().await?;
            let tokens = resp["tokens"].as_array().cloned().unwrap_or_default();
            let filtered: Vec<&Value> = tokens
                .iter()
                .filter(|t| {
                    subject
                        .as_ref()
                        .is_none_or(|s| t["subject_id"].as_str().unwrap_or("") == s)
                        && status
                            .as_ref()
                            .is_none_or(|s| t["status"].as_str().unwrap_or("") == s)
                        && subject_type
                            .as_ref()
                            .is_none_or(|s| t["subject_type"].as_str().unwrap_or("") == s)
                })
                .collect();

            if json_output {
                let out = json!({"tokens": filtered});
                println!("{}", serde_json::to_string(&out).unwrap_or_default());
            } else if filtered.is_empty() {
                println!("No tokens found.");
            } else {
                println!(
                    "{:<14} {:<10} {:<12} {:<6} {:<12} {:<16} {:<8} {:<10}",
                    "ID", "Prefix", "Subject", "Type", "Roles", "Name", "Status", "Expires"
                );
                for t in &filtered {
                    let id = t["id"].as_str().unwrap_or("-");
                    let prefix = t["token_prefix"].as_str().unwrap_or("-");
                    let subj = t["subject_id"].as_str().unwrap_or("-");
                    let stype = t["subject_type"].as_str().unwrap_or("-");
                    let roles = t["roles"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|v| v.as_str())
                                .collect::<Vec<_>>()
                                .join(",")
                        })
                        .unwrap_or_else(|| "-".to_string());
                    let name = t["name"].as_str().unwrap_or("-");
                    let st = t["status"].as_str().unwrap_or("-");
                    let exp = t["expires_at"]
                        .as_str()
                        .map(|s| s[..10].to_string())
                        .unwrap_or_else(|| "never".to_string());
                    println!(
                        "{:<14} {:<10} {:<12} {:<6} {:<12} {:<16} {:<8} {}",
                        &id[..id.len().min(14)],
                        &prefix[..prefix.len().min(10)],
                        &subj[..subj.len().min(12)],
                        &stype[..stype.len().min(6)],
                        &roles[..roles.len().min(12)],
                        &name[..name.len().min(16)],
                        st,
                        exp
                    );
                }
            }
        }
        TokenAction::Revoke { id } => {
            let resp = client.revoke_token(id).await?;
            if json_output {
                println!("{}", serde_json::to_string(&resp).unwrap_or_default());
            } else {
                println!("Token {} revoked.", id);
            }
        }
    }
    Ok(())
}

fn parse_expires(input: &str) -> Result<String, CliError> {
    let trimmed = input.trim();
    // Duration: 90d, 24h, 30m
    if let Some(num_str) = trimmed.strip_suffix('d') {
        let days: i64 = num_str
            .parse()
            .map_err(|_| CliError::Config("invalid --expires format".into()))?;
        let dt = Utc::now() + chrono::Duration::days(days);
        return Ok(dt.to_rfc3339());
    }
    if let Some(num_str) = trimmed.strip_suffix('h') {
        let hours: i64 = num_str
            .parse()
            .map_err(|_| CliError::Config("invalid --expires format".into()))?;
        let dt = Utc::now() + chrono::Duration::hours(hours);
        return Ok(dt.to_rfc3339());
    }
    if let Some(num_str) = trimmed.strip_suffix('m') {
        let mins: i64 = num_str
            .parse()
            .map_err(|_| CliError::Config("invalid --expires format".into()))?;
        let dt = Utc::now() + chrono::Duration::minutes(mins);
        return Ok(dt.to_rfc3339());
    }
    // Date: 2026-12-31 → end of day UTC
    if let Ok(date) = NaiveDate::parse_from_str(trimmed, "%Y-%m-%d") {
        let dt = date.and_hms_opt(23, 59, 59).unwrap().and_utc();
        return Ok(dt.to_rfc3339());
    }
    // ISO 8601 datetime
    if chrono::DateTime::parse_from_rfc3339(trimmed).is_ok() {
        return Ok(trimmed.to_string());
    }
    Err(CliError::Config(
        "invalid --expires format. Use: 90d, 24h, 2026-12-31, or ISO 8601".into(),
    ))
}
