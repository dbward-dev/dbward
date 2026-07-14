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
        /// Subject ID (defaults to yourself if omitted)
        #[arg(long)]
        subject: Option<String>,
        #[arg(long, default_value = "user", value_parser = parse_subject_type)]
        subject_type: String,
        /// Scope ceiling roles (comma-separated). Omit to use the user's resolved roles.
        #[arg(long, value_delimiter = ',')]
        scope_roles: Vec<String>,
        /// No scope ceiling (agent tokens only)
        #[arg(long, conflicts_with = "scope_roles")]
        no_scope_ceiling: bool,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        expires: Option<String>,
        /// Deprecated: use --scope-roles instead
        #[arg(long, hide = true)]
        role: Option<String>,
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
    /// Inspect a token's effective permissions (resolved dynamically)
    Inspect {
        /// Token ID (not prefix — existence leak prevention)
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
            scope_roles,
            no_scope_ceiling,
            name,
            expires,
            role,
        } => {
            // Resolve subject: if not provided, use caller's own identity
            let resolved_subject = match subject {
                Some(s) => s.clone(),
                None => {
                    if subject_type != "user" {
                        return Err(CliError::Config(
                            "--subject is required for agent tokens".into(),
                        ));
                    }
                    let me: serde_json::Value = client.get("/api/me").await?;
                    me.get("subject_id")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| {
                            CliError::Config("could not determine caller identity".into())
                        })?
                        .to_string()
                }
            };
            // Build scope_ceiling from flags
            let scope_ceiling = if *no_scope_ceiling {
                if subject_type != "agent" {
                    return Err(CliError::Config(
                        "--no-scope-ceiling is only allowed for agent tokens".into(),
                    ));
                }
                None
            } else if !scope_roles.is_empty() {
                Some(json!({"roles": scope_roles}))
            } else if let Some(legacy_role) = role {
                // Deprecated --role flag → convert to scope_ceiling
                eprintln!("⚠ --role is deprecated. Use --scope-roles instead.");
                Some(json!({"roles": [legacy_role]}))
            } else {
                // User tokens: auto-ceiling from resolved roles (server-side)
                // Agent tokens: unrestricted (no ceiling)
                None
            };

            let expires_at = match expires.as_deref() {
                Some(s) => Some(parse_expires(s)?),
                None => None,
            };

            let body = json!({
                "subject_id": resolved_subject,
                "subject_type": subject_type,
                "name": name,
                "scope_ceiling": scope_ceiling,
                "expires_at": expires_at,
            });
            let resp = client.create_token(&body).await?;

            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&resp).unwrap_or_default()
                );
            } else {
                println!("Token created successfully.\n");
                println!("  ID:      {}", resp["id"].as_str().unwrap_or("-"));
                println!("  Token:   {}", resp["token"].as_str().unwrap_or("-"));
                println!("  Prefix:  {}", resp["prefix"].as_str().unwrap_or("-"));
                println!("  Subject: {} ({})", resolved_subject, subject_type);
                if let Some(sc) = resp.get("scope_ceiling").filter(|v| !v.is_null()) {
                    if let Some(roles) = sc.get("roles").and_then(|r| r.as_array()) {
                        let role_strs: Vec<&str> =
                            roles.iter().filter_map(|v| v.as_str()).collect();
                        println!("  Ceiling: {}", role_strs.join(", "));
                    }
                } else {
                    println!("  Ceiling: unrestricted");
                }
                if let Some(roles) = resp["effective_roles"].as_array() {
                    let role_strs: Vec<&str> = roles.iter().filter_map(|v| v.as_str()).collect();
                    println!("  Roles:   {}", role_strs.join(", "));
                }
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
                println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
            } else if filtered.is_empty() {
                println!("No tokens found.");
            } else {
                println!(
                    "{:<14} {:<10} {:<12} {:<6} {:<20} {:<16} {:<8} {:<10}",
                    "ID", "Prefix", "Subject", "Type", "Ceiling", "Name", "Status", "Expires"
                );
                for t in &filtered {
                    let id = t["id"].as_str().unwrap_or("-");
                    let prefix = t["token_prefix"].as_str().unwrap_or("-");
                    let subj = t["subject_id"].as_str().unwrap_or("-");
                    let stype = t["subject_type"].as_str().unwrap_or("-");
                    let ceiling = t["scope_ceiling"]["roles"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|v| v.as_str())
                                .collect::<Vec<_>>()
                                .join(",")
                        })
                        .unwrap_or_else(|| "none".to_string());
                    let name = t["name"].as_str().unwrap_or("-");
                    let st = t["status"].as_str().unwrap_or("-");
                    let exp = t["expires_at"]
                        .as_str()
                        .map(|s| s[..10].to_string())
                        .unwrap_or_else(|| "never".to_string());
                    println!(
                        "{:<14} {:<10} {:<12} {:<6} {:<20} {:<16} {:<8} {}",
                        &id[..id.len().min(14)],
                        &prefix[..prefix.len().min(10)],
                        &subj[..subj.len().min(12)],
                        &stype[..stype.len().min(6)],
                        &ceiling[..ceiling.len().min(20)],
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
                println!(
                    "{}",
                    serde_json::to_string_pretty(&resp).unwrap_or_default()
                );
            } else {
                println!("Token {} revoked.", id);
            }
        }
        TokenAction::Inspect { id } => {
            let resp = client.inspect_token(id).await?;
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&resp).unwrap_or_default()
                );
            } else {
                println!("Token: {}", resp["id"].as_str().unwrap_or("-"));
                println!(
                    "  Subject:     {} ({})",
                    resp["subject_id"].as_str().unwrap_or("-"),
                    resp["subject_type"].as_str().unwrap_or("-"),
                );
                println!("  Status:      {}", resp["status"].as_str().unwrap_or("-"));
                if let Some(sc) = resp.get("scope_ceiling").filter(|v| !v.is_null()) {
                    if let Some(roles) = sc.get("roles").and_then(|r| r.as_array()) {
                        let role_strs: Vec<&str> =
                            roles.iter().filter_map(|v| v.as_str()).collect();
                        println!("  Ceiling:     {}", role_strs.join(", "));
                    }
                } else {
                    println!("  Ceiling:     unrestricted");
                }
                if let Some(roles) = resp["resolved_roles"].as_array() {
                    let role_strs: Vec<&str> = roles.iter().filter_map(|v| v.as_str()).collect();
                    println!("  Resolved:    {}", role_strs.join(", "));
                }
                if let Some(roles) = resp["effective_roles"].as_array() {
                    let role_strs: Vec<&str> = roles.iter().filter_map(|v| v.as_str()).collect();
                    println!("  Effective:   {}", role_strs.join(", "));
                }
                if let Some(perms) = resp["effective_permissions"].as_array() {
                    let perm_strs: Vec<&str> = perms.iter().filter_map(|v| v.as_str()).collect();
                    println!("  Permissions: {}", perm_strs.join(", "));
                }
            }
        }
    }
    Ok(())
}

fn parse_expires(input: &str) -> Result<String, CliError> {
    let trimmed = input.trim();
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
    if let Ok(date) = NaiveDate::parse_from_str(trimmed, "%Y-%m-%d") {
        let dt = date.and_hms_opt(23, 59, 59).unwrap().and_utc();
        return Ok(dt.to_rfc3339());
    }
    if chrono::DateTime::parse_from_rfc3339(trimmed).is_ok() {
        return Ok(trimmed.to_string());
    }
    Err(CliError::Config(
        "invalid --expires format. Use: 90d, 24h, 2026-12-31, or ISO 8601".into(),
    ))
}
