use chrono::{NaiveDate, Utc};
use clap::Subcommand;
use serde::Serialize;
use serde_json::{Value, json};

use crate::output::CliError;
use crate::output::{CliResponse, Column, RenderPlan, StderrLine};
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

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct TokenCreateOutput {
    pub id: String,
    pub token: String,
    pub prefix: String,
    pub subject: String,
    pub subject_type: String,
    pub scope_ceiling: Vec<String>,
    pub expires_at: Option<String>,
}

#[derive(Serialize)]
pub struct TokenListOutput {
    pub tokens: Vec<TokenSummary>,
}

#[derive(Serialize)]
pub struct TokenSummary {
    pub id: String,
    pub prefix: String,
    pub subject: String,
    pub subject_type: String,
    pub ceiling: Vec<String>,
    pub name: String,
    pub status: String,
    pub expires_at: Option<String>,
}

#[derive(Serialize)]
pub struct TokenRevokeOutput {
    pub id: String,
    pub status: String,
}

#[derive(Serialize)]
pub struct TokenInspectOutput {
    pub id: String,
    pub subject: String,
    pub subject_type: String,
    pub status: String,
    pub ceiling: Vec<String>,
    pub resolved_roles: Vec<String>,
    pub effective_roles: Vec<String>,
    pub effective_permissions: Vec<String>,
}

// ---------------------------------------------------------------------------
// Command implementations
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub async fn run_token_create(
    client: &ServerClient,
    subject: Option<&str>,
    subject_type: &str,
    scope_roles: &[String],
    no_scope_ceiling: bool,
    name: Option<&str>,
    expires: Option<&str>,
    role: Option<&str>,
) -> Result<CliResponse<TokenCreateOutput>, CliError> {
    let resolved_subject = match subject {
        Some(s) => s.to_string(),
        None => {
            if subject_type != "user" {
                return Err(CliError::Config(
                    "--subject is required for agent tokens".into(),
                ));
            }
            let me: Value = client.get("/api/me").await?;
            me.get("subject_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| CliError::Config("could not determine caller identity".into()))?
                .to_string()
        }
    };

    let mut warnings = Vec::new();

    let scope_ceiling = if no_scope_ceiling {
        if subject_type != "agent" {
            return Err(CliError::Config(
                "--no-scope-ceiling is only allowed for agent tokens".into(),
            ));
        }
        None
    } else if !scope_roles.is_empty() {
        Some(json!({"roles": scope_roles}))
    } else if let Some(legacy_role) = role {
        warnings.push("--role is deprecated. Use --scope-roles instead.".to_string());
        Some(json!({"roles": [legacy_role]}))
    } else {
        None
    };

    let expires_at = match expires {
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

    let token_value = resp["token"].as_str().unwrap_or("-").to_string();
    let id = resp["id"].as_str().unwrap_or("-").to_string();
    let prefix = resp["prefix"].as_str().unwrap_or("-").to_string();
    let ceiling: Vec<String> = resp["scope_ceiling"]["roles"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let output = TokenCreateOutput {
        id: id.clone(),
        token: token_value.clone(),
        prefix: prefix.clone(),
        subject: resolved_subject.clone(),
        subject_type: subject_type.to_string(),
        scope_ceiling: ceiling.clone(),
        expires_at: expires_at.clone(),
    };

    let render = RenderPlan::raw_with_info(
        token_value,
        vec![
            StderrLine::Status("Token created successfully.".into()),
            StderrLine::Info("ID".into(), id),
            StderrLine::Info("Prefix".into(), prefix),
            StderrLine::Info(
                "Subject".into(),
                format!("{resolved_subject} ({subject_type})"),
            ),
            StderrLine::Info(
                "Ceiling".into(),
                if ceiling.is_empty() {
                    "unrestricted".into()
                } else {
                    ceiling.join(", ")
                },
            ),
            StderrLine::Info(
                "Expires".into(),
                expires_at.unwrap_or_else(|| "never".into()),
            ),
            StderrLine::Warn("Save this token now. It cannot be retrieved later.".into()),
        ],
    );

    let mut response = CliResponse::ok(output, render);
    for w in warnings {
        response = response.with_warning(w);
    }
    Ok(response)
}

pub async fn run_token_list(
    client: &ServerClient,
    subject: Option<&str>,
    status: Option<&str>,
    subject_type: Option<&str>,
) -> Result<CliResponse<TokenListOutput>, CliError> {
    let resp = client.list_tokens().await?;
    let tokens = resp["tokens"].as_array().cloned().unwrap_or_default();

    let filtered: Vec<&Value> = tokens
        .iter()
        .filter(|t| {
            subject.is_none_or(|s| t["subject_id"].as_str().unwrap_or("") == s)
                && status.is_none_or(|s| t["status"].as_str().unwrap_or("") == s)
                && subject_type.is_none_or(|s| t["subject_type"].as_str().unwrap_or("") == s)
        })
        .collect();

    let summaries: Vec<TokenSummary> = filtered
        .iter()
        .map(|t| TokenSummary {
            id: t["id"].as_str().unwrap_or("-").to_string(),
            prefix: t["token_prefix"].as_str().unwrap_or("-").to_string(),
            subject: t["subject_id"].as_str().unwrap_or("-").to_string(),
            subject_type: t["subject_type"].as_str().unwrap_or("-").to_string(),
            ceiling: t["scope_ceiling"]["roles"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            name: t["name"].as_str().unwrap_or("-").to_string(),
            status: t["status"].as_str().unwrap_or("-").to_string(),
            expires_at: t["expires_at"]
                .as_str()
                .map(|s| s[..10.min(s.len())].to_string()),
        })
        .collect();

    let render = if summaries.is_empty() {
        RenderPlan::empty_list("tokens")
    } else {
        let columns = vec![
            Column::new("ID").with_max_width(14),
            Column::new("Prefix").with_max_width(10),
            Column::new("Subject").with_max_width(12),
            Column::new("Type").with_max_width(6),
            Column::new("Ceiling").with_max_width(20),
            Column::new("Name").with_max_width(16),
            Column::new("Status").with_max_width(8),
            Column::new("Expires"),
        ];
        let rows: Vec<Vec<String>> = summaries
            .iter()
            .map(|t| {
                vec![
                    t.id.clone(),
                    t.prefix.clone(),
                    t.subject.clone(),
                    t.subject_type.clone(),
                    if t.ceiling.is_empty() {
                        "none".to_string()
                    } else {
                        t.ceiling.join(",")
                    },
                    t.name.clone(),
                    t.status.clone(),
                    t.expires_at.clone().unwrap_or_else(|| "never".to_string()),
                ]
            })
            .collect();
        RenderPlan::table(columns, rows)
    };

    Ok(CliResponse::ok(
        TokenListOutput { tokens: summaries },
        render,
    ))
}

pub async fn run_token_revoke(
    client: &ServerClient,
    id: &str,
) -> Result<CliResponse<TokenRevokeOutput>, CliError> {
    let _resp = client.revoke_token(id).await?;

    let output = TokenRevokeOutput {
        id: id.to_string(),
        status: "revoked".into(),
    };
    let render = RenderPlan::status(format!("Token {id} revoked."));

    Ok(CliResponse::ok(output, render))
}

pub async fn run_token_inspect(
    client: &ServerClient,
    id: &str,
) -> Result<CliResponse<TokenInspectOutput>, CliError> {
    let resp = client.inspect_token(id).await?;

    let ceiling: Vec<String> = resp["scope_ceiling"]["roles"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let resolved_roles: Vec<String> = resp["resolved_roles"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let effective_roles: Vec<String> = resp["effective_roles"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let effective_permissions: Vec<String> = resp["effective_permissions"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let output = TokenInspectOutput {
        id: resp["id"].as_str().unwrap_or("-").to_string(),
        subject: resp["subject_id"].as_str().unwrap_or("-").to_string(),
        subject_type: resp["subject_type"].as_str().unwrap_or("-").to_string(),
        status: resp["status"].as_str().unwrap_or("-").to_string(),
        ceiling: ceiling.clone(),
        resolved_roles: resolved_roles.clone(),
        effective_roles: effective_roles.clone(),
        effective_permissions: effective_permissions.clone(),
    };

    let mut pairs = vec![
        (
            "Subject".into(),
            format!("{} ({})", output.subject, output.subject_type),
        ),
        ("Status".into(), output.status.clone()),
        (
            "Ceiling".into(),
            if ceiling.is_empty() {
                "unrestricted".into()
            } else {
                ceiling.join(", ")
            },
        ),
    ];
    if !resolved_roles.is_empty() {
        pairs.push(("Resolved".into(), resolved_roles.join(", ")));
    }
    if !effective_roles.is_empty() {
        pairs.push(("Effective".into(), effective_roles.join(", ")));
    }
    if !effective_permissions.is_empty() {
        pairs.push(("Permissions".into(), effective_permissions.join(", ")));
    }

    let render = RenderPlan::key_value(pairs);
    Ok(CliResponse::ok(output, render))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
