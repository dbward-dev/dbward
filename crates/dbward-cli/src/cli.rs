use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

use dbward_core::ClientConfig;

use crate::config_loader;
use crate::mcp;
use crate::oidc_login;
use crate::server_client;

const LIST_DETAIL_WIDTH: usize = 30;
type RequestListRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
);

#[derive(Parser)]
#[command(name = "dbward", about = "DB operations workflow + approval engine")]
pub struct Cli {
    /// Path to config file
    #[arg(long, default_value = "dbward.toml")]
    config: PathBuf,

    /// Select named database from config
    #[arg(long, env = "DBWARD_DATABASE")]
    database: Option<String>,

    /// Override environment for this request
    #[arg(long, env = "DBWARD_ENV")]
    environment: Option<String>,

    /// Output format: table (default) or json
    #[arg(long, default_value = "table")]
    format: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize dbward configuration
    Init {
        #[arg(long)]
        non_interactive: bool,
        #[arg(long)]
        force: bool,
    },
    /// Login via OIDC (opens browser)
    Login {
        #[arg(long)]
        device: bool,
    },
    /// Logout (revoke tokens + delete credentials)
    Logout,
    /// Show current identity
    Whoami,
    /// Run database migrations
    Migrate {
        #[command(subcommand)]
        action: MigrateAction,
    },
    /// Execute a SQL query
    Execute {
        /// SQL statement to execute
        sql: String,
        /// Emergency bypass (skip approval, requires --reason)
        #[arg(long)]
        emergency: bool,
        /// Reason for this request
        #[arg(long)]
        reason: Option<String>,
        /// Save result to a specific file
        #[arg(long)]
        output: Option<PathBuf>,
        /// Do not save result locally
        #[arg(long)]
        no_save: bool,
    },
    /// Search audit log
    Audit {
        #[arg(long)]
        limit: Option<u32>,
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        operation: Option<String>,
        #[arg(long)]
        status: Option<String>,
    },
    /// Start MCP stdio server
    Mcp,
    /// Start the dbward HTTP server
    Server {
        #[command(subcommand)]
        action: ServerAction,
    },
    /// Start the dbward agent
    Agent {
        /// Path to agent config file
        #[arg(long, default_value = "dbward-agent.toml")]
        config: PathBuf,
    },
    /// Start local dev server + agent
    Dev {
        #[arg(long)]
        database_url: String,
        #[arg(long, default_value = "3000")]
        port: u16,
    },
    /// Approve a pending request
    Approve { id: String },
    /// Reject a pending request
    Reject { id: String },
    /// List pending requests
    List {
        /// Maximum number of requests to return
        #[arg(long)]
        limit: Option<u32>,
        /// Filter by status (e.g. pending, approved, executed)
        #[arg(long)]
        status: Option<String>,
        /// Show only pending requests you can approve
        #[arg(long)]
        pending_for_me: bool,
    },
    /// Resume and get result of an executed request
    Resume {
        id: String,
        /// Save result to a specific file
        #[arg(long)]
        output: Option<PathBuf>,
        /// Do not save result locally
        #[arg(long)]
        no_save: bool,
    },
    /// Show a previously saved result from local storage
    Result { id: String },
}

#[derive(Subcommand)]
enum ServerAction {
    /// Start the HTTP server
    Start {
        #[arg(long, default_value = "127.0.0.1:3000")]
        listen: String,
        #[arg(long, default_value = "dbward.db")]
        data: String,
        #[arg(long, default_value = "dbward-server.toml")]
        config: String,
    },
    /// Manage API tokens
    Token {
        #[command(subcommand)]
        action: TokenAction,
    },
}

#[derive(Subcommand)]
enum TokenAction {
    Create {
        #[arg(long)]
        user: String,
        #[arg(long, value_parser = parse_role)]
        role: String,
        /// Create an agent token instead of a user token
        #[arg(long)]
        agent: bool,
        #[arg(long, default_value = "dbward.db")]
        data: String,
    },
    Revoke {
        #[arg(long)]
        id: String,
        #[arg(long, default_value = "dbward.db")]
        data: String,
    },
}

#[derive(Subcommand)]
enum MigrateAction {
    Up {
        #[arg(long)]
        count: Option<usize>,
    },
    Down {
        #[arg(long, default_value = "1")]
        count: usize,
    },
    Status,
    Create {
        name: String,
    },
}

fn parse_role(s: &str) -> Result<String, String> {
    if s.is_empty() {
        Err("role cannot be empty".into())
    } else {
        Ok(s.to_string())
    }
}

fn truncate_table_cell(value: &str, max_chars: usize) -> String {
    let char_count = value.chars().count();
    if char_count <= max_chars {
        return value.to_string();
    }
    if max_chars <= 3 {
        return ".".repeat(max_chars);
    }
    let prefix: String = value.chars().take(max_chars - 3).collect();
    format!("{prefix}...")
}

fn format_created_time(created_at: &str) -> String {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(created_at) {
        return dt.format("%H:%M").to_string();
    }

    for format in [
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M",
    ] {
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(created_at, format) {
            return dt.format("%H:%M").to_string();
        }
    }

    "?".to_string()
}

// ---------------------------------------------------------------------------
// Auth helper
// ---------------------------------------------------------------------------

async fn authenticate(config: &ClientConfig) -> Result<(String, String), dbward_core::Error> {
    let server_url = config.server.url.clone();

    // Try API token first
    if let Some(ref token) = config.server.token {
        return Ok((server_url, token.clone()));
    }

    // Try OIDC credentials
    if let Some(ref oc) = config.server.oidc {
        match oidc_login::load_token(&oc.issuer, &oc.client_id).await {
            Ok(token) => return Ok((server_url, token)),
            Err(e) => eprintln!("OIDC token load failed: {e}"),
        }
    }

    Err(dbward_core::Error::Auth(
        "no authentication: run 'dbward login' or set server.token in dbward.toml".into(),
    ))
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

pub async fn run(cli: Cli) -> Result<(), dbward_core::Error> {
    // Commands that don't need config/auth
    match &cli.command {
        Command::Init {
            non_interactive,
            force,
        } => return run_init(&cli, *non_interactive, *force),
        Command::Logout => {
            oidc_login::logout()
                .await
                .map_err(dbward_core::Error::Auth)?;
            return Ok(());
        }
        Command::Whoami => {
            oidc_login::whoami().map_err(dbward_core::Error::Auth)?;
            return Ok(());
        }
        Command::Server { action } => return run_server_command(action).await,
        Command::Agent {
            config: agent_config_path,
        } => {
            let content = std::fs::read_to_string(agent_config_path).map_err(|e| {
                dbward_core::Error::Config(format!("{}: {e}", agent_config_path.display()))
            })?;
            let agent_config: dbward_core::AgentConfig = {
                let mut value: toml::Value = toml::from_str(&content).map_err(|e| {
                    dbward_core::Error::Config(format!("{}: {e}", agent_config_path.display()))
                })?;
                dbward_core::env_expand::expand_env_vars(&mut value)?;
                value.try_into().map_err(|e| {
                    dbward_core::Error::Config(format!("{}: {e}", agent_config_path.display()))
                })?
            };
            return dbward_agent::run(agent_config).await;
        }
        Command::Dev { database_url, port } => {
            return run_dev(database_url, *port).await;
        }
        _ => {}
    }

    let config = config_loader::load(&cli.config)?;

    // Login needs OIDC config but not full auth
    if let Command::Login { device } = &cli.command {
        let oc = config
            .server
            .oidc
            .as_ref()
            .ok_or_else(|| dbward_core::Error::Config("[server.oidc] not configured".into()))?;
        if *device {
            oidc_login::login_device(&oc.issuer, &oc.client_id, oc.discovery_url.as_deref()).await
        } else {
            oidc_login::login(&oc.issuer, &oc.client_id, oc.discovery_url.as_deref()).await
        }
        .map_err(dbward_core::Error::Auth)?;
        return Ok(());
    }

    // Migrate create is local-only (just creates a file)
    if let Command::Migrate {
        action: MigrateAction::Create { ref name },
    } = cli.command
    {
        let db_name = config.resolve_database_name(cli.database.as_deref())?;
        let migrations_dir = config.migrations_dir_for(&db_name);
        let migrator = dbward_migrate::Migrator::new_local(migrations_dir);
        let path = migrator.create(name)?;
        println!("Created: {}", path.display());
        return Ok(());
    }

    let (server_url, api_token) = authenticate(&config).await?;
    let sc = server_client::ServerClient::new(&server_url, &api_token);
    let db_name = config.resolve_database_name(cli.database.as_deref())?;
    let env_str = cli.environment.as_deref().unwrap_or("development");
    let json_output = cli.format == "json";

    match cli.command {
        Command::Execute {
            ref sql,
            emergency,
            ref reason,
            ref output,
            no_save,
        } => {
            let (id, status, _token) = sc
                .create_request(
                    "execute_query",
                    env_str,
                    &db_name,
                    sql,
                    emergency,
                    reason.as_deref(),
                )
                .await?;

            match status.as_str() {
                "auto_approved" | "break_glass" => {
                    let resp = sc.dispatch_and_wait(&id).await?;
                    if json_output {
                        println!("{}", serde_json::to_string_pretty(&resp)?);
                    } else {
                        print_execution_result(&resp);
                    }
                    save_result(&id, &resp, output.as_deref(), no_save);
                }
                "pending" => {
                    eprintln!("Request {id} requires approval.");
                    eprintln!("Run: dbward resume {id}");
                }
                _ => {
                    return Err(dbward_core::Error::Server(format!(
                        "unexpected status: {status}"
                    )));
                }
            }
            Ok(())
        }
        Command::Migrate { ref action } => {
            let (operation, detail) = match action {
                MigrateAction::Up { count } => {
                    ("migrate_up", format!("count:{}", count.unwrap_or(0)))
                }
                MigrateAction::Down { count } => ("migrate_down", format!("count:{count}")),
                MigrateAction::Status => ("migrate_status", String::new()),
                MigrateAction::Create { .. } => unreachable!(),
            };

            let (id, status, _token) = sc
                .create_request(operation, env_str, &db_name, &detail, false, None)
                .await?;

            match status.as_str() {
                "auto_approved" | "break_glass" => {
                    let resp = sc.dispatch_and_wait(&id).await?;
                    if json_output {
                        println!("{}", serde_json::to_string_pretty(&resp)?);
                    } else {
                        print_execution_result(&resp);
                    }
                }
                "pending" => {
                    eprintln!("Request {id} requires approval.");
                    eprintln!("Run: dbward resume {id}");
                }
                _ => {
                    return Err(dbward_core::Error::Server(format!(
                        "unexpected status: {status}"
                    )));
                }
            }
            Ok(())
        }
        Command::Approve { ref id } => {
            match sc.approve(id).await {
                Ok(body) => println!("{}", serde_json::to_string_pretty(&body)?),
                Err(e) => {
                    if e.status == 404 {
                        return Err(dbward_core::Error::Server(format!(
                            "Request {id} not found"
                        )));
                    }
                    if e.status == 409 && e.body.to_lowercase().contains("already approved") {
                        return Err(dbward_core::Error::Server(format!(
                            "Request is already approved. Run: dbward resume {id}"
                        )));
                    }
                    if e.status == 403 {
                        return Err(dbward_core::Error::Server(e.body));
                    }
                    return Err(e.into_core_error("approve"));
                }
            }
            Ok(())
        }
        Command::Reject { ref id } => {
            match sc.reject(id).await {
                Ok(body) => println!("{}", serde_json::to_string_pretty(&body)?),
                Err(e) => {
                    if e.status == 404 {
                        return Err(dbward_core::Error::Server(format!(
                            "Request {id} not found"
                        )));
                    }
                    if e.status == 403 {
                        return Err(dbward_core::Error::Server(e.body));
                    }
                    return Err(e.into_core_error("reject"));
                }
            }
            Ok(())
        }
        Command::List {
            ref limit,
            ref status,
            pending_for_me,
        } => {
            let body = if pending_for_me {
                sc.list_pending_for_me(*limit).await?
            } else {
                sc.list_requests(*limit, status.as_deref()).await?
            };
            if json_output {
                println!("{}", serde_json::to_string_pretty(&body)?);
                return Ok(());
            }
            let empty = vec![];
            let requests = body["requests"]
                .as_array()
                .or_else(|| body.as_array())
                .unwrap_or(&empty);
            if requests.is_empty() {
                println!("No requests.");
            } else {
                // Collect rows first to calculate column widths
                let mut rows: Vec<RequestListRow> = Vec::new();
                for r in requests {
                    let id = r["id"].as_str().unwrap_or("?");
                    let short_id = id[..id.len().min(8)].to_string();
                    let status = r["status"].as_str().unwrap_or("?").to_string();
                    let user = r["created_by"].as_str().unwrap_or("?").to_string();
                    let env = r["environment"].as_str().unwrap_or("?").to_string();
                    let op = r["operation"].as_str().unwrap_or("?").to_string();
                    let detail = r["detail"].as_str().unwrap_or("");
                    let short_detail = truncate_table_cell(detail, LIST_DETAIL_WIDTH);
                    let reason = r["reason"].as_str().unwrap_or("").to_string();
                    let created = r["created_at"].as_str().unwrap_or("");
                    let short_time = format_created_time(created);
                    rows.push((
                        short_id,
                        status,
                        user,
                        env,
                        op,
                        short_detail,
                        reason,
                        short_time,
                    ));
                }

                let has_reason = rows.iter().any(|r| !r.6.is_empty());

                let w = (
                    rows.iter().map(|r| r.0.len()).max().unwrap_or(2).max(2) + 2,
                    rows.iter().map(|r| r.1.len()).max().unwrap_or(6).max(6) + 2,
                    rows.iter().map(|r| r.7.len()).max().unwrap_or(5).max(5) + 2,
                    rows.iter().map(|r| r.2.len()).max().unwrap_or(4).max(4) + 2,
                    rows.iter().map(|r| r.3.len()).max().unwrap_or(3).max(3) + 2,
                    rows.iter().map(|r| r.4.len()).max().unwrap_or(2).max(2) + 2,
                );

                if has_reason {
                    println!(
                        "{:<w0$}{:<w1$}{:<w2$}{:<w3$}{:<w4$}{:<w5$}{:<detail_width$} REASON",
                        "ID",
                        "STATUS",
                        "TIME",
                        "USER",
                        "ENV",
                        "OP",
                        "DETAIL",
                        w0 = w.0,
                        w1 = w.1,
                        w2 = w.2,
                        w3 = w.3,
                        w4 = w.4,
                        w5 = w.5,
                        detail_width = LIST_DETAIL_WIDTH,
                    );
                    for r in &rows {
                        println!(
                            "{:<w0$}{:<w1$}{:<w2$}{:<w3$}{:<w4$}{:<w5$}{:<detail_width$} {}",
                            r.0,
                            r.1,
                            r.7,
                            r.2,
                            r.3,
                            r.4,
                            r.5,
                            r.6,
                            w0 = w.0,
                            w1 = w.1,
                            w2 = w.2,
                            w3 = w.3,
                            w4 = w.4,
                            w5 = w.5,
                            detail_width = LIST_DETAIL_WIDTH,
                        );
                    }
                } else {
                    println!(
                        "{:<w0$}{:<w1$}{:<w2$}{:<w3$}{:<w4$}{:<w5$}DETAIL",
                        "ID",
                        "STATUS",
                        "TIME",
                        "USER",
                        "ENV",
                        "OP",
                        w0 = w.0,
                        w1 = w.1,
                        w2 = w.2,
                        w3 = w.3,
                        w4 = w.4,
                        w5 = w.5,
                    );
                    for r in &rows {
                        println!(
                            "{:<w0$}{:<w1$}{:<w2$}{:<w3$}{:<w4$}{:<w5$}{}",
                            r.0,
                            r.1,
                            r.7,
                            r.2,
                            r.3,
                            r.4,
                            r.5,
                            w0 = w.0,
                            w1 = w.1,
                            w2 = w.2,
                            w3 = w.3,
                            w4 = w.4,
                            w5 = w.5,
                        );
                    }
                }
            }
            Ok(())
        }
        Command::Resume {
            ref id,
            ref output,
            no_save,
        } => {
            let resp = sc.dispatch_and_wait(id).await?;
            if json_output {
                println!("{}", serde_json::to_string_pretty(&resp)?);
            } else {
                print_execution_result(&resp);
            }
            save_result(id, &resp, output.as_deref(), no_save);
            Ok(())
        }
        Command::Result { ref id } => {
            let resp = load_result(id)?;
            if json_output {
                println!("{}", serde_json::to_string_pretty(&resp)?);
            } else {
                print_execution_result(&resp);
            }
            Ok(())
        }
        Command::Mcp => mcp::run_stdio(config, cli.database.as_deref(), sc).await,
        Command::Audit {
            ref limit,
            ref user,
            ref operation,
            ref status,
        } => {
            let body = sc
                .list_audit(
                    *limit,
                    user.as_deref(),
                    operation.as_deref(),
                    status.as_deref(),
                )
                .await?;
            if json_output {
                println!("{}", serde_json::to_string_pretty(&body)?);
                return Ok(());
            }
            let empty = vec![];
            let entries = body["audit_log"].as_array().unwrap_or(&empty);
            if entries.is_empty() {
                println!("No audit log entries.");
            } else {
                println!(
                    "{:<10} {:<22} {:<10} {:<14} {:<10} {:<10} {:<12} DETAIL",
                    "ID", "TIMESTAMP", "USER", "OPERATION", "ENV", "DATABASE", "STATUS"
                );
                for e in entries {
                    let id = e["id"].as_str().unwrap_or("?");
                    let short_id = &id[..id.len().min(8)];
                    let ts = e["created_at"].as_str().unwrap_or("?");
                    let ts_short = &ts[..ts.len().min(19)];
                    let actor = e["actor_id"].as_str().unwrap_or("?");
                    let op = e["operation"].as_str().unwrap_or("?");
                    let env = e["environment"].as_str().unwrap_or("?");
                    let db = e["database_name"].as_str().unwrap_or("?");
                    let st = e["status"].as_str().unwrap_or("?");
                    let detail = e["detail"].as_str().unwrap_or("");
                    let short_detail = if detail.len() > 40 {
                        format!("{}...", &detail[..37])
                    } else {
                        detail.to_string()
                    };
                    println!(
                        "{:<10} {:<22} {:<10} {:<14} {:<10} {:<10} {:<12} {}",
                        short_id, ts_short, actor, op, env, db, st, short_detail
                    );
                }
            }
            Ok(())
        }
        // Handled above
        Command::Init { .. }
        | Command::Login { .. }
        | Command::Logout
        | Command::Whoami
        | Command::Server { .. }
        | Command::Agent { .. }
        | Command::Dev { .. } => unreachable!(),
    }
}

fn print_execution_result(resp: &serde_json::Value) {
    if let Some(false) = resp["success"].as_bool() {
        let err = resp["error"].as_str().unwrap_or("unknown error");
        eprintln!("Execution failed: {err}");
        return;
    }
    if let Some(result) = resp.get("result") {
        if result.is_null() {
            eprintln!("Executed successfully.");
        } else if let Some(text) = result.as_str() {
            println!("{text}");
        } else {
            println!(
                "{}",
                serde_json::to_string_pretty(result).unwrap_or_default()
            );
        }
    } else {
        eprintln!("Executed successfully.");
    }
}

/// Save result locally. Returns the path where it was saved.
fn save_result(
    request_id: &str,
    resp: &serde_json::Value,
    output: Option<&Path>,
    no_save: bool,
) -> Option<PathBuf> {
    if no_save {
        return None;
    }
    let path = match output {
        Some(p) => p.to_path_buf(),
        None => {
            let dir = dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".dbward")
                .join("results");
            if std::fs::create_dir_all(&dir).is_err() {
                return None;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
            }
            dir.join(format!("{request_id}.json"))
        }
    };
    let content = serde_json::to_string_pretty(resp).unwrap_or_default();
    if write_secure(&path, content.as_bytes()).is_ok() {
        eprintln!("Result saved to {}", path.display());
        Some(path)
    } else {
        eprintln!("Warning: failed to save result to {}", path.display());
        None
    }
}

#[cfg(unix)]
fn write_secure(path: &Path, content: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?
        .write_all(content)
}

#[cfg(not(unix))]
fn write_secure(path: &Path, content: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, content)
}

/// Load a previously saved result from local storage.
fn load_result(request_id: &str) -> Result<serde_json::Value, dbward_core::Error> {
    let path = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".dbward")
        .join("results")
        .join(format!("{request_id}.json"));
    let content = std::fs::read_to_string(&path).map_err(|_| {
        dbward_core::Error::Server(format!(
            "No saved result for {request_id}. Path: {}",
            path.display()
        ))
    })?;
    serde_json::from_str(&content)
        .map_err(|e| dbward_core::Error::Server(format!("Failed to parse saved result: {e}")))
}

// ---------------------------------------------------------------------------
// Server management commands (these don't go through the agent flow)
// ---------------------------------------------------------------------------

async fn run_server_command(action: &ServerAction) -> Result<(), dbward_core::Error> {
    match action {
        ServerAction::Start {
            listen,
            data,
            config: server_config_path,
        } => {
            let server_cfg = dbward_server::server_config::ServerConfig::load(
                std::path::Path::new(server_config_path),
            )
            .map_err(dbward_core::Error::Server)?;

            let conn = rusqlite::Connection::open(data)
                .map_err(|e| dbward_core::Error::Server(e.to_string()))?;
            dbward_server::db::init(&conn)
                .map_err(|e| dbward_core::Error::Server(e.to_string()))?;
            dbward_server::db::policy_repo::sync_workflows(&conn, &server_cfg.workflows)
                .map_err(|e| dbward_core::Error::Server(e.to_string()))?;
            dbward_server::db::policy_repo::sync_execution_policies(
                &conn,
                &server_cfg.execution_policies,
            )
            .map_err(|e| dbward_core::Error::Server(e.to_string()))?;
            dbward_server::db::policy_repo::sync_result_policies(
                &conn,
                &server_cfg.result_policies,
            )
            .map_err(|e| dbward_core::Error::Server(e.to_string()))?;
            dbward_server::db::policy_repo::sync_notification_policies(
                &conn,
                &server_cfg.notification_policies,
            )
            .map_err(|e| dbward_core::Error::Server(e.to_string()))?;
            let data_path = std::path::Path::new(data)
                .parent()
                .unwrap_or(std::path::Path::new("."));
            let token_signer = dbward_server::token::TokenSigner::load_or_generate(data_path)
                .map_err(dbward_core::Error::Server)?;
            let webhooks = dbward_server::webhook::WebhookDispatcher::new(server_cfg.webhooks);
            let (oidc, auth_mode) = match server_cfg.auth {
                Some(ref auth) => {
                    let mode = auth.mode.clone();
                    let verifier = auth.oidc.as_ref().map(|c| {
                        std::sync::Arc::new(dbward_server::oidc::OidcVerifier::new(c.clone()))
                    });
                    (verifier, mode)
                }
                None => (None, "token".to_string()),
            };
            let state = dbward_server::AppState {
                sqlite: std::sync::Arc::new(tokio::sync::Mutex::new(conn)),
                token_signer: std::sync::Arc::new(token_signer),
                webhooks: std::sync::Arc::new(webhooks),
                oidc,
                auth_mode,
                policy: std::sync::Arc::new(server_cfg.policy),
                result_channels: std::sync::Arc::new(dbward_server::ResultChannels::new()),
                retention: server_cfg.retention,
                request_notifier: std::sync::Arc::new(dbward_server::RequestNotifier::new()),
            };
            let addr: std::net::SocketAddr = listen
                .parse()
                .map_err(|e: std::net::AddrParseError| dbward_core::Error::Server(e.to_string()))?;
            dbward_server::start(addr, state).await
        }
        ServerAction::Token { action } => match action {
            TokenAction::Create {
                user,
                role,
                agent,
                data,
            } => {
                let conn = rusqlite::Connection::open(data)
                    .map_err(|e| dbward_core::Error::Server(e.to_string()))?;
                dbward_server::db::init(&conn)
                    .map_err(|e| dbward_core::Error::Server(e.to_string()))?;
                let data_path = std::path::Path::new(data)
                    .parent()
                    .unwrap_or(std::path::Path::new("."));
                let token_signer = dbward_server::token::TokenSigner::load_or_generate(data_path)
                    .map_err(dbward_core::Error::Server)?;
                let state = dbward_server::AppState {
                    sqlite: std::sync::Arc::new(tokio::sync::Mutex::new(conn)),
                    token_signer: std::sync::Arc::new(token_signer),
                    webhooks: std::sync::Arc::new(
                        dbward_server::webhook::WebhookDispatcher::empty(),
                    ),
                    oidc: None,
                    auth_mode: "token".to_string(),
                    policy: std::sync::Arc::new(Default::default()),
                    result_channels: std::sync::Arc::new(dbward_server::ResultChannels::new()),
                    retention: Default::default(),
                    request_notifier: std::sync::Arc::new(dbward_server::RequestNotifier::new()),
                };
                let subject_type = if *agent { "agent" } else { "user" };
                let (token_id, raw_token) =
                    dbward_server::auth::create_token_with_type(&state, user, role, subject_type)
                        .await
                        .map_err(dbward_core::Error::Server)?;
                let type_label = if *agent { "agent" } else { "user" };
                println!("Token created:");
                println!("  ID:    {token_id}");
                println!("  Token: {raw_token}");
                println!("  User:  {user}");
                println!("  Role:  {role}");
                println!("  Type:  {type_label}");
                println!("\nSave this token — it cannot be retrieved later.");
                Ok(())
            }
            TokenAction::Revoke { id, data } => {
                let conn = rusqlite::Connection::open(data)
                    .map_err(|e| dbward_core::Error::Server(e.to_string()))?;
                let data_path = std::path::Path::new(data)
                    .parent()
                    .unwrap_or(std::path::Path::new("."));
                let token_signer = dbward_server::token::TokenSigner::load_or_generate(data_path)
                    .map_err(dbward_core::Error::Server)?;
                let state = dbward_server::AppState {
                    sqlite: std::sync::Arc::new(tokio::sync::Mutex::new(conn)),
                    token_signer: std::sync::Arc::new(token_signer),
                    webhooks: std::sync::Arc::new(
                        dbward_server::webhook::WebhookDispatcher::empty(),
                    ),
                    oidc: None,
                    auth_mode: "token".to_string(),
                    policy: std::sync::Arc::new(Default::default()),
                    result_channels: std::sync::Arc::new(dbward_server::ResultChannels::new()),
                    retention: Default::default(),
                    request_notifier: std::sync::Arc::new(dbward_server::RequestNotifier::new()),
                };
                dbward_server::auth::revoke_token(&state, id)
                    .await
                    .map_err(dbward_core::Error::Server)?;
                println!("Token {id} revoked.");
                Ok(())
            }
        },
    }
}

// ---------------------------------------------------------------------------
// Dev (local server + agent)
// ---------------------------------------------------------------------------

async fn run_dev(database_url: &str, port: u16) -> Result<(), dbward_core::Error> {
    let dev_dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".dbward")
        .join("dev");
    std::fs::create_dir_all(&dev_dir).map_err(|e| dbward_core::Error::Server(e.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dev_dir, std::fs::Permissions::from_mode(0o700));
    }

    let db_path = dev_dir.join("dbward.db");
    let conn = rusqlite::Connection::open(&db_path)
        .map_err(|e| dbward_core::Error::Server(e.to_string()))?;
    dbward_server::db::init(&conn).map_err(|e| dbward_core::Error::Server(e.to_string()))?;

    // Auto-approve all environments
    let workflows = vec![dbward_server::server_config::WorkflowDef {
        database: "*".into(),
        environment: "*".into(),
        operations: vec![],
        steps: vec![],
        require_reason: false,
    }];
    dbward_server::db::policy_repo::sync_workflows(&conn, &workflows)
        .map_err(|e| dbward_core::Error::Server(e.to_string()))?;

    let token_signer = dbward_server::token::TokenSigner::load_or_generate(&dev_dir)
        .map_err(dbward_core::Error::Server)?;

    let state = dbward_server::AppState {
        sqlite: std::sync::Arc::new(tokio::sync::Mutex::new(conn)),
        token_signer: std::sync::Arc::new(token_signer),
        webhooks: std::sync::Arc::new(dbward_server::webhook::WebhookDispatcher::empty()),
        oidc: None,
        auth_mode: "token".into(),
        policy: std::sync::Arc::new(Default::default()),
        result_channels: std::sync::Arc::new(dbward_server::ResultChannels::new()),
        retention: Default::default(),
        request_notifier: std::sync::Arc::new(dbward_server::RequestNotifier::new()),
    };

    // Create tokens
    let (_, admin_token) =
        dbward_server::auth::create_token_with_type(&state, "admin", "admin", "user")
            .await
            .map_err(dbward_core::Error::Server)?;
    let (_, dev_token) =
        dbward_server::auth::create_token_with_type(&state, "developer", "developer", "user")
            .await
            .map_err(dbward_core::Error::Server)?;
    let (_, agent_token) =
        dbward_server::auth::create_token_with_type(&state, "agent", "admin", "agent")
            .await
            .map_err(dbward_core::Error::Server)?;

    let addr: std::net::SocketAddr = format!("127.0.0.1:{port}")
        .parse()
        .map_err(|e: std::net::AddrParseError| dbward_core::Error::Server(e.to_string()))?;
    let server_url = format!("http://127.0.0.1:{port}");

    // Write client config
    let client_config = format!(
        "[server]\nurl = \"{}\"\ntoken = \"{}\"\n",
        server_url, dev_token
    );
    let config_path = dev_dir.join("client.toml");
    let _ = std::fs::write(&config_path, &client_config);

    eprintln!("dbward dev server starting...");
    eprintln!("  Server:    {server_url}");
    eprintln!("  Database:  {database_url}");
    eprintln!();
    eprintln!("  Admin token:     {admin_token}");
    eprintln!("  Developer token: {dev_token}");
    eprintln!();
    eprintln!("  Config: {}", config_path.display());
    eprintln!(
        "  Try: dbward --config {} execute \"SELECT 1\"",
        config_path.display()
    );
    eprintln!();

    // Build agent config
    let mut databases = std::collections::BTreeMap::new();
    databases.insert(
        "default".into(),
        dbward_core::AgentDatabaseConfig {
            url: database_url.to_string(),
            migrations_dir: None,
        },
    );
    let agent_config = dbward_core::AgentConfig {
        agent_id: "dev-agent".into(),
        poll_interval_ms: 500,
        lease_duration_secs: 300,
        max_concurrent_tasks: 2,
        server: dbward_core::AgentServerConfig {
            url: server_url,
            agent_token: agent_token.clone(),
        },
        capabilities: dbward_core::AgentCapabilities {
            databases: vec!["default".into()],
            environments: vec!["*".into()],
            operations: vec!["*".into()],
        },
        databases,
    };

    // Spawn server, then run agent on main task
    let server_state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = dbward_server::start(addr, server_state).await {
            eprintln!("server error: {e}");
        }
    });

    // Wait for server to be ready
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Run agent (blocks until ctrl-c)
    dbward_agent::run(agent_config).await
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

fn run_init(cli: &Cli, non_interactive: bool, force: bool) -> Result<(), dbward_core::Error> {
    use std::io::{self, BufRead, Write};

    let config_path = &cli.config;
    if config_path.exists() && !force {
        return Err(dbward_core::Error::Config(format!(
            "{} already exists. Use --force to overwrite.",
            config_path.display()
        )));
    }

    let prompt = |msg: &str, default: &str| -> String {
        if non_interactive {
            return default.to_string();
        }
        eprint!("{msg} [{default}]: ");
        io::stderr().flush().ok();
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line).ok();
        let trimmed = line.trim();
        if trimmed.is_empty() {
            default.to_string()
        } else {
            trimmed.to_string()
        }
    };

    let server_url = prompt("Server URL", "http://localhost:3000");
    let db_name = prompt("Database name", "app");

    let toml_content = format!(
        r#"default_database = "{db_name}"

[server]
url = "{server_url}"
# token = "dbw_..."  # Or use [server.oidc] for OIDC

[databases.{db_name}]
"#
    );

    std::fs::write(config_path, toml_content.trim_end()).map_err(dbward_core::Error::Io)?;
    eprintln!("Created {}", config_path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_role_valid() {
        assert_eq!(parse_role("admin").unwrap(), "admin");
        assert_eq!(parse_role("developer").unwrap(), "developer");
        assert_eq!(parse_role("readonly").unwrap(), "readonly");
        assert_eq!(parse_role("dba").unwrap(), "dba");
    }

    #[test]
    fn parse_role_invalid() {
        assert!(parse_role("").is_err());
    }

    #[test]
    fn truncate_table_cell_preserves_short_values() {
        assert_eq!(
            truncate_table_cell("SELECT 1", LIST_DETAIL_WIDTH),
            "SELECT 1"
        );
    }

    #[test]
    fn truncate_table_cell_caps_long_values() {
        let value = "1234567890123456789012345678901234567890";
        let truncated = truncate_table_cell(value, LIST_DETAIL_WIDTH);
        assert_eq!(truncated.chars().count(), LIST_DETAIL_WIDTH);
        assert!(truncated.ends_with("..."));
    }

    #[test]
    fn format_created_time_supports_rfc3339() {
        assert_eq!(format_created_time("2026-05-05T01:13:27+09:00"), "01:13");
    }

    #[test]
    fn format_created_time_supports_space_separated_timestamp() {
        assert_eq!(format_created_time("2026-05-05 01:13:27.123"), "01:13");
    }

    #[test]
    fn format_created_time_falls_back_for_invalid_input() {
        assert_eq!(format_created_time("not-a-timestamp"), "?");
        assert_eq!(format_created_time("2026-05-05T01:🦀:27+09:00"), "?");
    }
}
