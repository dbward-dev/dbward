use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

use dbward_core::ClientConfig;

use crate::config_loader;
use crate::mcp;
use crate::oidc_login;
use crate::server_client;

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
        /// Reason for emergency bypass
        #[arg(long, requires = "emergency")]
        reason: Option<String>,
        /// Save result to a specific file
        #[arg(long)]
        output: Option<PathBuf>,
        /// Do not save result locally
        #[arg(long)]
        no_save: bool,
    },
    /// Search audit log
    Audit,
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
    /// Approve a pending request
    Approve { id: String },
    /// Reject a pending request
    Reject { id: String },
    /// List pending requests
    List,
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
    Result {
        id: String,
    },
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
        role: dbward_core::Role,
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

fn parse_role(s: &str) -> Result<dbward_core::Role, String> {
    match s {
        "admin" => Ok(dbward_core::Role::Admin),
        "developer" => Ok(dbward_core::Role::Developer),
        "readonly" => Ok(dbward_core::Role::Readonly),
        _ => Err(format!("unknown role: {s}")),
    }
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
            let content = std::fs::read_to_string(&agent_config_path).map_err(|e| {
                dbward_core::Error::Config(format!("{}: {e}", agent_config_path.display()))
            })?;
            let agent_config: dbward_core::AgentConfig = toml::from_str(&content).map_err(|e| {
                dbward_core::Error::Config(format!("{}: {e}", agent_config_path.display()))
            })?;
            return dbward_agent::run(agent_config).await;
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
                    print_execution_result(&resp);
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
                    print_execution_result(&resp);
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
            let body = sc.approve(id).await?;
            println!("{}", serde_json::to_string_pretty(&body)?);
            Ok(())
        }
        Command::Reject { ref id } => {
            let body = sc.reject(id).await?;
            println!("{}", serde_json::to_string_pretty(&body)?);
            Ok(())
        }
        Command::List => {
            let body = sc.list_requests().await?;
            let empty = vec![];
            let requests = body["requests"]
                .as_array()
                .or_else(|| body.as_array())
                .unwrap_or(&empty);
            if requests.is_empty() {
                println!("No requests.");
            } else {
                for r in requests {
                    let id = r["id"].as_str().unwrap_or("?");
                    let status = r["status"].as_str().unwrap_or("?");
                    let user = r["created_by"].as_str().unwrap_or("?");
                    let op = r["operation"].as_str().unwrap_or("?");
                    let env = r["environment"].as_str().unwrap_or("?");
                    let detail = r["detail"].as_str().unwrap_or("");
                    let short = if detail.len() > 60 {
                        &detail[..60]
                    } else {
                        detail
                    };
                    println!("[{status}] {id}  {user}  {op}  {env}  {short}");
                }
            }
            Ok(())
        }
        Command::Resume { ref id, ref output, no_save } => {
            let resp = sc.dispatch_and_wait(id).await?;
            print_execution_result(&resp);
            save_result(id, &resp, output.as_deref(), no_save);
            Ok(())
        }
        Command::Result { ref id } => {
            let resp = load_result(id)?;
            print_execution_result(&resp);
            Ok(())
        }
        Command::Mcp => mcp::run_stdio(config, cli.database.as_deref(), sc).await,
        Command::Audit => {
            println!("Audit search: not yet implemented.");
            Ok(())
        }
        // Handled above
        Command::Init { .. }
        | Command::Login { .. }
        | Command::Logout
        | Command::Whoami
        | Command::Server { .. }
        | Command::Agent { .. } => unreachable!(),
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
            println!("Executed successfully.");
        } else if let Some(text) = result.as_str() {
            println!("{text}");
        } else {
            println!(
                "{}",
                serde_json::to_string_pretty(result).unwrap_or_default()
            );
        }
    } else {
        println!("Executed successfully.");
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
            dir.join(format!("{request_id}.json"))
        }
    };
    let content = serde_json::to_string_pretty(resp).unwrap_or_default();
    if std::fs::write(&path, &content).is_ok() {
        eprintln!("Result saved to {}", path.display());
        Some(path)
    } else {
        eprintln!("Warning: failed to save result to {}", path.display());
        None
    }
}

/// Load a previously saved result from local storage.
fn load_result(request_id: &str) -> Result<serde_json::Value, dbward_core::Error> {
    let path = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".dbward")
        .join("results")
        .join(format!("{request_id}.json"));
    let content = std::fs::read_to_string(&path)
        .map_err(|_| dbward_core::Error::Server(format!("No saved result for {request_id}. Path: {}", path.display())))?;
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
            dbward_server::db::sync_workflows(&conn, &server_cfg.workflows)
                .map_err(|e| dbward_core::Error::Server(e.to_string()))?;
            dbward_server::db::sync_execution_policies(&conn, &server_cfg.execution_policies)
                .map_err(|e| dbward_core::Error::Server(e.to_string()))?;
            dbward_server::db::sync_result_policies(&conn, &server_cfg.result_policies)
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
            };
            let addr: std::net::SocketAddr = listen
                .parse()
                .map_err(|e: std::net::AddrParseError| dbward_core::Error::Server(e.to_string()))?;
            dbward_server::start(addr, state).await
        }
        ServerAction::Token { action } => match action {
            TokenAction::Create { user, role, data } => {
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
                };
                let (token_id, raw_token) = dbward_server::auth::create_token(&state, user, *role)
                    .await
                    .map_err(dbward_core::Error::Server)?;
                println!("Token created:");
                println!("  ID:    {token_id}");
                println!("  Token: {raw_token}");
                println!("  User:  {user}");
                println!("  Role:  {role}");
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
        assert!(matches!(parse_role("admin"), Ok(dbward_core::Role::Admin)));
        assert!(matches!(
            parse_role("developer"),
            Ok(dbward_core::Role::Developer)
        ));
        assert!(matches!(
            parse_role("readonly"),
            Ok(dbward_core::Role::Readonly)
        ));
    }

    #[test]
    fn parse_role_invalid() {
        assert!(parse_role("superuser").is_err());
    }
}
