use std::path::PathBuf;

use clap::{Parser, Subcommand};

use dbward_core::{Engine, Role};
use dbward_migrate::Migrator;

use crate::config_loader;
use crate::mcp;
use crate::server_client;

fn parse_role(s: &str) -> Result<Role, String> {
    match s {
        "admin" => Ok(Role::Admin),
        "developer" => Ok(Role::Developer),
        "readonly" => Ok(Role::Readonly),
        _ => Err(format!("unknown role: {s}")),
    }
}

#[derive(Parser)]
#[command(name = "dbward", about = "DB operations workflow + approval engine")]
pub struct Cli {
    /// Path to config file
    #[arg(long, default_value = "dbward.toml")]
    config: PathBuf,

    /// Override database URL
    #[arg(long, env = "DBWARD_DATABASE_URL")]
    database_url: Option<String>,

    /// Override environment
    #[arg(long, env = "DBWARD_ENV")]
    environment: Option<String>,

    /// Override role
    #[arg(long, env = "DBWARD_ROLE", value_parser = parse_role)]
    role: Option<Role>,

    /// Server URL for server mode
    #[arg(long, env = "DBWARD_SERVER_URL")]
    server: Option<String>,

    /// API token for server authentication
    #[arg(long, env = "DBWARD_SERVER_TOKEN")]
    token: Option<String>,

    /// Path to server's public key (signing.pub) for token verification
    #[arg(long, env = "DBWARD_PUBLIC_KEY")]
    public_key: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize dbward configuration
    Init {
        /// Non-interactive mode (for CI)
        #[arg(long)]
        non_interactive: bool,
        /// Overwrite existing dbward.toml
        #[arg(long)]
        force: bool,
    },
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
    },
    /// Search audit log (server mode only)
    Audit,
    /// Start MCP stdio server
    Mcp,
    /// Start the dbward HTTP server
    Server {
        #[command(subcommand)]
        action: ServerAction,
    },
    /// Approve a pending request
    Approve {
        /// Request ID to approve
        id: String,
    },
    /// Reject a pending request
    Reject {
        /// Request ID to reject
        id: String,
    },
    /// List pending requests (server mode)
    List,
    /// Resume execution of an approved request
    Resume {
        /// Request ID to resume
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
        /// Server config file (webhooks, etc.)
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
    /// Create a new API token
    Create {
        #[arg(long)]
        user: String,
        #[arg(long, value_parser = parse_role)]
        role: Role,
        #[arg(long, default_value = "dbward.db")]
        data: String,
    },
    /// Revoke an API token
    Revoke {
        #[arg(long)]
        id: String,
        #[arg(long, default_value = "dbward.db")]
        data: String,
    },
}

#[derive(Subcommand)]
enum MigrateAction {
    /// Apply pending migrations
    Up {
        #[arg(long)]
        count: Option<usize>,
    },
    /// Rollback migrations
    Down {
        #[arg(long, default_value = "1")]
        count: usize,
    },
    /// Show migration status
    Status,
    /// Create a new migration file
    Create {
        /// Migration name
        name: String,
    },
}

fn require_server_flags(cli: &Cli) -> Result<(&str, &str), dbward_core::Error> {
    let server = cli
        .server
        .as_deref()
        .ok_or_else(|| dbward_core::Error::Config("--server is required (or set [server] url in dbward.toml)".into()))?;
    let token = cli
        .token
        .as_deref()
        .ok_or_else(|| dbward_core::Error::Config("--token is required (or set [server] token in dbward.toml)".into()))?;
    Ok((server, token))
}

/// Merge config file [server] section into CLI flags (CLI flags take precedence).
fn apply_server_config(cli: &mut Cli, config: &dbward_core::Config) {
    if let Some(ref sc) = config.server {
        if cli.server.is_none() {
            cli.server = Some(sc.url.clone());
        }
        if cli.token.is_none() {
            cli.token = sc.token.clone();
        }
        if cli.public_key.is_none() {
            cli.public_key = sc.public_key.as_ref().map(std::path::PathBuf::from);
        }
    }
}

pub async fn run(mut cli: Cli) -> Result<(), dbward_core::Error> {
    // Load config early to merge server settings
    if let Ok(config) = config_loader::load(&cli.config, &cli.database_url, &cli.environment, &cli.role) {
        apply_server_config(&mut cli, &config);
    }
    // Handle init before anything else
    if let Command::Init { non_interactive, force } = &cli.command {
        return run_init(&cli, *non_interactive, *force).await;
    }

    // Handle approve/reject first (always require --server)
    match &cli.command {
        Command::Approve { id } => {
            let (server, token) = require_server_flags(&cli)?;
            let client = server_client::ServerClient::new(server, token);
            let body = client.approve(id).await?;
            println!("{}", serde_json::to_string_pretty(&body)?);
            return Ok(());
        }
        Command::Reject { id } => {
            let (server, token) = require_server_flags(&cli)?;
            let client = server_client::ServerClient::new(server, token);
            let body = client.reject(id).await?;
            println!("{}", serde_json::to_string_pretty(&body)?);
            return Ok(());
        }
        Command::List => {
            let (server, token) = require_server_flags(&cli)?;
            let client = server_client::ServerClient::new(server, token);
            let body = client.list_requests().await?;
            let empty = vec![];
            let requests = body.as_array().unwrap_or(&empty);
            if requests.is_empty() {
                println!("No requests.");
            } else {
                for r in requests {
                    let id = r["id"].as_str().unwrap_or("?");
                    let status = r["status"].as_str().unwrap_or("?");
                    let user = r["user"].as_str().unwrap_or("?");
                    let op = r["operation"].as_str().unwrap_or("?");
                    let env = r["environment"].as_str().unwrap_or("?");
                    let detail = r["detail"].as_str().unwrap_or("");
                    let short_detail = if detail.len() > 60 { &detail[..60] } else { detail };
                    println!("[{status}] {id}  {user}  {op}  {env}  {short_detail}");
                }
            }
            return Ok(());
        }
        Command::Resume { id } => {
            let (server, token) = require_server_flags(&cli)?;
            let client = server_client::ServerClient::new(server, token);

            let public_key_path = cli.public_key.as_deref()
                .ok_or_else(|| dbward_core::Error::Config("--public-key is required".into()))?;
            let public_key = dbward_core::token::load_public_key(public_key_path)?;

            let resp = client.get_request(id).await?;
            let status = resp["status"].as_str().unwrap_or("");
            if status != "approved" && status != "auto_approved" {
                return Err(dbward_core::Error::Config(format!("request is {status}, not approved")));
            }

            let exec_token: dbward_core::token::ExecutionToken =
                serde_json::from_value(resp["execution_token"].clone())
                    .map_err(|e| dbward_core::Error::Config(format!("missing execution_token: {e}")))?;

            let operation = resp["operation"].as_str().unwrap_or("");
            let environment = resp["environment"].as_str().unwrap_or("");
            let detail = resp["detail"].as_str().unwrap_or("");

            dbward_core::token::verify_token(&exec_token, &public_key, operation, environment, detail)?;

            let config = config_loader::load(&cli.config, &cli.database_url, &cli.environment, &cli.role)?;
            let mut engine = Engine::new(config.clone()).await?;
            let role = cli.role.unwrap_or(Role::Developer);

            let result_text = match operation {
                "execute_query" => {
                    let result = engine.execute_query("cli_user", role, detail).await?;
                    if result.rows.is_empty() {
                        format!("Rows affected: {}", result.rows_affected)
                    } else {
                        serde_json::to_string_pretty(&result.rows)?
                    }
                }
                "migrate_up" => {
                    let migrator = dbward_migrate::Migrator::new(engine.driver().clone(), config.migrations_dir.clone());
                    let count = detail.strip_prefix("count:").and_then(|s| s.parse().ok());
                    let count = if count == Some(0) { None } else { count };
                    let r = migrator.up(count).await?;
                    if r.applied.is_empty() { "No pending migrations.".into() }
                    else { format!("Applied {} migration(s):\n{}", r.applied.len(), r.applied.join("\n")) }
                }
                "migrate_down" => {
                    let migrator = dbward_migrate::Migrator::new(engine.driver().clone(), config.migrations_dir.clone());
                    let count = detail.strip_prefix("count:").and_then(|s| s.parse().ok());
                    let r = migrator.down(count).await?;
                    if r.rolled_back.is_empty() { "Nothing to rollback.".into() }
                    else { format!("Rolled back:\n{}", r.rolled_back.join("\n")) }
                }
                _ => format!("Executed operation: {operation}"),
            };

            client.complete_request(id, true).await?;
            println!("{result_text}");
            return Ok(());
        }
        _ => {}
    }

    // Server mode: route through approval flow
    if cli.server.is_some() {
        return run_server_mode(cli).await;
    }

    // Direct mode
    run_direct_mode(cli).await
}

async fn run_server_mode(cli: Cli) -> Result<(), dbward_core::Error> {
    let (server_url, api_token) = require_server_flags(&cli)?;
    let sc = server_client::ServerClient::new(server_url, api_token);

    let public_key_path = cli
        .public_key
        .as_deref()
        .ok_or_else(|| dbward_core::Error::Config("--public-key is required in server mode".into()))?;
    let public_key = dbward_core::token::load_public_key(public_key_path)?;

    let config = config_loader::load(&cli.config, &cli.database_url, &cli.environment, &cli.role)?;
    let env_str = config.environment.to_string();

    match cli.command {
        Command::Execute { ref sql, emergency, ref reason } => {
            let (id, status, token) = sc
                .create_request("execute_query", &env_str, sql, emergency, reason.as_deref())
                .await?;

            let token = match status.as_str() {
                "auto_approved" | "break_glass" => token.expect("should include token"),
                "pending" => {
                    eprintln!("Request {id} requires approval.");
                    let (_status, token) = sc
                        .poll_request(
                            &id,
                            std::time::Duration::from_secs(2),
                            std::time::Duration::from_secs(1800),
                        )
                        .await?;
                    token.expect("approved should include token")
                }
                _ => return Err(dbward_core::Error::Config(format!("unexpected status: {status}"))),
            };

            dbward_core::token::verify_token(&token, &public_key, "execute_query", &env_str, sql)?;

            let mut engine = Engine::new(config).await?;
            let role = cli.role.unwrap_or(Role::Developer);
            let result = engine.execute_query("cli_user", role, sql).await?;

            sc.complete_request(&id, true).await?;

            if result.rows.is_empty() {
                println!("Rows affected: {}", result.rows_affected);
            } else {
                println!("{}", serde_json::to_string_pretty(&result.rows)?);
            }
            Ok(())
        }
        Command::Migrate { ref action } => {
            let (operation, detail) = match action {
                MigrateAction::Up { count } => {
                    ("migrate_up", format!("count:{}", count.unwrap_or(0)))
                }
                MigrateAction::Down { count } => ("migrate_down", format!("count:{count}")),
                MigrateAction::Status => {
                    // Status is read-only, still goes through server for audit
                    let (id, status, token) = sc
                        .create_request("migrate_status", &env_str, "", false, None)
                        .await?;
                    let token = resolve_token(&sc, &id, status, token).await?;
                    dbward_core::token::verify_token(&token, &public_key, "migrate_status", &env_str, "")?;

                    let engine = Engine::new(config).await?;
                    let migrator = Migrator::new(engine.driver().clone(), config_loader::load(&cli.config, &cli.database_url, &cli.environment, &cli.role)?.migrations_dir);
                    let statuses = migrator.status().await?;
                    sc.complete_request(&id, true).await?;

                    if statuses.is_empty() {
                        println!("No migration files found.");
                    } else {
                        for s in &statuses {
                            let mark = if s.applied { "[x]" } else { "[ ]" };
                            println!("{mark} {}_{}", s.version, s.name);
                        }
                    }
                    return Ok(());
                }
                MigrateAction::Create { .. } => {
                    // Create is local-only (no DB operation)
                    let migrator = Migrator::new(
                        Engine::new(config).await?.driver().clone(),
                        config_loader::load(&cli.config, &cli.database_url, &cli.environment, &cli.role)?.migrations_dir,
                    );
                    if let MigrateAction::Create { name } = action {
                        let path = migrator.create(name)?;
                        println!("Created: {}", path.display());
                    }
                    return Ok(());
                }
            };

            let (id, status, token) = sc.create_request(operation, &env_str, &detail, false, None).await?;
            let token = resolve_token(&sc, &id, status, token).await?;
            dbward_core::token::verify_token(&token, &public_key, operation, &env_str, &detail)?;

            let engine = Engine::new(config.clone()).await?;
            let migrator = Migrator::new(engine.driver().clone(), config.migrations_dir.clone());

            match action {
                MigrateAction::Up { count } => {
                    let result = migrator.up(*count).await?;
                    sc.complete_request(&id, true).await?;
                    if result.applied.is_empty() {
                        println!("No pending migrations.");
                    } else {
                        for m in &result.applied {
                            println!("Applied: {m}");
                        }
                        println!("Applied {} migration(s).", result.applied.len());
                    }
                }
                MigrateAction::Down { count } => {
                    let result = migrator.down(Some(*count)).await?;
                    sc.complete_request(&id, true).await?;
                    if result.rolled_back.is_empty() {
                        println!("Nothing to rollback.");
                    } else {
                        for m in &result.rolled_back {
                            println!("Rolled back: {m}");
                        }
                    }
                }
                _ => unreachable!(),
            }
            Ok(())
        }
        Command::Mcp => {
            mcp::run_stdio_server_mode(
                config,
                server_client::ServerClient::new(server_url, api_token),
                public_key,
            )
            .await
        }
        Command::Audit => {
            println!("Audit search via server: not yet implemented.");
            Ok(())
        }
        _ => unreachable!(),
    }
}

async fn resolve_token(
    sc: &server_client::ServerClient,
    id: &str,
    status: String,
    token: Option<dbward_core::token::ExecutionToken>,
) -> Result<dbward_core::token::ExecutionToken, dbward_core::Error> {
    match status.as_str() {
        "auto_approved" => Ok(token.expect("auto_approved should include token")),
        "pending" => {
            eprintln!("Request {id} requires approval.");
            let (_status, token) = sc
                .poll_request(
                    id,
                    std::time::Duration::from_secs(2),
                    std::time::Duration::from_secs(1800),
                )
                .await?;
            Ok(token.expect("approved should include token"))
        }
        _ => Err(dbward_core::Error::Config(format!("unexpected status: {status}"))),
    }
}

async fn run_direct_mode(cli: Cli) -> Result<(), dbward_core::Error> {
    // Direct mode is only allowed for development environment
    if let Some(ref env) = cli.environment {
        if env != "development" {
            return Err(dbward_core::Error::Config(format!(
                "direct mode is only allowed for development environment (got: {env}). Use --server for {env}."
            )));
        }
    }
    // Also check config file
    if let Ok(config) = config_loader::load(&cli.config, &cli.database_url, &cli.environment, &cli.role) {
        if config.environment != dbward_core::Environment::Development {
            return Err(dbward_core::Error::Config(format!(
                "direct mode is only allowed for development environment (got: {}). Use --server for non-development environments.",
                config.environment
            )));
        }
    }

    match cli.command {
        Command::Mcp => {
            let config = config_loader::load(&cli.config, &cli.database_url, &cli.environment, &cli.role)?;
            mcp::run_stdio(config).await
        }
        Command::Migrate { action } => {
            let config = config_loader::load(&cli.config, &cli.database_url, &cli.environment, &cli.role)?;
            let engine = Engine::new(config.clone()).await?;
            let migrator = Migrator::new(engine.driver().clone(), config.migrations_dir.clone());

            match action {
                MigrateAction::Up { count } => {
                    let result = migrator.up(count).await?;
                    if result.applied.is_empty() {
                        println!("No pending migrations.");
                    } else {
                        for m in &result.applied {
                            println!("Applied: {m}");
                        }
                        println!("Applied {} migration(s).", result.applied.len());
                    }
                }
                MigrateAction::Down { count } => {
                    let result = migrator.down(Some(count)).await?;
                    if result.rolled_back.is_empty() {
                        println!("Nothing to rollback.");
                    } else {
                        for m in &result.rolled_back {
                            println!("Rolled back: {m}");
                        }
                    }
                }
                MigrateAction::Status => {
                    let statuses = migrator.status().await?;
                    if statuses.is_empty() {
                        println!("No migration files found.");
                    } else {
                        for s in &statuses {
                            let mark = if s.applied { "[x]" } else { "[ ]" };
                            println!("{mark} {}_{}", s.version, s.name);
                        }
                    }
                }
                MigrateAction::Create { name } => {
                    let path = migrator.create(&name)?;
                    println!("Created: {}", path.display());
                }
            }
            Ok(())
        }
        Command::Execute { sql, .. } => {
            let config = config_loader::load(&cli.config, &cli.database_url, &cli.environment, &cli.role)?;
            let role = config.role;
            let mut engine = Engine::new(config).await?;
            let result = engine.execute_query("cli_user", role, &sql).await?;

            if result.rows.is_empty() {
                println!("Rows affected: {}", result.rows_affected);
            } else {
                println!("{}", serde_json::to_string_pretty(&result.rows)?);
            }
            Ok(())
        }
        Command::Audit => {
            println!("Audit search is only available in server mode (--server).");
            Ok(())
        }
        Command::Server { action } => match action {
            ServerAction::Start { listen, data, config: server_config_path } => {
                let server_cfg = dbward_server::server_config::ServerConfig::load(
                    std::path::Path::new(&server_config_path),
                )
                .map_err(|e| dbward_core::Error::Config(e))?;

                let conn = rusqlite::Connection::open(&data)
                    .map_err(|e| dbward_core::Error::Config(e.to_string()))?;
                dbward_server::db::init(&conn)
                    .map_err(|e| dbward_core::Error::Config(e.to_string()))?;
                let data_path = std::path::Path::new(&data)
                    .parent()
                    .unwrap_or(std::path::Path::new("."));
                let token_signer =
                    dbward_server::token::TokenSigner::load_or_generate(data_path)
                        .map_err(|e| dbward_core::Error::Config(e))?;
                let webhooks = dbward_server::webhook::WebhookDispatcher::new(server_cfg.webhooks);
                let state = dbward_server::AppState {
                    sqlite: std::sync::Arc::new(std::sync::Mutex::new(conn)),
                    token_signer: std::sync::Arc::new(token_signer),
                    webhooks: std::sync::Arc::new(webhooks),
                };
                let addr: std::net::SocketAddr = listen
                    .parse()
                    .map_err(|e: std::net::AddrParseError| dbward_core::Error::Config(e.to_string()))?;
                dbward_server::start(addr, state).await
            }
            ServerAction::Token { action } => match action {
                TokenAction::Create { user, role, data } => {
                    let conn = rusqlite::Connection::open(&data)
                        .map_err(|e| dbward_core::Error::Config(e.to_string()))?;
                    dbward_server::db::init(&conn)
                        .map_err(|e| dbward_core::Error::Config(e.to_string()))?;
                    let data_path = std::path::Path::new(&data)
                        .parent()
                        .unwrap_or(std::path::Path::new("."));
                    let token_signer =
                        dbward_server::token::TokenSigner::load_or_generate(data_path)
                            .map_err(|e| dbward_core::Error::Config(e))?;
                    let state = dbward_server::AppState {
                        sqlite: std::sync::Arc::new(std::sync::Mutex::new(conn)),
                        token_signer: std::sync::Arc::new(token_signer),
                        webhooks: std::sync::Arc::new(dbward_server::webhook::WebhookDispatcher::empty()),
                    };
                    let (token_id, raw_token) =
                        dbward_server::auth::create_token(&state, &user, role)
                            .map_err(|e| dbward_core::Error::Config(e))?;
                    println!("Token created:");
                    println!("  ID:    {token_id}");
                    println!("  Token: {raw_token}");
                    println!("  User:  {user}");
                    println!("  Role:  {role}");
                    println!("\nSave this token — it cannot be retrieved later.");
                    Ok(())
                }
                TokenAction::Revoke { id, data } => {
                    let conn = rusqlite::Connection::open(&data)
                        .map_err(|e| dbward_core::Error::Config(e.to_string()))?;
                    let data_path = std::path::Path::new(&data)
                        .parent()
                        .unwrap_or(std::path::Path::new("."));
                    let token_signer =
                        dbward_server::token::TokenSigner::load_or_generate(data_path)
                            .map_err(|e| dbward_core::Error::Config(e))?;
                    let state = dbward_server::AppState {
                        sqlite: std::sync::Arc::new(std::sync::Mutex::new(conn)),
                        token_signer: std::sync::Arc::new(token_signer),
                        webhooks: std::sync::Arc::new(dbward_server::webhook::WebhookDispatcher::empty()),
                    };
                    dbward_server::auth::revoke_token(&state, &id)
                        .map_err(|e| dbward_core::Error::Config(e))?;
                    println!("Token {id} revoked.");
                    Ok(())
                }
            },
        },
        // Approve/Reject handled before this point
        Command::Approve { .. } | Command::Reject { .. } | Command::List | Command::Resume { .. } | Command::Init { .. } => unreachable!(),
    }
}

async fn run_init(cli: &Cli, non_interactive: bool, force: bool) -> Result<(), dbward_core::Error> {
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
        if trimmed.is_empty() { default.to_string() } else { trimmed.to_string() }
    };

    // Database URL
    let db_url = cli.database_url.clone().unwrap_or_else(|| {
        prompt("Database URL", "postgres://localhost:5432/mydb")
    });

    // Test connection
    eprint!("Testing database connection... ");
    match dbward_core::driver::connect(&db_url).await {
        Ok(drv) => {
            match drv.query("SELECT 1 AS ok").await {
                Ok(_) => eprintln!("✓"),
                Err(e) => eprintln!("✗ query failed: {e}"),
            }
        }
        Err(e) => eprintln!("✗ {e}"),
    }

    let environment = cli.environment.clone().unwrap_or_else(|| {
        prompt("Environment", "development")
    });
    let role_str = cli.role.map(|r| r.to_string()).unwrap_or_else(|| {
        prompt("Role", "developer")
    });
    let migrations_dir = prompt("Migrations directory", "db/migrations");

    // Server (optional)
    let server_url = cli.server.clone().unwrap_or_else(|| {
        prompt("Server URL (leave empty for direct mode)", "")
    });

    let mut server_section = String::new();
    if !server_url.is_empty() {
        // Fetch public key
        let pub_key_path = ".dbward/signing.pub";
        eprint!("Fetching public key from {server_url}... ");
        match reqwest::get(format!("{}/api/public-key", server_url.trim_end_matches('/'))).await {
            Ok(resp) if resp.status().is_success() => {
                let bytes = resp.bytes().await.unwrap_or_default();
                if bytes.len() == 32 {
                    std::fs::create_dir_all(".dbward").ok();
                    std::fs::write(pub_key_path, &bytes).ok();
                    eprintln!("✓ saved to {pub_key_path}");
                } else {
                    eprintln!("✗ unexpected key size");
                }
            }
            Ok(resp) => eprintln!("✗ server returned {}", resp.status()),
            Err(e) => eprintln!("✗ {e}"),
        }

        server_section = format!(
            r#"
[server]
url = "{server_url}"
# token = "dbw_..."  # Set via DBWARD_SERVER_TOKEN env var
public_key = "{pub_key_path}"
"#
        );
    }

    let toml_content = format!(
        r#"environment = "{environment}"
role = "{role_str}"
migrations_dir = "{migrations_dir}"

[database]
url = "{db_url}"
{server_section}"#
    );

    std::fs::write(config_path, toml_content.trim_end()).map_err(dbward_core::Error::Io)?;
    eprintln!("Created {}", config_path.display());

    // Add .dbward/ to .gitignore
    if std::path::Path::new(".git").exists() && !server_url.is_empty() {
        let gitignore = std::path::Path::new(".gitignore");
        let content = std::fs::read_to_string(gitignore).unwrap_or_default();
        if !content.contains(".dbward/") {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(gitignore)
                .map_err(dbward_core::Error::Io)?;
            writeln!(f, "\n.dbward/").map_err(dbward_core::Error::Io)?;
            eprintln!("Added .dbward/ to .gitignore");
        }
    }

    Ok(())
}
