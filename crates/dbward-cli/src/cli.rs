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
    /// Run database migrations
    Migrate {
        #[command(subcommand)]
        action: MigrateAction,
    },
    /// Execute a SQL query
    Execute {
        /// SQL statement to execute
        sql: String,
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
}

#[derive(Subcommand)]
enum ServerAction {
    /// Start the HTTP server
    Start {
        #[arg(long, default_value = "127.0.0.1:3000")]
        listen: String,
        #[arg(long, default_value = "dbward.db")]
        data: String,
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
        .ok_or_else(|| dbward_core::Error::Config("--server is required".into()))?;
    let token = cli
        .token
        .as_deref()
        .ok_or_else(|| dbward_core::Error::Config("--token is required".into()))?;
    Ok((server, token))
}

pub async fn run(cli: Cli) -> Result<(), dbward_core::Error> {
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
        Command::Execute { ref sql } => {
            let (id, status, token) = sc
                .create_request("execute_query", &env_str, sql)
                .await?;

            let token = match status.as_str() {
                "auto_approved" => token.expect("auto_approved should include token"),
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
                        .create_request("migrate_status", &env_str, "")
                        .await?;
                    let token = resolve_token(&sc, &id, status, token).await?;
                    dbward_core::token::verify_token(&token, &public_key, "migrate_status", &env_str, "")?;

                    let engine = Engine::new(config).await?;
                    let migrator = Migrator::new(engine.pool().clone(), config_loader::load(&cli.config, &cli.database_url, &cli.environment, &cli.role)?.migrations_dir);
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
                        Engine::new(config).await?.pool().clone(),
                        config_loader::load(&cli.config, &cli.database_url, &cli.environment, &cli.role)?.migrations_dir,
                    );
                    if let MigrateAction::Create { name } = action {
                        let path = migrator.create(name)?;
                        println!("Created: {}", path.display());
                    }
                    return Ok(());
                }
            };

            let (id, status, token) = sc.create_request(operation, &env_str, &detail).await?;
            let token = resolve_token(&sc, &id, status, token).await?;
            dbward_core::token::verify_token(&token, &public_key, operation, &env_str, &detail)?;

            let engine = Engine::new(config.clone()).await?;
            let migrator = Migrator::new(engine.pool().clone(), config.migrations_dir.clone());

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
    match cli.command {
        Command::Mcp => {
            let config = config_loader::load(&cli.config, &cli.database_url, &cli.environment, &cli.role)?;
            mcp::run_stdio(config).await
        }
        Command::Migrate { action } => {
            let config = config_loader::load(&cli.config, &cli.database_url, &cli.environment, &cli.role)?;
            let engine = Engine::new(config.clone()).await?;
            let migrator = Migrator::new(engine.pool().clone(), config.migrations_dir.clone());

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
        Command::Execute { sql } => {
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
            ServerAction::Start { listen, data } => {
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
                    };
                    dbward_server::auth::revoke_token(&state, &id)
                        .map_err(|e| dbward_core::Error::Config(e))?;
                    println!("Token {id} revoked.");
                    Ok(())
                }
            },
        },
        // Approve/Reject handled before this point
        Command::Approve { .. } | Command::Reject { .. } => unreachable!(),
    }
}
