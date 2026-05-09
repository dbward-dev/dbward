use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

use crate::display::*;
use dbward_core::ClientConfig;

use crate::config_loader;
use crate::mcp;
use crate::oidc_login;
use crate::self_update;
use crate::server_client;


#[derive(Parser)]
#[command(name = "dbward", about = "DB operations workflow + approval engine")]
pub struct Cli {
    /// Path to config file
    #[arg(long, default_value = "dbward.toml")]
    config: PathBuf,

    /// Select named database from config
    #[arg(long, env = "DBWARD_DATABASE", global = true)]
    database: Option<String>,

    /// Override environment for this request
    #[arg(long, env = "DBWARD_ENV", global = true)]
    environment: Option<String>,

    /// Output format: human (default) or json
    #[arg(long, default_value = "human", value_parser = ["human", "json"], global = true)]
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
        /// Ticket identifier to attach as metadata
        #[arg(long)]
        ticket: Option<String>,
        /// Repository identifier to attach as metadata
        #[arg(long)]
        repo: Option<String>,
        /// Optional idempotency key for deduplicating identical submissions
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
        /// Share result with specified principals (e.g. group:backend-team, user:bob)
        #[arg(long = "share-with")]
        share_with: Vec<String>,
        /// Do not persist result to server storage
        #[arg(long = "no-store")]
        no_store: bool,
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
        #[arg(long)]
        event_type: Option<String>,
        #[arg(long)]
        category: Option<String>,
        #[arg(long)]
        outcome: Option<String>,
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        until: Option<String>,
        /// Verify hash chain integrity
        #[arg(long)]
        verify: bool,
        /// Output format: table (default), json, csv
        #[arg(long, value_name = "FORMAT", default_value = "table")]
        output: String,
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
    /// Manage requests
    Request {
        #[command(subcommand)]
        action: RequestAction,
    },
    /// Manage results
    Result {
        #[command(subcommand)]
        action: ResultAction,
    },
    /// Update dbward to the latest version
    SelfUpdate,
    /// Show agent status (admin only)
    Agents,
}

#[derive(Subcommand)]
enum RequestAction {
    /// List requests
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
        /// Filter by requesting user
        #[arg(long)]
        user: Option<String>,
    },
    /// Show request details
    Show { id: String },
    /// Approve a pending request
    Approve {
        id: String,
        #[arg(long)]
        comment: Option<String>,
    },
    /// Reject a pending request
    Reject {
        id: String,
        #[arg(long, alias = "comment")]
        reason: Option<String>,
    },
    /// Cancel a request
    Cancel {
        id: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Dispatch and wait for result
    Resume {
        id: String,
        /// Save result to a specific file
        #[arg(long)]
        output: Option<PathBuf>,
        /// Do not save result locally
        #[arg(long)]
        no_save: bool,
    },
    /// Get execution result
    Result { id: String },
}

#[derive(Subcommand)]
enum ResultAction {
    /// List shared results accessible to you
    List,
    /// Get stored result content by request ID
    Get {
        /// Request ID (full UUID or 8-char short ID)
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
        role: String,
        /// Create an agent token instead of a user token
        #[arg(long)]
        agent: bool,
        /// Comma-separated groups for this token
        #[arg(long, value_delimiter = ',')]
        groups: Vec<String>,
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
        /// Ticket identifier to attach as metadata
        #[arg(long)]
        ticket: Option<String>,
        /// Repository identifier to attach as metadata
        #[arg(long)]
        repo: Option<String>,
        /// Optional idempotency key for deduplicating identical submissions
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
        /// Share result with specified users/roles for persistent storage
        #[arg(long = "share-with")]
        share_with: Vec<String>,
    },
    Down {
        #[arg(long, default_value = "1")]
        count: usize,
        /// Ticket identifier to attach as metadata
        #[arg(long)]
        ticket: Option<String>,
        /// Repository identifier to attach as metadata
        #[arg(long)]
        repo: Option<String>,
        /// Optional idempotency key for deduplicating identical submissions
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
    Status {
        /// Ticket identifier to attach as metadata
        #[arg(long)]
        ticket: Option<String>,
        /// Repository identifier to attach as metadata
        #[arg(long)]
        repo: Option<String>,
        /// Optional idempotency key for deduplicating identical submissions
        #[arg(long = "idempotency-key")]
        idempotency_key: Option<String>,
    },
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
            Err(e) => {
                return Err(dbward_core::Error::Auth(e.to_string()));
            }
        }
    }

    Err(dbward_core::Error::Auth(
        "no authentication configured: set [server.oidc] or server.token in dbward.toml".into(),
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
            dbward_agent::init_logging();
            let agent_config = config_loader::load_agent(agent_config_path)?;
            return dbward_agent::run(agent_config).await;
        }
        Command::Dev { database_url, port } => {
            return run_dev(database_url, *port).await;
        }
        Command::SelfUpdate => {
            return self_update::run_self_update().await;
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
            oidc_login::login_device(
                &oc.issuer,
                &oc.client_id,
                oc.discovery_url.as_deref(),
                oc.browser_url.as_deref(),
                oc.backchannel_url.as_deref(),
            )
            .await
        } else {
            oidc_login::login(
                &oc.issuer,
                &oc.client_id,
                oc.discovery_url.as_deref(),
                oc.backchannel_url.as_deref(),
            )
            .await
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
            ref ticket,
            ref repo,
            ref idempotency_key,
            ref share_with,
            no_store,
        } => {
            let metadata = build_request_metadata(ticket.as_deref(), repo.as_deref());
            let sw = if share_with.is_empty() {
                None
            } else {
                Some(share_with.as_slice())
            };
            let (id, status, _token, approvers) = sc
                .create_request(server_client::CreateRequest {
                    operation: "execute_query",
                    environment: env_str,
                    database: &db_name,
                    detail: sql,
                    emergency,
                    reason: reason.as_deref(),
                    metadata: metadata.as_ref(),
                    idempotency_key: idempotency_key.as_deref(),
                    share_with: sw,
                    no_store,
                })
                .await?;
            if no_store {
                eprintln!("⚠ --no-store: result will not be persisted. If you disconnect, it cannot be recovered.");
            }

            match status.as_str() {
                "dispatched" | "break_glass" | "running" => {
                    let resp = sc.wait_for_result(&id).await?;
                    if json_output {
                        println!("{}", serde_json::to_string_pretty(&resp)?);
                    } else {
                        print_execution_result(&resp);
                    }
                    save_result(&id, &resp, output.as_deref(), no_save);
                }
                "executed" | "failed" => {
                    let resp = sc.get_terminal_result(&id).await?;
                    if json_output {
                        println!("{}", serde_json::to_string_pretty(&resp)?);
                    } else {
                        print_execution_result(&resp);
                    }
                    save_result(&id, &resp, output.as_deref(), no_save);
                }
                "approved" | "auto_approved" => {
                    eprintln!("Request {id} is approved but not yet dispatched.");
                    eprintln!("Run: dbward request resume {id}");
                }
                "pending" => {
                    eprintln!("Request {id} requires approval.");
                    if !approvers.is_empty() {
                        eprintln!("  Approvers: {}", approvers.join(", "));
                    }
                    eprintln!("Run: dbward request resume {id}");
                    std::process::exit(2);
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
            let (operation, detail, metadata, idempotency_key, migrate_share_with) = match action {
                MigrateAction::Up {
                    count,
                    ticket,
                    repo,
                    idempotency_key,
                    share_with,
                } => (
                    "migrate_up",
                    dbward_migrate::build_migration_approval_detail(
                        &config.migrations_dir_for(&db_name),
                        count.unwrap_or(0),
                    )?,
                    build_request_metadata(ticket.as_deref(), repo.as_deref()),
                    idempotency_key.as_deref(),
                    share_with,
                ),
                MigrateAction::Down {
                    count,
                    ticket,
                    repo,
                    idempotency_key,
                } => (
                    "migrate_down",
                    dbward_migrate::build_migration_approval_detail(
                        &config.migrations_dir_for(&db_name),
                        *count,
                    )?,
                    build_request_metadata(ticket.as_deref(), repo.as_deref()),
                    idempotency_key.as_deref(),
                    &vec![],
                ),
                MigrateAction::Status {
                    ticket,
                    repo,
                    idempotency_key,
                } => (
                    "migrate_status",
                    String::new(),
                    build_request_metadata(ticket.as_deref(), repo.as_deref()),
                    idempotency_key.as_deref(),
                    &vec![],
                ),
                MigrateAction::Create { .. } => unreachable!(),
            };

            let sw = if migrate_share_with.is_empty() {
                None
            } else {
                Some(migrate_share_with.as_slice())
            };
            let (id, status, _token, approvers) = sc
                .create_request(server_client::CreateRequest {
                    operation,
                    environment: env_str,
                    database: &db_name,
                    detail: &detail,
                    emergency: false,
                    reason: None,
                    metadata: metadata.as_ref(),
                    idempotency_key,
                    share_with: sw,
                    no_store: false,
                })
                .await?;

            match status.as_str() {
                "dispatched" | "break_glass" | "running" => {
                    let resp = sc.wait_for_result(&id).await?;
                    if json_output {
                        println!("{}", serde_json::to_string_pretty(&resp)?);
                    } else {
                        print_execution_result(&resp);
                    }
                }
                "pending" => {
                    eprintln!("Request {id} requires approval.");
                    if !approvers.is_empty() {
                        eprintln!("  Approvers: {}", approvers.join(", "));
                    }
                    eprintln!("Run: dbward request resume {id}");
                    std::process::exit(2);
                }
                "approved" | "auto_approved" => {
                    eprintln!("Request {id} is approved but not yet dispatched.");
                    eprintln!("Run: dbward request resume {id}");
                }
                "executed" | "failed" => {
                    let resp = sc.get_terminal_result(&id).await?;
                    if json_output {
                        println!("{}", serde_json::to_string_pretty(&resp)?);
                    } else {
                        print_execution_result(&resp);
                    }
                }
                _ => {
                    return Err(dbward_core::Error::Server(format!(
                        "unexpected status: {status}"
                    )));
                }
            }
            Ok(())
        }
        Command::Request { action } => match action {
            RequestAction::Approve { id, comment } => {
                match sc.approve(&id, comment.as_deref()).await {
                    Ok(body) => {
                        if json_output {
                            println!("{}", serde_json::to_string_pretty(&body)?);
                        } else {
                            print_approve_result(&body, &id);
                        }
                    }
                    Err(e) => {
                        if e.status == 404 {
                            return Err(dbward_core::Error::Server(format!(
                                "Request {id} not found"
                            )));
                        }
                        let body_lower = e.body.to_lowercase();
                        if e.status == 409
                            && (body_lower.contains("already approved")
                                || body_lower.contains("already dispatched"))
                        {
                            return Err(dbward_core::Error::Server(format!(
                                "Request is already approved. Run: dbward request resume {id}"
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
            RequestAction::Reject { id, reason } => {
                match sc.reject(&id, reason.as_deref()).await {
                    Ok(body) => {
                        if json_output {
                            println!("{}", serde_json::to_string_pretty(&body)?);
                        } else {
                            println!("Rejected: {id}");
                        }
                    }
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
            RequestAction::Cancel { id, reason } => {
                // Check if running — prompt for confirmation
                let req_info = sc.get_json(&format!("/api/requests/{id}")).await;
                if let Ok(info) = &req_info {
                    if info["status"].as_str() == Some("running") {
                        eprintln!("⚠ Query is currently executing on the database.");
                        eprintln!("  Cancelling will kill the running query and roll back any changes.");
                        eprint!("  Continue? [y/N] ");
                        let mut input = String::new();
                        std::io::stdin().read_line(&mut input).unwrap_or(0);
                        if !input.trim().eq_ignore_ascii_case("y") {
                            eprintln!("Aborted.");
                            return Ok(());
                        }
                    }
                }

                match sc.cancel_request(&id, reason.as_deref()).await {
                    Ok(body) => {
                        if json_output {
                            println!("{}", serde_json::to_string_pretty(&body)?);
                        } else {
                            println!("Cancelled: {id}");
                        }
                    }
                    Err(e) => {
                        if e.status == 404 {
                            return Err(dbward_core::Error::Server(format!(
                                "Request {id} not found"
                            )));
                        }
                        if e.status == 403 {
                            return Err(dbward_core::Error::Server(e.body));
                        }
                        return Err(e.into_core_error("cancel"));
                    }
                }
                Ok(())
            }
            RequestAction::List {
                limit,
                status,
                pending_for_me,
                user,
            } => {
                let body = if pending_for_me {
                    sc.list_pending_for_me(limit).await?
                } else {
                    sc.list_requests(
                        limit,
                        status.as_deref(),
                        cli.database.as_deref(),
                        cli.environment.as_deref(),
                        user.as_deref(),
                    )
                    .await?
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
                    print_request_list(requests);
                }
                Ok(())
            }
            RequestAction::Show { id } => {
                let body = sc.get_request(&id).await?;
                if json_output {
                    println!("{}", serde_json::to_string_pretty(&body)?);
                } else {
                    print_request_detail(&body);
                }
                Ok(())
            }
            RequestAction::Resume {
                id,
                output,
                no_save,
            } => {
                // Check if this is a DML re-dispatch (execution_lost → potential double execution)
                let req = sc.get_request(&id).await?;
                let status = req["status"].as_str().unwrap_or("");
                let operation = req["operation"].as_str().unwrap_or("");
                if status == "execution_lost" && operation == "execute_query" {
                    let detail = req["detail"].as_str().unwrap_or("");
                    eprintln!("⚠️  WARNING: This request previously failed with execution_lost.");
                    eprintln!("   The previous execution may have partially completed.");
                    let sql_preview: String = detail.chars().take(80).collect();
                    eprintln!("   SQL: {sql_preview}");
                    eprintln!("   Re-dispatching may cause DUPLICATE execution.");
                    eprint!("   Continue? [y/N] ");
                    std::io::Write::flush(&mut std::io::stderr()).ok();
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input).ok();
                    if !input.trim().eq_ignore_ascii_case("y") {
                        eprintln!("Aborted.");
                        return Ok(());
                    }
                }

                // Dispatch first (idempotent — safe if already dispatched)
                if let Err(e) = sc.dispatch(&id).await {
                    if e.status == 409 {
                        eprintln!(
                            "Request {id} cannot be dispatched yet (may still be pending approval)."
                        );
                        eprintln!("Check status: dbward request show {id}");
                        return Err(dbward_core::Error::Server(
                            "request not ready for dispatch".into(),
                        ));
                    }
                    return Err(e.into_core_error("dispatch"));
                }
                let resp = sc.wait_for_result(&id).await?;
                if json_output {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    print_execution_result(&resp);
                }
                save_result(&id, &resp, output.as_deref(), no_save);
                Ok(())
            }
            RequestAction::Result { id } => {
                // Try local first, then server
                match load_result(&id) {
                    Ok(resp) => {
                        if json_output {
                            println!("{}", serde_json::to_string_pretty(&resp)?);
                        } else {
                            print_execution_result(&resp);
                        }
                    }
                    Err(_) => {
                        let resp = sc.get_result_content(&id).await?;
                        if json_output {
                            println!("{}", serde_json::to_string_pretty(&resp)?);
                        } else {
                            let wrapped = serde_json::json!({"success": true, "result": resp});
                            print_execution_result(&wrapped);
                        }
                    }
                }
                Ok(())
            }
        },
        Command::Result { action } => match action {
            ResultAction::List => {
                let body = sc.list_results().await?;
                if json_output {
                    println!("{}", serde_json::to_string_pretty(&body)?);
                } else if let Some(results) = body["results"].as_array() {
                    if results.is_empty() {
                        println!("No shared results.");
                    } else {
                        println!(
                            "{:<10} {:<12} {:<10} {:<12} DETAIL",
                            "ID", "USER", "ENV", "DB"
                        );
                        for r in results {
                            println!(
                                "{:<10} {:<12} {:<10} {:<12} {}",
                                &r["request_id"].as_str().unwrap_or("")
                                    [..8.min(r["request_id"].as_str().unwrap_or("").len())],
                                r["created_by"].as_str().unwrap_or(""),
                                r["environment"].as_str().unwrap_or(""),
                                r["database"].as_str().unwrap_or(""),
                                r["detail"].as_str().unwrap_or(""),
                            );
                        }
                    }
                }
                Ok(())
            }
            ResultAction::Get { ref id } => {
                let body = sc.get_result_content(id).await?;
                println!("{}", serde_json::to_string_pretty(&body)?);
                Ok(())
            }
        },
        Command::Mcp => mcp::run_stdio(config, cli.database.as_deref(), sc).await,
        Command::Audit {
            ref limit,
            ref user,
            ref operation,
            ref status,
            ref event_type,
            ref category,
            ref outcome,
            ref since,
            ref until,
            verify,
            ref output,
        } => {
            if verify {
                let resp = sc.get_json("/api/audit/verify").await?;
                if json_output {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                } else {
                    let count = resp["verified_events"].as_u64().unwrap_or(0);
                    let intact = resp["chain_intact"].as_bool().unwrap_or(false);
                    if intact {
                        println!("✓ Hash chain intact ({count} events verified)");
                    } else {
                        let broken = resp["first_broken_id"].as_str().unwrap_or("unknown");
                        eprintln!(
                            "✗ Hash chain BROKEN at event {broken} ({count} events verified before break)"
                        );
                        std::process::exit(1);
                    }
                }
                return Ok(());
            }
            let body = sc
                .list_audit_events(
                    *limit,
                    user.as_deref(),
                    operation.as_deref(),
                    status.as_deref(),
                    event_type.as_deref(),
                    category.as_deref(),
                    outcome.as_deref(),
                    cli.environment.as_deref(),
                    since.as_deref(),
                    until.as_deref(),
                )
                .await?;
            if json_output {
                println!("{}", serde_json::to_string_pretty(&body)?);
                return Ok(());
            }
            if output == "json" {
                println!("{}", serde_json::to_string_pretty(&body["audit_events"])?);
                return Ok(());
            }
            if output == "csv" {
                let empty = vec![];
                let entries = body["audit_events"].as_array().unwrap_or(&empty);
                let total = body["total"].as_u64().unwrap_or(0);
                if total > entries.len() as u64 {
                    eprintln!(
                        "⚠ Showing {} of {} events. Use --limit to export more.",
                        entries.len(),
                        total
                    );
                }
                println!("id,event_type,event_category,outcome,actor_id,created_at,environment,database_name,operation,client_ip,resource_type,resource_id,request_id,event_hash,reason");
                for e in entries {
                    let escape = |s: &str| {
                        if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
                            format!("\"{}\"", s.replace('"', "\"\""))
                        } else {
                            s.to_string()
                        }
                    };
                    let f = |key: &str| e[key].as_str().unwrap_or("").to_string();
                    println!(
                        "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
                        escape(&f("id")),
                        escape(&f("event_type")),
                        escape(&f("event_category")),
                        escape(&f("outcome")),
                        escape(&f("actor_id")),
                        escape(&f("created_at")),
                        escape(&f("environment")),
                        escape(&f("database_name")),
                        escape(&f("operation")),
                        escape(&f("client_ip")),
                        escape(&f("resource_type")),
                        escape(&f("resource_id")),
                        escape(&f("request_id")),
                        escape(&f("event_hash")),
                        escape(&f("reason")),
                    );
                }
                return Ok(());
            }
            let empty = vec![];
            let entries = body["audit_events"].as_array().unwrap_or(&empty);
            if entries.is_empty() {
                println!("No audit events.");
            } else {
                println!(
                    "{:<10} {:<22} {:<10} {:<14} {:<10} {:<10} {:<12} DETAIL",
                    "ID", "TIMESTAMP", "USER", "EVENT", "ENV", "DATABASE", "OUTCOME"
                );
                for e in entries {
                    let id = e["id"].as_str().unwrap_or("?");
                    let short_id = &id[..id.len().min(8)];
                    let ts = e["created_at"].as_str().unwrap_or("?");
                    let ts_short = &ts[..ts.len().min(19)];
                    let actor = e["actor_id"].as_str().unwrap_or("?");
                    let event_type = e["event_type"].as_str().unwrap_or("?");
                    let env = e["environment"].as_str().unwrap_or("-");
                    let db = e["database_name"].as_str().unwrap_or("-");
                    let outcome_val = e["outcome"].as_str().unwrap_or("?");
                    let detail = e["detail_fingerprint"].as_str().unwrap_or("");
                    let short_detail = if detail.len() > 40 {
                        format!("{}...", &detail[..37])
                    } else {
                        detail.to_string()
                    };
                    println!(
                        "{:<10} {:<22} {:<10} {:<14} {:<10} {:<10} {:<12} {}",
                        short_id, ts_short, actor, event_type, env, db, outcome_val, short_detail
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
        | Command::Dev { .. }
        | Command::SelfUpdate => unreachable!(),
        Command::Agents => {
            let body = sc.get_json("/api/agents").await?;
            if json_output {
                println!("{}", serde_json::to_string_pretty(&body)?);
            } else {
                print_agents_status(&body);
            }
            Ok(())
        }
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
                if let Err(err) =
                    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                {
                    eprintln!(
                        "Warning: failed to secure results directory {}: {err}",
                        dir.display()
                    );
                }
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

fn build_request_metadata(ticket: Option<&str>, repo: Option<&str>) -> Option<serde_json::Value> {
    let mut metadata = serde_json::Map::new();
    if let Some(ticket) = ticket.filter(|value| !value.is_empty()) {
        metadata.insert(
            "ticket".to_string(),
            serde_json::Value::String(ticket.to_string()),
        );
    }
    if let Some(repo) = repo.filter(|value| !value.is_empty()) {
        metadata.insert(
            "repo".to_string(),
            serde_json::Value::String(repo.to_string()),
        );
    }
    if metadata.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(metadata))
    }
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

            let _log_guard = dbward_server::init_logging(&server_cfg.logging);

            // Free tier config validation
            let license = dbward_server::license::License::load();
            let warnings = dbward_server::limits::validate_config(&server_cfg, &license);
            for w in &warnings {
                match w {
                    dbward_server::limits::ConfigWarning::HardBlock(_) => {
                        return Err(dbward_core::Error::Server(w.to_string()));
                    }
                    _ => eprintln!("Warning: {w}"),
                }
            }
            let server_cfg = if !license.is_pro() {
                dbward_server::limits::apply_free_limits(server_cfg)
            } else {
                server_cfg
            };

            let conn = rusqlite::Connection::open(data)
                .map_err(|e| dbward_core::Error::Server(e.to_string()))?;
            if let Some(backup_path) = dbward_server::db::backup_if_migration_needed(&conn, std::path::Path::new(data)) {
                eprintln!("Backup created: {}", backup_path.display());
            }
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
            dbward_server::db::policy_repo::sync_access_policies(
                &conn,
                &server_cfg.access_policies,
            )
            .map_err(|e| dbward_core::Error::Server(e.to_string()))?;
            let data_path = std::path::Path::new(data)
                .parent()
                .unwrap_or(std::path::Path::new("."));
            let token_signer = dbward_server::token::TokenSigner::load_or_generate(data_path)
                .map_err(dbward_core::Error::Server)?;
            let webhooks = {
                // Seed config-file webhooks to DB, then load all active from DB
                dbward_server::db::webhook_repo::seed_config_webhooks(&conn, &server_cfg.webhooks)
                    .map_err(|e| dbward_core::Error::Server(format!("webhook seed: {e}")))?;
                let configs = dbward_server::db::webhook_repo::load_active_webhook_configs(&conn)
                    .map_err(|e| dbward_core::Error::Server(format!("webhook load: {e}")))?;
                dbward_server::webhook::WebhookDispatcher::new(configs)
            };
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
                license: dbward_server::license::License::load(),
                sqlite: std::sync::Arc::new(tokio::sync::Mutex::new(conn)),
                token_signer: std::sync::Arc::new(token_signer),
                webhooks: std::sync::Arc::new(std::sync::RwLock::new(webhooks)),
                metrics: std::sync::Arc::new(dbward_server::Metrics::new()),
                oidc,
                auth_mode,
                result_channels: std::sync::Arc::new(dbward_server::ResultChannels::new()),
                retention: server_cfg.retention,
                request_notifier: std::sync::Arc::new(dbward_server::RequestNotifier::new()),
                result_store: match server_cfg.result_storage.as_ref().expect("[result_storage] is required") {
                    dbward_server::server_config::ResultStorageConfig::Local { root_dir } => {
                        std::sync::Arc::new(
                            dbward_server::result_storage::ResultStore::new_local(root_dir)
                                .expect("result storage init failed"),
                        )
                    }
                    dbward_server::server_config::ResultStorageConfig::S3 {
                        bucket,
                        region,
                        endpoint,
                    } => {
                        std::sync::Arc::new(
                            dbward_server::result_storage::ResultStore::new_s3(
                                bucket,
                                region,
                                endpoint.as_deref(),
                            )
                            .expect("result storage init failed"),
                        )
                    }
                },
                draining: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                break_glass_roles: server_cfg
                    .auth
                    .as_ref()
                    .map(|a| a.break_glass_roles.clone())
                    .unwrap_or_else(dbward_server::server_config::default_break_glass_roles),
                audit_config: server_cfg.audit.clone(),
                trusted_proxies: server_cfg.trusted_proxies.clone(),
                update_available: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
                update_check_enabled: server_cfg.update_check,
                enforcer: dbward_server::authz::get_enforcer_arc(),
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
                groups,
                data,
            } => {
                let conn = rusqlite::Connection::open(data)
                    .map_err(|e| dbward_core::Error::Server(e.to_string()))?;
                dbward_server::db::init_schema_only(&conn)
                    .map_err(|e| dbward_core::Error::Server(e.to_string()))?;
                let data_path = std::path::Path::new(data)
                    .parent()
                    .unwrap_or(std::path::Path::new("."));
                let token_signer = dbward_server::token::TokenSigner::load_or_generate(data_path)
                    .map_err(dbward_core::Error::Server)?;
                let state = dbward_server::AppState {
                    license: dbward_server::license::License::load(),
                    sqlite: std::sync::Arc::new(tokio::sync::Mutex::new(conn)),
                    token_signer: std::sync::Arc::new(token_signer),
                    webhooks: std::sync::Arc::new(std::sync::RwLock::new(dbward_server::webhook::WebhookDispatcher::empty())),
                    metrics: std::sync::Arc::new(dbward_server::Metrics::new()),
                    oidc: None,
                    auth_mode: "token".to_string(),
                    result_channels: std::sync::Arc::new(dbward_server::ResultChannels::new()),
                    retention: Default::default(),
                    request_notifier: std::sync::Arc::new(dbward_server::RequestNotifier::new()),
                    result_store: std::sync::Arc::new(
                        dbward_server::result_storage::ResultStore::new_local(
                            &std::env::temp_dir().join("dbward-token-op").to_string_lossy(),
                        ).expect("result storage init"),
                    ),
                    draining: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                    break_glass_roles: dbward_server::server_config::default_break_glass_roles(),
                    audit_config: Default::default(),
                    trusted_proxies: vec![],
            update_available: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
                update_check_enabled: false,
                enforcer: dbward_server::authz::get_enforcer_arc(),
                };
                let group_refs: Vec<&str> = groups.iter().map(|s| s.as_str()).collect();

                // Free tier checks
                {
                    let conn = state.sqlite.lock().await;
                    dbward_server::limits::check_can_create(
                        &conn,
                        dbward_server::limits::Resource::Token,
                        &state.license,
                    )
                    .map_err(|e| dbward_core::Error::Server(e.to_string()))?;
                }
                if !groups.is_empty() {
                    dbward_server::limits::require_pro("Group-based authorization", &state.license)
                        .map_err(|e| dbward_core::Error::Server(e.to_string()))?;
                }

                let (token_id, raw_token) = if *agent {
                    dbward_server::auth::create_token_with_type(&state, user, role, "agent")
                        .await
                        .map_err(dbward_core::Error::Server)?
                } else {
                    dbward_server::auth::create_token_with_groups(&state, user, role, &group_refs)
                        .await
                        .map_err(dbward_core::Error::Server)?
                };

                // Audit: token_created (CLI path, actor=system)
                {
                    let type_label = if *agent { "agent" } else { "user" };
                    let meta = serde_json::json!({
                        "subject_user": user, "role": role, "subject_type": type_label,
                    }).to_string();
                    let mut conn = state.sqlite.lock().await;
                    let _ = dbward_server::db::audit_event_repo::insert_audit_event(
                        &mut conn,
                        &dbward_server::db::audit_event_repo::AuditEvent {
                            event_type: "token_created",
                            event_category: "token",
                            outcome: "success",
                            actor_id: "system",
                            actor_type: "system",
                            resource_type: Some("token"),
                            resource_id: Some(&token_id),
                            peer_ip: None, client_ip: None, client_ip_source: None,
                            request_id: None, operation: None, environment: None,
                            database_name: None, detail_fingerprint: None, detail_raw: None,
                            reason: None,
                            metadata_json: &meta,
                        },
                    );
                }

                let type_label = if *agent { "agent" } else { "user" };
                println!("Token created:");
                println!("  ID:    {token_id}");
                println!("  Token: {raw_token}");
                println!("  User:  {user}");
                println!("  Role:  {role}");
                println!("  Type:  {type_label}");
                if !groups.is_empty() {
                    println!("  Groups: {}", groups.join(", "));
                }
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
                    license: dbward_server::license::License::load(),
                    sqlite: std::sync::Arc::new(tokio::sync::Mutex::new(conn)),
                    token_signer: std::sync::Arc::new(token_signer),
                    webhooks: std::sync::Arc::new(std::sync::RwLock::new(dbward_server::webhook::WebhookDispatcher::empty())),
                    metrics: std::sync::Arc::new(dbward_server::Metrics::new()),
                    oidc: None,
                    auth_mode: "token".to_string(),
                    result_channels: std::sync::Arc::new(dbward_server::ResultChannels::new()),
                    retention: Default::default(),
                    request_notifier: std::sync::Arc::new(dbward_server::RequestNotifier::new()),
                    result_store: std::sync::Arc::new(
                        dbward_server::result_storage::ResultStore::new_local(
                            &std::env::temp_dir().join("dbward-token-op").to_string_lossy(),
                        ).expect("result storage init"),
                    ),
                    draining: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                    break_glass_roles: dbward_server::server_config::default_break_glass_roles(),
                    audit_config: Default::default(),
                    trusted_proxies: vec![],
            update_available: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
                update_check_enabled: false,
                enforcer: dbward_server::authz::get_enforcer_arc(),
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
    dbward_agent::init_logging();

    let dev_dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".dbward")
        .join("dev");
    std::fs::create_dir_all(&dev_dir).map_err(|e| dbward_core::Error::Server(e.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(err) = std::fs::set_permissions(&dev_dir, std::fs::Permissions::from_mode(0o700))
        {
            eprintln!(
                "Warning: failed to secure dev directory {}: {err}",
                dev_dir.display()
            );
        }
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
        allow_same_approver_across_steps: false,
        allow_self_approve: false,
    }];
    dbward_server::db::policy_repo::sync_workflows(&conn, &workflows)
        .map_err(|e| dbward_core::Error::Server(e.to_string()))?;

    let token_signer = dbward_server::token::TokenSigner::load_or_generate(&dev_dir)
        .map_err(dbward_core::Error::Server)?;

    let state = dbward_server::AppState {
        license: dbward_server::license::License::load(),
        sqlite: std::sync::Arc::new(tokio::sync::Mutex::new(conn)),
        token_signer: std::sync::Arc::new(token_signer),
        webhooks: std::sync::Arc::new(std::sync::RwLock::new(dbward_server::webhook::WebhookDispatcher::empty())),
        metrics: std::sync::Arc::new(dbward_server::Metrics::new()),
        oidc: None,
        auth_mode: "token".into(),
        result_channels: std::sync::Arc::new(dbward_server::ResultChannels::new()),
        retention: Default::default(),
        request_notifier: std::sync::Arc::new(dbward_server::RequestNotifier::new()),
        result_store: {
            let results_dir = dev_dir.join("results");
            std::sync::Arc::new(
                dbward_server::result_storage::ResultStore::new_local(
                    results_dir.to_str().unwrap_or("./data/results"),
                )
                .expect("failed to init local result storage for dev mode"),
            )
        },
        draining: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        break_glass_roles: dbward_server::server_config::default_break_glass_roles(),
        audit_config: Default::default(),
        trusted_proxies: vec![],
        update_available: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
        update_check_enabled: false,
                enforcer: dbward_server::authz::get_enforcer_arc(),
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
    std::fs::write(&config_path, &client_config)
        .map_err(|e| dbward_core::Error::Server(format!("write {}: {e}", config_path.display())))?;

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
        "app".into(),
        dbward_core::AgentDatabaseConfig {
            url: database_url.to_string(),
            migrations_dir: None,
        },
    );
    let agent_config = dbward_core::AgentConfig {
        agent_id: "dev-agent".into(),
        poll_interval_ms: 500,
        lease_duration_secs: 300,
        drain_timeout_secs: 60,
        max_concurrent_tasks: 2,
        statement_timeout_secs: None,
        server: dbward_core::AgentServerConfig {
            url: server_url,
            agent_token: agent_token.clone(),
        },
        capabilities: dbward_core::AgentCapabilities {
            databases: vec!["app".into()],
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

    #[test]
    fn format_result_cell_value_sanitizes_and_truncates() {
        let input = serde_json::Value::String(format!("{}\n{}", "あ".repeat(80), "tail"));
        let formatted = format_result_cell_value(&input);
        assert!(!formatted.contains('\n'));
        assert!(formatted.ends_with("..."));
        assert!(display_width(&formatted) <= RESULT_CELL_MAX_WIDTH);
    }

    #[test]
    fn render_result_table_uses_columns_from_all_rows() {
        let rows = vec![
            serde_json::json!({"id": 1, "name": "alice"}),
            serde_json::json!({"id": 2, "status": "ok"}),
        ];
        let rendered = render_result_table(&rows);
        assert!(rendered[0].contains("id"));
        assert!(rendered[0].contains("name"));
        assert!(rendered[0].contains("status"));
        assert!(rendered.iter().any(|line| line.contains("alice")));
        assert!(rendered.iter().any(|line| line.contains("ok")));
    }

    #[test]
    fn global_options_parse_before_subcommand() {
        let cli = Cli::try_parse_from([
            "dbward",
            "--environment",
            "production",
            "--database",
            "primary",
            "execute",
            "SELECT 1",
        ])
        .unwrap();

        assert_eq!(cli.environment.as_deref(), Some("production"));
        assert_eq!(cli.database.as_deref(), Some("primary"));
        assert!(matches!(cli.command, Command::Execute { .. }));
    }

    #[test]
    fn global_options_parse_after_subcommand() {
        let cli = Cli::try_parse_from([
            "dbward",
            "execute",
            "SELECT 1",
            "--environment",
            "production",
            "--database",
            "primary",
        ])
        .unwrap();

        assert_eq!(cli.environment.as_deref(), Some("production"));
        assert_eq!(cli.database.as_deref(), Some("primary"));
        assert!(matches!(cli.command, Command::Execute { .. }));
    }

    #[test]
    fn global_format_option_parses_after_subcommand() {
        let cli = Cli::try_parse_from(["dbward", "request", "list", "--format", "json"]).unwrap();

        assert_eq!(cli.format, "json");
        assert!(matches!(cli.command, Command::Request { .. }));
    }

    #[test]
    fn invalid_format_is_rejected() {
        let err = match Cli::try_parse_from(["dbward", "--format", "yaml", "request", "list"]) {
            Ok(_) => panic!("expected invalid format to be rejected"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains("possible values"));
    }

    #[test]
    fn request_approve_comment_option_parses() {
        let cli = Cli::try_parse_from([
            "dbward",
            "request",
            "approve",
            "abc12345",
            "--comment",
            "LGTM",
        ])
        .unwrap();

        match cli.command {
            Command::Request {
                action: RequestAction::Approve { comment, .. },
            } => assert_eq!(comment.as_deref(), Some("LGTM")),
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn request_list_user_option_parses() {
        let cli = Cli::try_parse_from([
            "dbward",
            "--database",
            "primary",
            "--environment",
            "production",
            "request",
            "list",
            "--user",
            "alice",
        ])
        .unwrap();

        assert_eq!(cli.database.as_deref(), Some("primary"));
        assert_eq!(cli.environment.as_deref(), Some("production"));
        match cli.command {
            Command::Request {
                action: RequestAction::List { user, .. },
            } => assert_eq!(user.as_deref(), Some("alice")),
            _ => panic!("unexpected command"),
        }
    }
}
