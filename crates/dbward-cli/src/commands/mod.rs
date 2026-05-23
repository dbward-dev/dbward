mod agent;
mod audit;
mod auth;
mod dev;
mod doctor;
mod execute;
pub(crate) mod helpers;
mod migrate;
mod misc;
mod policy;
mod request;
mod result;
mod server;
mod token;
mod user;
pub(crate) mod workflow;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::config::{self, ClientConfig};
use crate::error::CliError;
use crate::oidc_login;
use crate::self_update;
use crate::server_client::ServerClient;

#[derive(Parser)]
#[command(name = "dbward", about = "DB operations workflow + approval engine")]
pub struct Cli {
    /// Path to config file
    #[arg(
        long,
        env = "DBWARD_CONFIG",
        default_value = "dbward.toml",
        global = true
    )]
    pub config: PathBuf,

    /// Select named database from config
    #[arg(long, env = "DBWARD_DATABASE", global = true)]
    pub database: Option<String>,

    /// Override environment for this request
    #[arg(long, env = "DBWARD_ENV", global = true)]
    pub environment: Option<String>,

    /// Output format: human (default) or json
    #[arg(long, default_value = "human", value_parser = ["human", "json"], global = true)]
    pub format: String,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
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
        action: migrate::MigrateAction,
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
        /// Result display format
        #[arg(long, value_enum, default_value = "table")]
        result_format: crate::display::ResultFormat,
        /// Timeout in seconds (no timeout if not specified)
        #[arg(long)]
        timeout: Option<u64>,
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
    /// List registered databases
    Databases,
    /// Start the dbward HTTP server
    Server {
        #[command(subcommand)]
        action: server::ServerAction,
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
        action: request::RequestAction,
    },
    /// Manage results
    Result {
        #[command(subcommand)]
        action: result::ResultAction,
    },
    /// Update user profile
    User {
        #[command(subcommand)]
        action: user::UserAction,
    },
    /// Manage API tokens
    Token {
        #[command(subcommand)]
        action: token::TokenAction,
    },
    /// Update dbward to the latest version
    SelfUpdate,
    /// Show agent status (admin only)
    Agents,
    /// Diagnose configuration and connectivity issues
    Doctor {
        /// Validate agent config file instead of CLI config
        #[arg(long)]
        agent: Option<PathBuf>,
        /// Validate server config file instead of CLI config
        #[arg(long)]
        server: Option<PathBuf>,
        /// Network timeout per check in seconds
        #[arg(long, default_value = "5")]
        timeout: u64,
    },
    /// Show effective policy for a database/environment
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
}

#[derive(clap::Subcommand)]
pub enum PolicyAction {
    /// Resolve effective policy for a database/environment
    Resolve {
        /// Database name
        database: String,
        /// Environment name
        environment: String,
        /// Specific operation to resolve
        #[arg(long)]
        operation: Option<String>,
    },
}

// ---------------------------------------------------------------------------
// Auth helper
// ---------------------------------------------------------------------------

async fn authenticate(config: &ClientConfig) -> Result<(String, String), CliError> {
    let server_url = config.server.url.clone();

    if let Some(ref token) = config.server.token {
        return Ok((server_url, token.clone()));
    }

    if let Some(ref oc) = config.server.oidc {
        match oidc_login::load_token(&oc.issuer, &oc.client_id).await {
            Ok(token) => return Ok((server_url, token)),
            Err(e) => {
                return Err(CliError::Auth(e.to_string()));
            }
        }
    }

    Err(CliError::Auth(
        "no authentication configured: set [server.oidc] or server.token in dbward.toml".into(),
    ))
}

// ---------------------------------------------------------------------------
// Main dispatch
// ---------------------------------------------------------------------------

pub async fn run(cli: Cli) -> Result<(), CliError> {
    // Commands that don't need config/auth
    match &cli.command {
        Command::Init {
            non_interactive,
            force,
        } => return auth::run_init(&cli, *non_interactive, *force),
        Command::Logout => {
            oidc_login::logout().await.map_err(CliError::Auth)?;
            return Ok(());
        }
        Command::Whoami => {
            // Try OIDC credentials first
            if oidc_login::whoami().is_ok() {
                return Ok(());
            }
            // Fall back to API token via server
            let cfg = match config::load(&cli.config) {
                Ok(c) => c,
                Err(e) => {
                    return Err(CliError::Auth(format!(
                        "Not logged in. Config error: {e}\nRun: dbward login or dbward init"
                    )));
                }
            };
            if let Some(ref token) = cfg.server.token {
                let sc = ServerClient::new(&cfg.server.url, token);
                match sc.get_json("/api/me").await {
                    Ok(resp) => {
                        let subject = resp["subject_id"].as_str().unwrap_or("unknown");
                        let stype = resp["subject_type"].as_str().unwrap_or("unknown");
                        let roles: Vec<&str> = resp["roles"]
                            .as_array()
                            .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
                            .unwrap_or_default();
                        println!("Subject: {subject} ({stype})");
                        if !roles.is_empty() {
                            println!("Roles: {}", roles.join(", "));
                        }
                    }
                    Err(e) => return Err(CliError::Server(format!("Failed to query server: {e}"))),
                }
            } else {
                return Err(CliError::Auth("Not logged in. Run: dbward login".into()));
            }
            return Ok(());
        }
        Command::Server { action } => return server::run_server_command(action).await,
        Command::Agent {
            config: agent_config_path,
        } => return agent::run_agent(agent_config_path).await,
        Command::Dev { database_url, port } => {
            return dev::run_dev(database_url, *port).await;
        }
        Command::SelfUpdate => {
            return self_update::run_self_update().await;
        }
        Command::Doctor {
            agent,
            server,
            timeout,
        } => {
            return doctor::run(
                &cli.config,
                agent.clone(),
                server.clone(),
                cli.format == "json",
                *timeout,
            )
            .await;
        }
        _ => {}
    }

    let cfg = config::load(&cli.config)?;

    // Login needs OIDC config but not full auth
    if let Command::Login { device } = &cli.command {
        let oc = cfg
            .server
            .oidc
            .as_ref()
            .ok_or_else(|| CliError::Config("[server.oidc] not configured".into()))?;
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
        .map_err(CliError::Auth)?;
        return Ok(());
    }

    // Migrate create is local-only
    if let Command::Migrate {
        action: migrate::MigrateAction::Create { ref name },
    } = cli.command
    {
        let db_name = cfg.resolve_database_name(cli.database.as_deref())?;
        let migrations_dir = cfg.migrations_dir_for(&db_name);
        let migrator = dbward_migrate::LocalMigrator::new(migrations_dir);
        let path = migrator.create(name)?;
        println!("Created: {}", path.display());
        return Ok(());
    }

    let (server_url, api_token) = authenticate(&cfg).await?;
    let sc = ServerClient::new(&server_url, &api_token);
    let db_name = cfg.resolve_database_name(cli.database.as_deref())?;
    let env_str = cli
        .environment
        .as_deref()
        .or(cfg.default_environment.as_deref())
        .unwrap_or("development");
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
            result_format,
            timeout,
        } => {
            execute::run_execute(
                &sc,
                &db_name,
                env_str,
                json_output,
                sql,
                emergency,
                reason.as_deref(),
                output.as_deref(),
                no_save,
                ticket.as_deref(),
                repo.as_deref(),
                idempotency_key.as_deref(),
                share_with,
                no_store,
                result_format,
                timeout,
            )
            .await
        }
        Command::Migrate { ref action } => {
            migrate::run_migrate(
                &sc,
                &cfg,
                &db_name,
                env_str,
                json_output,
                action,
                cli.database.as_deref(),
            )
            .await
        }
        Command::Request { action } => {
            request::run_request(
                &sc,
                json_output,
                action,
                cli.database.as_deref(),
                cli.environment.as_deref(),
            )
            .await
        }
        Command::Result { action } => result::run_result(&sc, json_output, action).await,
        Command::Databases => misc::run_databases(&sc, json_output).await,
        Command::Mcp => crate::mcp::run_stdio(cfg, cli.database.as_deref(), sc).await,
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
            audit::run_audit(
                &sc,
                json_output,
                *limit,
                user.as_deref(),
                operation.as_deref(),
                status.as_deref(),
                event_type.as_deref(),
                category.as_deref(),
                outcome.as_deref(),
                since.as_deref(),
                until.as_deref(),
                cli.environment.as_deref(),
                verify,
                output,
            )
            .await
        }
        Command::Agents => misc::run_agents(&sc, json_output).await,
        Command::User { action } => user::run_user(&sc, action).await,
        Command::Token { action } => token::run_token_command(&action, &sc, json_output).await,
        Command::Policy { action } => match action {
            PolicyAction::Resolve {
                database,
                environment,
                operation,
            } => {
                policy::run_resolve(
                    &sc,
                    json_output,
                    &database,
                    &environment,
                    operation.as_deref(),
                )
                .await
            }
        },
        // Handled above
        Command::Init { .. }
        | Command::Login { .. }
        | Command::Logout
        | Command::Whoami
        | Command::Server { .. }
        | Command::Agent { .. }
        | Command::Dev { .. }
        | Command::SelfUpdate
        | Command::Doctor { .. } => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

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
        let result = Cli::try_parse_from(["dbward", "--format", "yaml", "request", "list"]);
        assert!(result.is_err());
        let err = result.err().unwrap().to_string();
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
                action: request::RequestAction::Approve { comment, .. },
            } => {
                assert_eq!(comment.as_deref(), Some("LGTM"));
            }
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
                action: request::RequestAction::List { user, .. },
            } => {
                assert_eq!(user.as_deref(), Some("alice"));
            }
            _ => panic!("unexpected command"),
        }
    }
}
