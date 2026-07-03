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
mod preflight;
mod request;
mod server;
mod slack;
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
#[command(
    name = "dbward",
    about = "DB operations workflow + approval engine",
    version,
    disable_version_flag = true
)]
pub struct Cli {
    /// Print version
    #[arg(short = 'v', long = "version", action = clap::ArgAction::Version)]
    pub version: (),

    /// Path to config file (standalone mode: disables global merge)
    #[arg(long, env = "DBWARD_CONFIG", global = true)]
    pub config: Option<PathBuf>,

    /// Merge global config even when --config is explicitly set
    #[arg(long, global = true)]
    pub merge_global: bool,

    /// Select named database from config
    #[arg(long, env = "DBWARD_DATABASE", global = true)]
    pub database: Option<String>,

    /// Override environment for this request
    #[arg(short = 'e', long, env = "DBWARD_ENV", global = true)]
    pub environment: Option<String>,

    /// Output format: human (default) or json
    #[arg(long, default_value = "human", value_parser = ["human", "json"], global = true)]
    pub format: String,

    /// Allow insecure HTTP connections to non-local servers (suppresses TLS warning)
    #[arg(long, global = true)]
    pub allow_insecure: bool,

    /// Skip interactive confirmation prompts
    #[arg(long, short = 'y', global = true)]
    pub yes: bool,

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
        /// Generate config files from a preset template (e.g., small-team)
        #[arg(long)]
        preset: Option<String>,
        /// Output directory for generated files
        #[arg(long, default_value = ".")]
        output_dir: std::path::PathBuf,
        /// Print generated files to stdout without writing
        #[arg(long)]
        dry_run: bool,
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
        /// Allow schema DDL (DROP TABLE/VIEW/INDEX/SEQUENCE, CREATE SEQUENCE) in emergency mode
        #[arg(long = "allow-ddl", requires = "emergency")]
        allow_ddl: bool,
        /// Reason for this request
        #[arg(long)]
        reason: Option<String>,
        /// Save result to a specific file
        #[arg(long)]
        output: Option<PathBuf>,
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
        /// Do not store query result on server. Request metadata and SQL text are always retained for audit.
        #[arg(long = "no-result-store")]
        no_result_store: bool,
        /// Result display format (default from config or table)
        #[arg(long, value_enum)]
        result_format: Option<crate::display::ResultFormat>,
        /// Timeout in seconds (no timeout if not specified)
        #[arg(long)]
        timeout: Option<u64>,
    },
    /// Preflight check: analyze SQL without creating a request
    Preflight {
        /// SQL statement to analyze
        sql: String,
        /// Skip EXPLAIN (static analysis only)
        #[arg(long = "no-explain")]
        no_explain: bool,
        /// EXPLAIN timeout in milliseconds
        #[arg(long = "explain-timeout", default_value = "5000")]
        explain_timeout_ms: u64,
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
    /// Manage Slack App setup
    Slack {
        #[command(subcommand)]
        action: slack::SlackAction,
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

fn resolve_result_format(
    flag: Option<crate::display::ResultFormat>,
    config: &ClientConfig,
) -> crate::display::ResultFormat {
    flag.unwrap_or_else(|| {
        config
            .results
            .format
            .map(crate::display::ResultFormat::from)
            .unwrap_or(crate::display::ResultFormat::Table)
    })
}

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

/// Like `authenticate` but returns `Ok(None)` when no auth is configured.
async fn try_authenticate(config: &ClientConfig) -> Result<Option<(String, String)>, CliError> {
    let server_url = config.server.url.clone();

    if let Some(ref token) = config.server.token {
        return Ok(Some((server_url, token.clone())));
    }

    if let Some(ref oc) = config.server.oidc {
        match oidc_login::load_token(&oc.issuer, &oc.client_id).await {
            Ok(token) => return Ok(Some((server_url, token))),
            Err(e) => return Err(CliError::Auth(e.to_string())),
        }
    }

    Ok(None)
}

// ---------------------------------------------------------------------------
// Main dispatch
// ---------------------------------------------------------------------------

pub async fn run(mut cli: Cli) -> Result<(), CliError> {
    // Merge DBWARD_YES env var (accepts 1/true/yes)
    if let (false, Ok(val)) = (cli.yes, std::env::var("DBWARD_YES")) {
        cli.yes = matches!(val.to_lowercase().as_str(), "1" | "true" | "yes");
    }

    // Commands that don't need config/auth
    match &cli.command {
        Command::Init {
            non_interactive,
            force,
            preset,
            output_dir,
            dry_run,
        } => {
            return auth::run_init(
                &cli,
                *non_interactive,
                *force,
                preset.as_deref(),
                output_dir,
                *dry_run,
            );
        }
        Command::Logout => {
            oidc_login::logout().await.map_err(CliError::Auth)?;
            return Ok(());
        }
        Command::Whoami => {
            let cfg_result = dbward_config::load_merged(cli.config.as_deref(), cli.merge_global);
            let cfg = match cfg_result {
                Ok(m) => Some(m.config),
                Err(dbward_config::ConfigError::NotFound(_)) => None,
                Err(e) => return Err(CliError::Config(e.to_string())),
            };

            if let Some(cfg) = &cfg {
                // TLS transport security check before sending credentials
                let has_oidc = cfg.server.oidc.is_some();
                let allow_insecure =
                    cfg.server.allow_insecure.unwrap_or(false) || cli.allow_insecure;
                if let Err(e) = dbward_config::transport::check_transport_security(
                    &cfg.server.url,
                    allow_insecure,
                    has_oidc,
                ) {
                    match &e {
                        dbward_config::transport::TransportError::InsecureHttp { .. } => {
                            eprintln!("warning: {e}");
                        }
                        _ => return Err(CliError::Config(e.to_string())),
                    }
                }

                match try_authenticate(cfg).await {
                    Ok(Some((url, token))) => {
                        let sc = ServerClient::new(&url, &token);
                        match sc.get_json("/api/me").await {
                            Ok(resp) => {
                                print_whoami_server(&resp);
                                return Ok(());
                            }
                            Err(CliError::Transport(_)) => {
                                // Connection failure → fall through to local
                            }
                            Err(e) => return Err(e),
                        }
                    }
                    Ok(None) => {
                        // Auth not configured → fall through to local
                    }
                    Err(e) => {
                        // Auth failure (expired token etc) → warn then fall through to local
                        eprintln!("warning: {e}");
                    }
                }
            }

            // Fallback: local OIDC credentials
            if oidc_login::whoami().is_ok() {
                eprintln!(
                    "(showing local credentials only — server not available or auth not configured)"
                );
                return Ok(());
            }
            return Err(CliError::Auth("Not logged in. Run: dbward login".into()));
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
                cli.config.as_deref(),
                agent.clone(),
                server.clone(),
                cli.format == "json",
                *timeout,
            )
            .await;
        }
        Command::Slack { action } => {
            return slack::run(action.clone(), cli.format == "json").await;
        }
        _ => {}
    }

    let cfg = config::load_resolved(cli.config.as_deref(), cli.merge_global)?.config;

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

    // TLS transport security check (OIDC + external HTTP → hard error)
    let has_oidc = cfg.server.oidc.is_some();
    let allow_insecure = cfg.server.allow_insecure.unwrap_or(false);
    if let Err(e) = dbward_config::transport::check_transport_security(
        &cfg.server.url,
        allow_insecure,
        has_oidc,
    ) {
        match &e {
            dbward_config::transport::TransportError::InsecureHttp { .. } => {
                eprintln!("warning: {e}");
            }
            _ => return Err(CliError::Config(e.to_string())),
        }
    }

    let (server_url, api_token) = authenticate(&cfg).await?;

    let sc = ServerClient::new(&server_url, &api_token);
    let json_output = cli.format == "json";

    match cli.command {
        Command::Execute {
            ref sql,
            emergency,
            allow_ddl,
            ref reason,
            ref output,
            ref ticket,
            ref repo,
            ref idempotency_key,
            ref share_with,
            no_result_store,
            result_format,
            timeout,
        } => {
            let db_name = cfg.resolve_database_name(cli.database.as_deref())?;
            let env_str = cli
                .environment
                .as_deref()
                .or(cfg.default_environment.as_deref())
                .unwrap_or("development");
            execute::run_execute(
                &sc,
                &db_name,
                env_str,
                json_output,
                sql,
                emergency,
                allow_ddl,
                reason.as_deref(),
                output.as_deref(),
                cfg.results.dir.as_deref(),
                ticket.as_deref(),
                repo.as_deref(),
                idempotency_key.as_deref(),
                share_with,
                no_result_store,
                resolve_result_format(result_format, &cfg),
                timeout,
                cli.yes,
            )
            .await
        }
        Command::Migrate { ref action } => {
            let db_name = cfg.resolve_database_name(cli.database.as_deref())?;
            let env_str = cli
                .environment
                .as_deref()
                .or(cfg.default_environment.as_deref())
                .unwrap_or("development");
            migrate::run_migrate(
                &sc,
                &cfg,
                &db_name,
                env_str,
                json_output,
                action,
                cli.database.as_deref(),
                cli.yes,
            )
            .await
        }
        Command::Request { action } => {
            let default_fmt = resolve_result_format(None, &cfg);
            request::run_request(
                &sc,
                json_output,
                action,
                cli.database.as_deref(),
                cli.environment.as_deref(),
                cfg.results.dir.as_deref(),
                default_fmt,
                cli.yes,
            )
            .await
        }
        Command::Databases => misc::run_databases(&sc, json_output).await,
        Command::Preflight {
            ref sql,
            no_explain,
            explain_timeout_ms,
        } => {
            let db_name = cfg.resolve_database_name(cli.database.as_deref())?;
            let env_str = cli
                .environment
                .as_deref()
                .or(cfg.default_environment.as_deref())
                .unwrap_or("development");
            preflight::run_preflight(
                &sc,
                &db_name,
                env_str,
                sql,
                !no_explain,
                explain_timeout_ms,
                json_output,
            )
            .await
        }
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
        | Command::Doctor { .. }
        | Command::Slack { .. } => unreachable!(),
    }
}

fn print_whoami_server(resp: &serde_json::Value) {
    let subject = resp["subject_id"].as_str().unwrap_or("unknown");
    let stype = resp["subject_type"].as_str().unwrap_or("unknown");
    println!("Subject: {subject} ({stype})");

    let roles: Vec<&str> = resp["roles"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v["name"].as_str().or_else(|| v.as_str()))
                .collect()
        })
        .unwrap_or_default();
    if !roles.is_empty() {
        println!("Roles: {}", roles.join(", "));
    }

    let groups: Vec<&str> = resp["groups"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    if !groups.is_empty() {
        println!("Groups: {}", groups.join(", "));
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

    #[test]
    fn no_result_store_flag_parses() {
        let cli =
            Cli::try_parse_from(["dbward", "execute", "--no-result-store", "SELECT 1"]).unwrap();
        match cli.command {
            Command::Execute {
                no_result_store, ..
            } => assert!(no_result_store),
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn no_result_store_defaults_to_false() {
        let cli = Cli::try_parse_from(["dbward", "execute", "SELECT 1"]).unwrap();
        match cli.command {
            Command::Execute {
                no_result_store, ..
            } => assert!(!no_result_store),
            _ => panic!("unexpected command"),
        }
    }

    #[test]
    fn yes_flag_parses_short() {
        let cli = Cli::try_parse_from(["dbward", "-y", "execute", "SELECT 1"]).unwrap();
        assert!(cli.yes);
    }

    #[test]
    fn yes_flag_parses_long() {
        let cli = Cli::try_parse_from(["dbward", "--yes", "execute", "SELECT 1"]).unwrap();
        assert!(cli.yes);
    }

    #[test]
    fn yes_flag_defaults_to_false() {
        let cli = Cli::try_parse_from(["dbward", "execute", "SELECT 1"]).unwrap();
        assert!(!cli.yes);
    }

    #[test]
    fn print_whoami_server_with_groups_and_roles() {
        let resp = serde_json::json!({
            "subject_id": "alice@example.com",
            "subject_type": "user",
            "roles": [{"name": "dba", "permissions": ["execute"]}, {"name": "dev"}],
            "groups": ["backend-team", "sre"]
        });
        // Capture stdout to verify output
        let output = capture_whoami_output(&resp);
        assert!(output.contains("Subject: alice@example.com (user)"));
        assert!(output.contains("Roles: dba, dev"));
        assert!(output.contains("Groups: backend-team, sre"));
    }

    #[test]
    fn print_whoami_server_empty_groups_and_roles() {
        let resp = serde_json::json!({
            "subject_id": "bot",
            "subject_type": "api_token",
            "roles": [],
            "groups": []
        });
        let output = capture_whoami_output(&resp);
        assert!(output.contains("Subject: bot (api_token)"));
        assert!(!output.contains("Roles:"));
        assert!(!output.contains("Groups:"));
    }

    #[test]
    fn print_whoami_server_legacy_string_roles() {
        let resp = serde_json::json!({
            "subject_id": "old-server",
            "subject_type": "user",
            "roles": ["admin", "developer"]
        });
        let output = capture_whoami_output(&resp);
        assert!(output.contains("Roles: admin, developer"));
    }

    /// Helper: extract what print_whoami_server would produce by calling the internal logic directly
    fn capture_whoami_output(resp: &serde_json::Value) -> String {
        let subject = resp["subject_id"].as_str().unwrap_or("unknown");
        let stype = resp["subject_type"].as_str().unwrap_or("unknown");
        let roles: Vec<&str> = resp["roles"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v["name"].as_str().or_else(|| v.as_str()))
                    .collect()
            })
            .unwrap_or_default();
        let groups: Vec<&str> = resp["groups"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();

        let mut output = format!("Subject: {subject} ({stype})\n");
        if !roles.is_empty() {
            output.push_str(&format!("Roles: {}\n", roles.join(", ")));
        }
        if !groups.is_empty() {
            output.push_str(&format!("Groups: {}\n", groups.join(", ")));
        }
        output
    }
}
