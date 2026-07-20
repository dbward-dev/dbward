mod agent;
mod audit;
mod auth;
mod dev;
mod doctor;
mod execute;
mod group;
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
use serde::Serialize;

use crate::config::{self, ClientConfig};
use crate::error::CliError;
use crate::oidc_login;
use crate::output::{CliResponse, RenderPlan, StdoutRender};
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

    /// Output format: human (default), json, or quiet
    #[arg(long, default_value = "human", value_enum, global = true)]
    pub format: crate::output::OutputMode,

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
        /// Bypass sql_review blocks (DROP TABLE, TRUNCATE, etc.) in emergency mode
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
    /// Manage users
    User {
        #[command(subcommand)]
        action: user::UserAction,
    },
    /// View groups
    Group {
        #[command(subcommand)]
        action: group::GroupAction,
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
// Whoami output type
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct WhoamiOutput {
    pub subject_id: String,
    pub subject_type: String,
    pub roles: Vec<String>,
    pub groups: Vec<String>,
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
// Whoami implementation
// ---------------------------------------------------------------------------

async fn run_whoami(cli: &Cli) -> Result<CliResponse<WhoamiOutput>, CliError> {
    let cfg_result = dbward_config::load_merged(cli.config.as_deref(), cli.merge_global);
    let cfg = match cfg_result {
        Ok(m) => Some(m.config),
        Err(dbward_config::ConfigError::NotFound(_)) => None,
        Err(e) => return Err(CliError::Config(e.to_string())),
    };

    if let Some(cfg) = &cfg {
        // TLS transport security check before sending credentials
        let has_oidc = cfg.server.oidc.is_some();
        let allow_insecure = cfg.server.allow_insecure.unwrap_or(false) || cli.allow_insecure;
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
                        return Ok(build_whoami_response(&resp));
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
        // Return a minimal output for local-only case
        let output = WhoamiOutput {
            subject_id: "local".into(),
            subject_type: "oidc".into(),
            roles: vec![],
            groups: vec![],
        };
        let render = RenderPlan {
            stdout: StdoutRender::None,
            stderr: vec![],
        };
        return Ok(CliResponse::ok(output, render));
    }

    Err(CliError::Auth("Not logged in. Run: dbward login".into()))
}

fn build_whoami_response(resp: &serde_json::Value) -> CliResponse<WhoamiOutput> {
    let subject = resp["subject_id"].as_str().unwrap_or("unknown").to_string();
    let stype = resp["subject_type"].as_str().unwrap_or("unknown").to_string();

    let roles: Vec<String> = resp["roles"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v["name"].as_str().or_else(|| v.as_str()))
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();

    let groups: Vec<String> = resp["groups"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).map(String::from).collect())
        .unwrap_or_default();

    let mut pairs = vec![
        ("Subject".into(), format!("{subject} ({stype})")),
    ];
    if !roles.is_empty() {
        pairs.push(("Roles".into(), roles.join(", ")));
    }
    if !groups.is_empty() {
        pairs.push(("Groups".into(), groups.join(", ")));
    }

    let output = WhoamiOutput {
        subject_id: subject,
        subject_type: stype,
        roles,
        groups,
    };

    let render = RenderPlan::key_value(pairs);
    CliResponse::ok(output, render)
}

// ---------------------------------------------------------------------------
// Main dispatch
// ---------------------------------------------------------------------------

pub async fn run(mut cli: Cli) -> Result<Option<crate::output::CliOutcome>, CliError> {
    // Merge DBWARD_YES env var (accepts 1/true/yes)
    if let (false, Ok(val)) = (cli.yes, std::env::var("DBWARD_YES")) {
        cli.yes = matches!(val.to_lowercase().as_str(), "1" | "true" | "yes");
    }

    // -----------------------------------------------------------------------
    // New path: commands that return CliResponse<T> → CliOutcome
    // (Add new commands here as they are migrated)
    // -----------------------------------------------------------------------

    // --- Token commands ---
    if let Command::Token { ref action } = cli.command {
        let cfg = config::load_resolved(cli.config.as_deref(), cli.merge_global)?.config;
        let (server_url, api_token) = authenticate(&cfg).await?;
        let sc = ServerClient::new(&server_url, &api_token);

        let outcome: crate::output::CliOutcome = match action {
            token::TokenAction::List { subject, status, subject_type } => {
                token::run_token_list(&sc, subject.as_deref(), status.as_deref(), subject_type.as_deref()).await?.into()
            }
            token::TokenAction::Create { subject, subject_type, scope_roles, no_scope_ceiling, name, expires, role } => {
                token::run_token_create(
                    &sc,
                    subject.as_deref(),
                    subject_type,
                    scope_roles,
                    *no_scope_ceiling,
                    name.as_deref(),
                    expires.as_deref(),
                    role.as_deref(),
                ).await?.into()
            }
            token::TokenAction::Revoke { id } => {
                token::run_token_revoke(&sc, id).await?.into()
            }
            token::TokenAction::Inspect { id } => {
                token::run_token_inspect(&sc, id).await?.into()
            }
        };
        return Ok(Some(outcome));
    }

    // --- Whoami ---
    if let Command::Whoami = cli.command {
        let outcome: crate::output::CliOutcome = run_whoami(&cli).await?.into();
        return Ok(Some(outcome));
    }

    // --- User commands ---
    if let Command::User { ref action } = cli.command {
        let cfg = config::load_resolved(cli.config.as_deref(), cli.merge_global)?.config;
        let (server_url, api_token) = authenticate(&cfg).await?;
        let sc = ServerClient::new(&server_url, &api_token);

        let outcome: crate::output::CliOutcome = match action {
            user::UserAction::Add { id, role, group } => {
                user::run_user_add(&sc, id, role, group).await?.into()
            }
            user::UserAction::List => {
                user::run_user_list(&sc).await?.into()
            }
            user::UserAction::Show { id } => {
                user::run_user_show(&sc, id).await?.into()
            }
            user::UserAction::Update {
                id, role, add_role, rm_role, add_group, rm_group, slack_user_id,
            } => {
                user::run_user_update(
                    &sc, id, role, add_role, rm_role, add_group, rm_group,
                    slack_user_id.as_deref(),
                ).await?.into()
            }
            user::UserAction::Suspend { id } => {
                user::run_user_suspend(&sc, id).await?.into()
            }
            user::UserAction::Activate { id } => {
                user::run_user_activate(&sc, id).await?.into()
            }
            user::UserAction::Rm { id } => {
                user::run_user_rm(&sc, id).await?.into()
            }
            user::UserAction::ReissueInitialToken { id } => {
                user::run_user_reissue_token(&sc, id).await?.into()
            }
        };
        return Ok(Some(outcome));
    }

    // --- Group commands ---
    if let Command::Group { ref action } = cli.command {
        let cfg = config::load_resolved(cli.config.as_deref(), cli.merge_global)?.config;
        let (server_url, api_token) = authenticate(&cfg).await?;
        let sc = ServerClient::new(&server_url, &api_token);

        let outcome: crate::output::CliOutcome = match action {
            group::GroupAction::List => {
                group::run_group_list(&sc).await?.into()
            }
            group::GroupAction::Show { name } => {
                group::run_group_show(&sc, name).await?.into()
            }
        };
        return Ok(Some(outcome));
    }

    // --- Request commands ---
    if let Command::Request { ref action } = cli.command {
        let cfg = config::load_resolved(cli.config.as_deref(), cli.merge_global)?.config;
        let (server_url, api_token) = authenticate(&cfg).await?;
        let sc = ServerClient::new(&server_url, &api_token);
        let default_fmt = resolve_result_format(None, &cfg);
        let outcome = request::run_request_cmd(
            &sc,
            action,
            cli.database.as_deref(),
            cli.environment.as_deref(),
            cfg.results.dir.as_deref(),
            default_fmt,
            cli.yes,
            cli.format,
        )
        .await?;
        return Ok(Some(outcome));
    }

    // --- Databases ---
    if let Command::Databases = cli.command {
        let cfg = config::load_resolved(cli.config.as_deref(), cli.merge_global)?.config;
        let (server_url, api_token) = authenticate(&cfg).await?;
        let sc = ServerClient::new(&server_url, &api_token);
        let outcome: crate::output::CliOutcome = misc::run_databases(&sc).await?.into();
        return Ok(Some(outcome));
    }

    // --- Agents ---
    if let Command::Agents = cli.command {
        let cfg = config::load_resolved(cli.config.as_deref(), cli.merge_global)?.config;
        let (server_url, api_token) = authenticate(&cfg).await?;
        let sc = ServerClient::new(&server_url, &api_token);
        let outcome: crate::output::CliOutcome = misc::run_agents(&sc).await?.into();
        return Ok(Some(outcome));
    }

    // --- Init ---
    if let Command::Init {
        ref non_interactive,
        ref force,
        ref preset,
        ref output_dir,
        ref dry_run,
    } = cli.command
    {
        let outcome: crate::output::CliOutcome = auth::run_init(
            &cli,
            *non_interactive,
            *force,
            preset.as_deref(),
            output_dir,
            *dry_run,
            cli.format,
        )?.into();
        return Ok(Some(outcome));
    }

    // --- Logout ---
    if let Command::Logout = cli.command {
        oidc_login::logout().await.map_err(CliError::Auth)?;
        let render = RenderPlan::status("Logged out.");
        let outcome: crate::output::CliOutcome = CliResponse::<()>::empty(render).into();
        return Ok(Some(outcome));
    }

    // --- Server ---
    if let Command::Server { ref action } = cli.command {
        let outcome: crate::output::CliOutcome = server::run_server_command(action).await?.into();
        return Ok(Some(outcome));
    }

    // --- Self-update ---
    if let Command::SelfUpdate = cli.command {
        let outcome: crate::output::CliOutcome = self_update::run_self_update().await?.into();
        return Ok(Some(outcome));
    }

    // --- Doctor ---
    if let Command::Doctor {
        ref agent,
        ref server,
        ref timeout,
    } = cli.command
    {
        let suppress = matches!(cli.format, crate::output::OutputMode::Json | crate::output::OutputMode::Quiet);
        let outcome: crate::output::CliOutcome = doctor::run(
            cli.config.as_deref(),
            agent.clone(),
            server.clone(),
            suppress,
            *timeout,
        )
        .await?.into();
        return Ok(Some(outcome));
    }

    // --- Slack ---
    if let Command::Slack { ref action } = cli.command {
        let outcome: crate::output::CliOutcome = slack::run(action.clone()).await?.into();
        return Ok(Some(outcome));
    }

    // --- Policy ---
    if let Command::Policy { ref action } = cli.command {
        let cfg = config::load_resolved(cli.config.as_deref(), cli.merge_global)?.config;
        let (server_url, api_token) = authenticate(&cfg).await?;
        let sc = ServerClient::new(&server_url, &api_token);

        let outcome: crate::output::CliOutcome = match action {
            PolicyAction::Resolve {
                database,
                environment,
                operation,
            } => {
                policy::run_resolve(&sc, database, environment, operation.as_deref()).await?.into()
            }
        };
        return Ok(Some(outcome));
    }

    // --- Execute ---
    if let Command::Execute {
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
    } = cli.command
    {
        let cfg = config::load_resolved(cli.config.as_deref(), cli.merge_global)?.config;
        check_transport(&cfg, cli.allow_insecure)?;
        let (server_url, api_token) = authenticate(&cfg).await?;
        let sc = ServerClient::new(&server_url, &api_token);
        let db_name = cfg.resolve_database_name(cli.database.as_deref())?;
        let env_str = cli
            .environment
            .as_deref()
            .or(cfg.default_environment.as_deref())
            .unwrap_or("development");
        let outcome: crate::output::CliOutcome = execute::run_execute(
            &sc,
            &db_name,
            env_str,
            cli.format,
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
        .await?.into();
        return Ok(Some(outcome));
    }

    // --- Preflight ---
    if let Command::Preflight {
        ref sql,
        no_explain,
        explain_timeout_ms,
    } = cli.command
    {
        let cfg = config::load_resolved(cli.config.as_deref(), cli.merge_global)?.config;
        check_transport(&cfg, cli.allow_insecure)?;
        let (server_url, api_token) = authenticate(&cfg).await?;
        let sc = ServerClient::new(&server_url, &api_token);
        let db_name = cfg.resolve_database_name(cli.database.as_deref())?;
        let env_str = cli
            .environment
            .as_deref()
            .or(cfg.default_environment.as_deref())
            .unwrap_or("development");
        let outcome: crate::output::CliOutcome = preflight::run_preflight(
            &sc,
            &db_name,
            env_str,
            sql,
            !no_explain,
            explain_timeout_ms,
        )
        .await?.into();
        return Ok(Some(outcome));
    }

    // --- Audit ---
    if let Command::Audit {
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
    } = cli.command
    {
        let cfg = config::load_resolved(cli.config.as_deref(), cli.merge_global)?.config;
        check_transport(&cfg, cli.allow_insecure)?;
        let (server_url, api_token) = authenticate(&cfg).await?;
        let sc = ServerClient::new(&server_url, &api_token);
        let cli_outcome: crate::output::CliOutcome = audit::run_audit(
            &sc,
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
        .await?.into();
        return Ok(Some(cli_outcome));
    }

    // --- Migrate ---
    if let Command::Migrate { ref action } = cli.command {
        let cfg = config::load_resolved(cli.config.as_deref(), cli.merge_global)?.config;
        let db_name = cfg.resolve_database_name(cli.database.as_deref())?;

        // migrate create is local-only
        if let migrate::MigrateAction::Create { name } = action {
            let outcome: crate::output::CliOutcome =
                migrate::run_migrate_create(&cfg, &db_name, name)?.into();
            return Ok(Some(outcome));
        }

        check_transport(&cfg, cli.allow_insecure)?;
        let (server_url, api_token) = authenticate(&cfg).await?;
        let sc = ServerClient::new(&server_url, &api_token);
        let env_str = cli
            .environment
            .as_deref()
            .or(cfg.default_environment.as_deref())
            .unwrap_or("development");
        let outcome: crate::output::CliOutcome = migrate::run_migrate(
            &sc,
            &cfg,
            &db_name,
            env_str,
            cli.format,
            action,
            cli.yes,
        )
        .await?.into();
        return Ok(Some(outcome));
    }

    // -----------------------------------------------------------------------
    // Legacy path: commands still using println! directly.
    // Returns None (output already written).
    // -----------------------------------------------------------------------
    run_legacy(cli).await?;
    Ok(None)
}

/// TLS transport security check helper.
fn check_transport(cfg: &ClientConfig, allow_insecure_flag: bool) -> Result<(), CliError> {
    let has_oidc = cfg.server.oidc.is_some();
    let allow_insecure = cfg.server.allow_insecure.unwrap_or(false) || allow_insecure_flag;
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
    Ok(())
}

async fn run_legacy(cli: Cli) -> Result<(), CliError> {
    // Commands that don't need config/auth
    match &cli.command {
        Command::Agent {
            config: agent_config_path,
        } => return agent::run_agent(agent_config_path).await,
        Command::Dev { database_url, port } => {
            return dev::run_dev(database_url, *port).await;
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

    let (server_url, api_token) = authenticate(&cfg).await?;
    let sc = ServerClient::new(&server_url, &api_token);

    match cli.command {
        Command::Mcp => crate::mcp::run_stdio(cfg, cli.database.as_deref(), sc).await,
        // All other commands handled by new path
        _ => unreachable!("all commands should be handled by new path"),
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
        assert_eq!(cli.format, crate::output::OutputMode::Json);
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
    fn build_whoami_response_with_groups_and_roles() {
        let resp = serde_json::json!({
            "subject_id": "alice@example.com",
            "subject_type": "user",
            "roles": [{"name": "dba", "permissions": ["execute"]}, {"name": "dev"}],
            "groups": ["backend-team", "sre"]
        });
        let cli_resp = build_whoami_response(&resp);
        let data = cli_resp.data.unwrap();
        assert_eq!(data.subject_id, "alice@example.com");
        assert_eq!(data.subject_type, "user");
        assert_eq!(data.roles, vec!["dba", "dev"]);
        assert_eq!(data.groups, vec!["backend-team", "sre"]);
    }

    #[test]
    fn build_whoami_response_empty_groups_and_roles() {
        let resp = serde_json::json!({
            "subject_id": "bot",
            "subject_type": "api_token",
            "roles": [],
            "groups": []
        });
        let cli_resp = build_whoami_response(&resp);
        let data = cli_resp.data.unwrap();
        assert_eq!(data.subject_id, "bot");
        assert_eq!(data.subject_type, "api_token");
        assert!(data.roles.is_empty());
        assert!(data.groups.is_empty());
    }

    #[test]
    fn build_whoami_response_legacy_string_roles() {
        let resp = serde_json::json!({
            "subject_id": "old-server",
            "subject_type": "user",
            "roles": ["admin", "requester"]
        });
        let cli_resp = build_whoami_response(&resp);
        let data = cli_resp.data.unwrap();
        assert_eq!(data.roles, vec!["admin", "requester"]);
    }
}
