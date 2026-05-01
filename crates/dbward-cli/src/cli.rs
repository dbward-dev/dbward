use std::path::PathBuf;

use clap::{Parser, Subcommand};

use dbward_core::{Engine, Role};
use dbward_migrate::Migrator;

use crate::config_loader;
use crate::mcp;

fn parse_role(s: &str) -> Result<Role, String> {
    match s {
        "admin" => Ok(Role::Admin),
        "developer" => Ok(Role::Developer),
        "readonly" => Ok(Role::Readonly),
        _ => Err(format!("invalid role: {s} (expected: admin, developer, readonly)")),
    }
}

#[derive(Parser)]
#[command(name = "dbward", version, about = "Workflow and approval engine for database operations")]
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
    /// Search audit log (direct mode: not available, server mode only)
    Audit,
    /// Start MCP stdio server
    Mcp,
}

#[derive(Subcommand)]
enum MigrateAction {
    /// Apply pending migrations
    Up {
        /// Max number of migrations to apply
        #[arg(long)]
        count: Option<usize>,
    },
    /// Rollback migrations
    Down {
        /// Number of migrations to rollback
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

pub async fn run(cli: Cli) -> Result<(), dbward_core::Error> {
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
    }
}
