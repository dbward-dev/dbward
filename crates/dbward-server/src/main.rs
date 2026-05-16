use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "dbward-server", about = "dbward HTTP server")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Listen address
    #[arg(long, default_value = "127.0.0.1:3000")]
    listen: String,

    /// SQLite database path
    #[arg(long, default_value = "dbward.db")]
    data: String,

    /// Server config file path
    #[arg(long, default_value = "dbward-server.toml")]
    config: String,

    /// Dev bootstrap mode: output tokens as JSON to stdout then start
    #[arg(long, hide = true)]
    dev_bootstrap: bool,

    /// License key (Pro/Enterprise)
    #[arg(long, env = "DBWARD_LICENSE_KEY")]
    license_key: Option<String>,

    /// Path to license key file
    #[arg(long, env = "DBWARD_LICENSE_FILE")]
    license_file: Option<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Manage API tokens
    Token {
        #[command(subcommand)]
        action: TokenCommand,
    },
}

#[derive(Subcommand)]
enum TokenCommand {
    /// Create a new API token
    Create {
        #[arg(long)]
        user: String,
        #[arg(long)]
        role: String,
        #[arg(long)]
        agent: bool,
        #[arg(long, value_delimiter = ',')]
        groups: Vec<String>,
    },
    /// Revoke an existing API token
    Revoke {
        #[arg(long)]
        id: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Some(Command::Token { action }) => match action {
            TokenCommand::Create {
                user,
                role,
                agent,
                groups,
            } => dbward_server::bootstrap::create_token_standalone(
                &cli.data, &user, &role, agent, &groups,
            ),
            TokenCommand::Revoke { id } => {
                dbward_server::bootstrap::revoke_token_standalone(&cli.data, &id)
            }
        },
        None => {
            dbward_server::run_from_args(
                &cli.listen,
                &cli.data,
                &cli.config,
                cli.dev_bootstrap,
                cli.license_key.as_deref(),
                cli.license_file.as_deref(),
            )
            .await
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn serve_mode_backward_compat() {
        let cli = Cli::try_parse_from([
            "dbward-server",
            "--listen",
            "0.0.0.0:3000",
            "--data",
            "/data/dbward.db",
            "--config",
            "/config/server.toml",
            "--dev-bootstrap",
        ])
        .unwrap();
        assert!(cli.command.is_none());
        assert_eq!(cli.listen, "0.0.0.0:3000");
        assert_eq!(cli.data, "/data/dbward.db");
        assert!(cli.dev_bootstrap);
    }

    #[test]
    fn token_create_parses() {
        let cli = Cli::try_parse_from([
            "dbward-server",
            "--data",
            "/data/dbward.db",
            "token",
            "create",
            "--user",
            "alice",
            "--role",
            "admin",
        ])
        .unwrap();
        assert!(matches!(cli.command, Some(Command::Token { .. })));
        assert_eq!(cli.data, "/data/dbward.db");
    }

    #[test]
    fn token_create_with_groups_parses() {
        let cli = Cli::try_parse_from([
            "dbward-server",
            "--data",
            "/data/dbward.db",
            "token",
            "create",
            "--user",
            "alice",
            "--role",
            "admin",
            "--agent",
            "--groups",
            "backend,dba",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Token {
                action: TokenCommand::Create { groups, agent, .. },
            }) => {
                assert!(agent);
                assert_eq!(groups, vec!["backend", "dba"]);
            }
            _ => panic!("expected token create"),
        }
    }

    #[test]
    fn token_revoke_parses() {
        let cli = Cli::try_parse_from([
            "dbward-server",
            "--data",
            "/data/dbward.db",
            "token",
            "revoke",
            "--id",
            "abc-123",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Token {
                action: TokenCommand::Revoke { id },
            }) => {
                assert_eq!(id, "abc-123");
            }
            _ => panic!("expected token revoke"),
        }
        assert_eq!(cli.data, "/data/dbward.db");
    }
}
