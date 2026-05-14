use clap::Subcommand;

use crate::error::CliError;

#[derive(Subcommand)]
pub enum TokenAction {
    /// Create a new API token
    Create {
        #[arg(long)]
        user: String,
        #[arg(long, value_parser = parse_role)]
        role: String,
        #[arg(long)]
        agent: bool,
        #[arg(long, value_delimiter = ',')]
        groups: Vec<String>,
        /// Path to SQLite database file
        #[arg(long, default_value = "dbward.db")]
        data: String,
    },
    /// Revoke an existing API token
    Revoke {
        #[arg(long)]
        id: String,
        /// Path to SQLite database file
        #[arg(long, default_value = "dbward.db")]
        data: String,
    },
}

pub fn run_token(action: &TokenAction) -> Result<(), CliError> {
    match action {
        TokenAction::Create {
            user,
            role,
            agent,
            groups,
            data,
        } => {
            let output = dbward_infra::token_admin::create_token(data, user, role, *agent, groups)
                .map_err(|e| CliError::Other(e.to_string()))?;

            let subject_type = if *agent { "agent" } else { "user" };
            println!("Token created:");
            println!("  ID:    {}", output.id);
            println!("  Token: {}", output.token);
            println!("  User:  {user}");
            println!("  Role:  {role}");
            println!("  Type:  {subject_type}");
            println!();
            println!("Save this token \u{2014} it cannot be retrieved later.");
            Ok(())
        }
        TokenAction::Revoke { id, data } => {
            dbward_infra::token_admin::revoke_token(data, id)
                .map_err(|e| CliError::Other(e.to_string()))?;
            println!("Token revoked: {id}");
            Ok(())
        }
    }
}

fn parse_role(s: &str) -> Result<String, String> {
    if s.is_empty() {
        Err("role cannot be empty".into())
    } else {
        Ok(s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(subcommand)]
        action: TokenAction,
    }

    #[test]
    fn token_create_parses() {
        let cli = TestCli::try_parse_from([
            "test",
            "create",
            "--user",
            "alice",
            "--role",
            "admin",
            "--data",
            "/tmp/test.db",
        ])
        .unwrap();
        assert!(matches!(cli.action, TokenAction::Create { .. }));
    }

    #[test]
    fn token_create_with_groups_parses() {
        let cli = TestCli::try_parse_from([
            "test",
            "create",
            "--user",
            "alice",
            "--role",
            "admin",
            "--agent",
            "--groups",
            "backend,dba",
            "--data",
            "/tmp/test.db",
        ])
        .unwrap();
        match cli.action {
            TokenAction::Create { agent, groups, .. } => {
                assert!(agent);
                assert_eq!(groups, vec!["backend", "dba"]);
            }
            _ => panic!("expected create"),
        }
    }

    #[test]
    fn token_revoke_parses() {
        let cli =
            TestCli::try_parse_from(["test", "revoke", "--id", "abc-123", "--data", "/tmp/t.db"])
                .unwrap();
        match cli.action {
            TokenAction::Revoke { id, .. } => assert_eq!(id, "abc-123"),
            _ => panic!("expected revoke"),
        }
    }

    #[test]
    fn empty_role_rejected() {
        let result = TestCli::try_parse_from([
            "test",
            "create",
            "--user",
            "alice",
            "--role",
            "",
            "--data",
            "/tmp/t.db",
        ]);
        assert!(result.is_err());
    }
}
