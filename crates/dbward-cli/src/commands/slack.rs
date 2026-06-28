use clap::Subcommand;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};

use crate::error::CliError;

#[derive(Clone, Subcommand)]
pub enum SlackAction {
    /// Generate Slack App manifest and creation URL
    Init {
        /// Public URL of the dbward server (e.g. https://dbward.example.com)
        #[arg(long)]
        server_url: String,
        /// App display name
        #[arg(long, default_value = "dbward")]
        app_name: String,
        /// Open browser automatically
        #[arg(long)]
        open: bool,
        /// Output manifest YAML only (no instructions)
        #[arg(long)]
        manifest_only: bool,
    },
}

pub async fn run(action: SlackAction, json_output: bool) -> Result<(), CliError> {
    match action {
        SlackAction::Init {
            server_url,
            app_name,
            open,
            manifest_only,
        } => run_init(&server_url, &app_name, open, manifest_only, json_output),
    }
}

fn run_init(
    server_url: &str,
    app_name: &str,
    open_browser: bool,
    manifest_only: bool,
    json_output: bool,
) -> Result<(), CliError> {
    let server_url = validate_and_normalize_url(server_url)?;
    validate_app_name(app_name)?;
    let manifest = generate_manifest(&server_url, app_name);

    if manifest_only {
        print!("{manifest}");
        return Ok(());
    }

    let encoded = utf8_percent_encode(&manifest, NON_ALPHANUMERIC).to_string();
    let create_url = format!("https://api.slack.com/apps?new_app=1&manifest_yaml={encoded}");

    if json_output {
        let output = serde_json::json!({
            "manifest_yaml": manifest,
            "create_url": create_url,
            "next_steps": [
                "Create app via URL",
                "Copy Signing Secret",
                "Install to Workspace",
                "Copy Bot Token",
                "Configure server.toml"
            ]
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        eprintln!("dbward slack init — Slack App Setup\n");
        eprintln!("Manifest generated for: {server_url}\n");
        eprintln!("Next steps:\n");
        eprintln!("  1. Open this URL to create your Slack App:");
        eprintln!("     {create_url}\n");
        eprintln!("  2. Select your workspace → Click \"Create\"\n");
        eprintln!("  3. Go to \"Basic Information\" and copy:");
        eprintln!("     • Signing Secret → server.toml [slack] signing_secret\n");
        eprintln!("  4. Go to \"Install App\" → \"Install to Workspace\"\n");
        eprintln!(
            "  5. Copy the Bot User OAuth Token (xoxb-...) → server.toml [slack] bot_token\n"
        );
        eprintln!("  6. Add to your server.toml:\n");
        eprintln!("     [slack]");
        eprintln!(
            "     bot_token = \"\"           # paste xoxb-... token here (or use ${{SLACK_BOT_TOKEN}})"
        );
        eprintln!(
            "     signing_secret = \"\"      # paste signing secret here (or use ${{SLACK_SIGNING_SECRET}})"
        );
        eprintln!(
            "     channel = \"C0123ABC456\"  # Channel ID (right-click channel → View channel details → copy ID)\n"
        );
        eprintln!("  7. Invite the bot to your channel:");
        eprintln!("     /invite @{app_name}\n");
        eprintln!("Done! Run `dbward doctor --server server.toml` to verify.");
    }

    if open_browser && let Err(e) = open::that(&create_url) {
        eprintln!("warning: failed to open browser: {e}");
        eprintln!("         Open the URL above manually.");
    }

    Ok(())
}

fn validate_and_normalize_url(url: &str) -> Result<String, CliError> {
    let url = url.trim_end_matches('/');
    let parsed = reqwest::Url::parse(url)
        .map_err(|e| CliError::Config(format!("invalid server-url: {e}")))?;
    if parsed.scheme() != "https" {
        return Err(CliError::Config(
            "server-url must use HTTPS (Slack requires HTTPS for all endpoints)".into(),
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(CliError::Config(
            "server-url must not contain query parameters or fragments".into(),
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(CliError::Config(
            "server-url must not contain credentials".into(),
        ));
    }
    Ok(url.to_string())
}

fn validate_app_name(name: &str) -> Result<(), CliError> {
    if name.contains('"') || name.contains('\n') || name.contains('\\') {
        return Err(CliError::Config(
            "app-name must not contain quotes, newlines, or backslashes".into(),
        ));
    }
    if name.is_empty() || name.len() > 35 {
        return Err(CliError::Config(
            "app-name must be 1-35 characters (Slack limit)".into(),
        ));
    }
    Ok(())
}

fn generate_manifest(server_url: &str, app_name: &str) -> String {
    MANIFEST_TEMPLATE
        .replace("{server_url}", server_url)
        .replace("{app_name}", app_name)
}

const MANIFEST_TEMPLATE: &str = r##"display_information:
  name: "{app_name}"
  description: "DB approval workflow — approve/reject from Slack"
  background_color: "#1E293B"
features:
  bot_user:
    display_name: "{app_name}"
    always_online: true
  slash_commands:
    - command: /dbward
      description: "Execute SQL via approval workflow"
      usage_hint: "execute | help"
      url: "{server_url}/api/slack/commands"
oauth_config:
  scopes:
    bot:
      - chat:write
      - channels:join
      - channels:read
      - groups:read
      - commands
      - users:read
      - users:read.email
settings:
  interactivity:
    is_enabled: true
    request_url: "{server_url}/api/slack/interactions"
  org_deploy_enabled: false
  socket_mode_enabled: false
  token_rotation_enabled: false
"##;

#[cfg(test)]
mod tests {
    use super::*;
    use percent_encoding::percent_decode_str;

    #[test]
    fn manifest_generation_injects_url_and_name() {
        let manifest = generate_manifest("https://dbward.example.com", "mybot");
        assert!(manifest.contains("https://dbward.example.com/api/slack/commands"));
        assert!(manifest.contains("https://dbward.example.com/api/slack/interactions"));
        assert!(manifest.contains("name: \"mybot\""));
        assert!(manifest.contains("display_name: \"mybot\""));
    }

    #[test]
    fn url_encoding_roundtrip() {
        let manifest = generate_manifest("https://dbward.example.com", "dbward");
        let encoded = utf8_percent_encode(&manifest, NON_ALPHANUMERIC).to_string();
        let decoded = percent_decode_str(&encoded).decode_utf8().unwrap();
        assert_eq!(manifest, decoded);
    }

    #[test]
    fn server_url_validation_rejects_http() {
        let result = validate_and_normalize_url("http://example.com");
        assert!(result.is_err());
    }

    #[test]
    fn server_url_validation_accepts_https() {
        let result = validate_and_normalize_url("https://example.com");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://example.com");
    }

    #[test]
    fn server_url_trailing_slash_removed() {
        let result = validate_and_normalize_url("https://example.com/");
        assert_eq!(result.unwrap(), "https://example.com");
    }

    #[test]
    fn server_url_rejects_invalid_url() {
        let result = validate_and_normalize_url("not-a-url");
        assert!(result.is_err());
    }

    #[test]
    fn server_url_rejects_query_params() {
        let result = validate_and_normalize_url("https://example.com?x=1");
        assert!(result.is_err());
    }

    #[test]
    fn server_url_rejects_fragment() {
        let result = validate_and_normalize_url("https://example.com#foo");
        assert!(result.is_err());
    }

    #[test]
    fn app_name_rejects_quotes() {
        assert!(validate_app_name("my\"bot").is_err());
    }

    #[test]
    fn app_name_rejects_newlines() {
        assert!(validate_app_name("my\nbot").is_err());
    }

    #[test]
    fn app_name_rejects_empty() {
        assert!(validate_app_name("").is_err());
    }

    #[test]
    fn app_name_accepts_valid() {
        assert!(validate_app_name("dbward").is_ok());
    }
}
