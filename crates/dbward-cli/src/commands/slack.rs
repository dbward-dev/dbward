use clap::Subcommand;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde::Serialize;

use crate::error::CliError;
use crate::output::{CliResponse, RenderPlan, StderrLine, StdoutRender};

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

// ---------------------------------------------------------------------------
// Output type
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct SlackInitOutput {
    pub manifest_yaml: String,
    pub create_url: String,
    pub next_steps: Vec<String>,
}

// ---------------------------------------------------------------------------
// Command implementation
// ---------------------------------------------------------------------------

pub async fn run(action: SlackAction) -> Result<CliResponse<SlackInitOutput>, CliError> {
    match action {
        SlackAction::Init {
            server_url,
            app_name,
            open,
            manifest_only,
        } => run_init(&server_url, &app_name, open, manifest_only),
    }
}

fn run_init(
    server_url: &str,
    app_name: &str,
    open_browser: bool,
    manifest_only: bool,
) -> Result<CliResponse<SlackInitOutput>, CliError> {
    let server_url = validate_and_normalize_url(server_url)?;
    validate_app_name(app_name)?;
    let manifest = generate_manifest(&server_url, app_name);

    let encoded = utf8_percent_encode(&manifest, NON_ALPHANUMERIC).to_string();
    let create_url = format!("https://api.slack.com/apps?new_app=1&manifest_yaml={encoded}");

    let next_steps = vec![
        "Create app via URL".into(),
        "Copy Signing Secret".into(),
        "Install to Workspace".into(),
        "Copy Bot Token".into(),
        "Configure server.toml".into(),
    ];

    let output = SlackInitOutput {
        manifest_yaml: manifest.clone(),
        create_url: create_url.clone(),
        next_steps: next_steps.clone(),
    };

    let render = if manifest_only {
        RenderPlan {
            stdout: StdoutRender::Raw { value: manifest },
            stderr: vec![],
        }
    } else {
        let stderr = vec![
            StderrLine::Status("dbward slack init — Slack App Setup".into()),
            StderrLine::Status(String::new()),
            StderrLine::Status(format!("Manifest generated for: {server_url}")),
            StderrLine::Status(String::new()),
            StderrLine::Status("Next steps:".into()),
            StderrLine::Status(String::new()),
            StderrLine::Status("  1. Open this URL to create your Slack App:".into()),
            StderrLine::Status(format!("     {create_url}")),
            StderrLine::Status(String::new()),
            StderrLine::Status("  2. Select your workspace → Click \"Create\"".into()),
            StderrLine::Status(String::new()),
            StderrLine::Status("  3. Go to \"Basic Information\" and copy:".into()),
            StderrLine::Status("     • Signing Secret → server.toml [slack] signing_secret".into()),
            StderrLine::Status(String::new()),
            StderrLine::Status("  4. Go to \"Install App\" → \"Install to Workspace\"".into()),
            StderrLine::Status(String::new()),
            StderrLine::Status("  5. Copy the Bot User OAuth Token (xoxb-...) → server.toml [slack] bot_token".into()),
            StderrLine::Status(String::new()),
            StderrLine::Status("  6. Add to your server.toml:".into()),
            StderrLine::Status(String::new()),
            StderrLine::Status("     [slack]".into()),
            StderrLine::Status("     bot_token = \"\"           # paste xoxb-... token here (or use ${SLACK_BOT_TOKEN})".into()),
            StderrLine::Status("     signing_secret = \"\"      # paste signing secret here (or use ${SLACK_SIGNING_SECRET})".into()),
            StderrLine::Status("     channel = \"C0123ABC456\"  # Channel ID (right-click channel → View channel details → copy ID)".into()),
            StderrLine::Status(String::new()),
            StderrLine::Status("  7. Invite the bot to your channel:".to_string()),
            StderrLine::Status(format!("     /invite @{app_name}")),
            StderrLine::Status(String::new()),
            StderrLine::Status("Done! Run `dbward doctor --server server.toml` to verify.".into()),
        ];

        RenderPlan {
            stdout: StdoutRender::None,
            stderr,
        }
    };

    if open_browser && let Err(e) = open::that(&create_url) {
        // Non-fatal warning added to the response.
        let resp = CliResponse::ok(output, render)
            .with_warning(format!("failed to open browser: {e}. Open the URL above manually."));
        return Ok(resp);
    }

    Ok(CliResponse::ok(output, render))
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
  description: "DB approval workflow — approve/reject and onboard from Slack"
  background_color: "#1E293B"
features:
  bot_user:
    display_name: "{app_name}"
    always_online: true
  slash_commands:
    - command: /dbward
      description: "DB workflow commands (join, execute, help)"
      usage_hint: "join | execute | help"
      url: "{server_url}/api/slack/commands"
oauth_config:
  scopes:
    bot:
      - chat:write
      - im:write
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
