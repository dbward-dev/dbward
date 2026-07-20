mod confirm;
mod error;
pub mod render;
pub mod types;
pub mod views;

pub use confirm::confirm_or_reject;
pub use error::CliError;
pub use render::render;
pub use types::{
    CliOutcome, CliResponse, Column, EnvelopeError, ErrorInfo, OutputMode, ProgressSink,
    RenderPlan, StderrLine, StdoutRender,
};

/// Detect `--format` value from raw args before clap parsing.
///
/// Used when `Cli::try_parse()` fails (e.g. usage error) to determine whether
/// to output the error as JSON or human text.
///
/// Only reads `--format` / `--format=<value>`. Must stay in sync with the
/// `Cli` struct definition.
pub fn detect_format_from_args() -> OutputMode {
    let args: Vec<String> = std::env::args().collect();
    for (i, arg) in args.iter().enumerate() {
        if arg == "--format"
            && let Some(val) = args.get(i + 1)
        {
            match val.as_str() {
                "json" => return OutputMode::Json,
                "quiet" => return OutputMode::Quiet,
                _ => {}
            }
        }
        if let Some(val) = arg.strip_prefix("--format=") {
            match val {
                "json" => return OutputMode::Json,
                "quiet" => return OutputMode::Quiet,
                _ => {}
            }
        }
    }
    OutputMode::Human
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // detect_format_from_args reads std::env::args() so it's hard to unit-test
    // directly. We test the logic through the public types instead.

    #[test]
    fn output_mode_default_is_human() {
        assert_eq!(OutputMode::default(), OutputMode::Human);
    }

    #[test]
    fn cli_response_ok_creates_valid_response() {
        #[derive(serde::Serialize)]
        struct TestData {
            count: u32,
        }
        let resp = CliResponse::ok(TestData { count: 3 }, RenderPlan::status("done"));
        assert!(resp.data.is_some());
        assert!(resp.exit_code.is_none());
        assert!(resp.error_info.is_none());
        assert!(resp.warnings.is_empty());
    }

    #[test]
    fn cli_response_empty_has_no_data() {
        let resp: CliResponse<()> = CliResponse {
            data: None,
            warnings: vec![],
            render: RenderPlan::status("revoked"),
            exit_code: None,
            error_info: None,
        };
        assert!(resp.data.is_none());
    }

    #[test]
    fn cli_response_with_warning_appends() {
        #[derive(serde::Serialize)]
        struct D;
        let resp = CliResponse::ok(D, RenderPlan::none())
            .with_warning("deprecated")
            .with_warning("also this");
        assert_eq!(resp.warnings.len(), 2);
    }
}
