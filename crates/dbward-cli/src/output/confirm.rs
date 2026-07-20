use std::io::IsTerminal;

use super::error::CliError;
use super::types::OutputMode;

/// Check whether a destructive operation should proceed.
///
/// Rules (from design doc §9.2):
/// - `--yes` flag: always proceed (any mode, any TTY state)
/// - `--format human` + TTY + no `--yes`: prompt the user
/// - `--format json/quiet` + no `--yes`: error (confirmation_required)
/// - non-TTY stdin + no `--yes`: error (confirmation_required)
pub fn confirm_or_reject(mode: OutputMode, yes_flag: bool) -> Result<(), CliError> {
    if yes_flag {
        return Ok(());
    }

    if mode != OutputMode::Human || !std::io::stdin().is_terminal() {
        return Err(CliError::Api {
            code: "confirmation_required".into(),
            message: "--yes is required for destructive operations in non-interactive mode".into(),
        });
    }

    // Human + TTY: interactive prompt
    prompt_user_confirmation()
}

fn prompt_user_confirmation() -> Result<(), CliError> {
    eprint!("Continue? [y/N] ");

    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .map_err(|e| CliError::Internal(format!("failed to read input: {e}")))?;

    match input.trim().to_lowercase().as_str() {
        "y" | "yes" => Ok(()),
        _ => Err(CliError::Blocked {
            reason: "aborted by user".into(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yes_flag_always_ok() {
        assert!(confirm_or_reject(OutputMode::Human, true).is_ok());
        assert!(confirm_or_reject(OutputMode::Json, true).is_ok());
        assert!(confirm_or_reject(OutputMode::Quiet, true).is_ok());
    }

    #[test]
    fn json_mode_without_yes_is_confirmation_required() {
        let result = confirm_or_reject(OutputMode::Json, false);
        assert!(result.is_err());
        match result.unwrap_err() {
            CliError::Api { code, message } => {
                assert_eq!(code, "confirmation_required");
                assert!(message.contains("--yes"));
            }
            other => panic!("expected Api error, got: {other:?}"),
        }
    }

    #[test]
    fn quiet_mode_without_yes_is_confirmation_required() {
        let result = confirm_or_reject(OutputMode::Quiet, false);
        assert!(result.is_err());
        match result.unwrap_err() {
            CliError::Api { code, .. } => assert_eq!(code, "confirmation_required"),
            other => panic!("expected Api error, got: {other:?}"),
        }
    }

    #[test]
    fn human_mode_non_tty_without_yes_is_confirmation_required() {
        // In CI/test environments, stdin is typically not a TTY
        if std::io::stdin().is_terminal() {
            return; // Skip in interactive terminals
        }
        let result = confirm_or_reject(OutputMode::Human, false);
        assert!(result.is_err());
        match result.unwrap_err() {
            CliError::Api { code, .. } => assert_eq!(code, "confirmation_required"),
            other => panic!("expected Api error, got: {other:?}"),
        }
    }
}
