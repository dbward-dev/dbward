//! Integration tests for `--format` output mode behavior.
//!
//! These tests exercise the CLI binary directly (no server connection required).
//! They verify that JSON envelope and exit codes behave correctly for:
//! - Usage errors (missing subcommand)
//! - Help output
//! - Quiet mode
//! - Invalid format values

use assert_cmd::Command;
use predicates::prelude::*;

fn dbward() -> Command {
    Command::cargo_bin("dbward").expect("binary exists")
}

// ---------------------------------------------------------------------------
// --format json
// ---------------------------------------------------------------------------

#[test]
fn format_json_usage_error_produces_json_envelope() {
    // No subcommand → usage error
    let assert = dbward().arg("--format").arg("json").assert();

    assert
        .code(2)
        .stdout(predicate::str::contains("\"ok\":false"))
        .stdout(predicate::str::contains("\"error\""));
}

#[test]
fn format_json_usage_error_envelope_is_valid_json() {
    let output = dbward()
        .arg("--format")
        .arg("json")
        .output()
        .expect("command runs");

    assert_eq!(output.status.code(), Some(2));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout is valid JSON");
    assert_eq!(parsed["ok"], false);
    assert!(parsed["error"]["code"].is_string());
    assert!(parsed["error"]["message"].is_string());
}

#[test]
fn format_json_help_outputs_text_not_json() {
    // --help is handled by clap before format routing — always text, exit 0
    let assert = dbward().arg("--format").arg("json").arg("--help").assert();

    assert
        .code(0)
        .stdout(predicate::str::contains("Usage:").or(predicate::str::contains("usage:")));
}

// ---------------------------------------------------------------------------
// --format quiet
// ---------------------------------------------------------------------------

#[test]
fn format_quiet_usage_error_json_on_stdout_nothing_on_stderr() {
    let output = dbward()
        .arg("--format")
        .arg("quiet")
        .output()
        .expect("command runs");

    assert_eq!(output.status.code(), Some(2));

    // stdout: JSON envelope
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout is valid JSON");
    assert_eq!(parsed["ok"], false);

    // stderr: empty in quiet mode
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.trim().is_empty(),
        "quiet mode should suppress stderr, got: {stderr:?}"
    );
}

// ---------------------------------------------------------------------------
// Invalid --format value
// ---------------------------------------------------------------------------

#[test]
fn invalid_format_value_produces_human_error() {
    // clap rejects invalid enum values before our code runs → human error + exit 2
    let assert = dbward().arg("--format").arg("yaml").assert();

    assert.code(2).stderr(predicate::str::contains("invalid"));
}
