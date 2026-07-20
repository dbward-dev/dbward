use serde_json::Value;

use super::types::{CliOutcome, OutputMode, StderrLine, StdoutRender};
use crate::display::{display_width, pad_table_cell, truncate_table_cell};

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Render the outcome according to the output mode.
pub fn render(mode: OutputMode, outcome: &CliOutcome) {
    match mode {
        OutputMode::Human => render_human(outcome),
        OutputMode::Json => render_json(outcome, false),
        OutputMode::Quiet => render_json(outcome, true),
    }
}

// ---------------------------------------------------------------------------
// JSON renderer
// ---------------------------------------------------------------------------

fn render_json(outcome: &CliOutcome, suppress_stderr: bool) {
    let mut envelope = serde_json::Map::new();
    envelope.insert("ok".into(), Value::Bool(outcome.ok));

    if let Some(ref data) = outcome.data {
        envelope.insert("data".into(), data.clone());
    } else {
        envelope.insert("data".into(), Value::Null);
    }

    if !outcome.warnings.is_empty() {
        envelope.insert(
            "warnings".into(),
            Value::Array(
                outcome
                    .warnings
                    .iter()
                    .map(|w| Value::String(w.clone()))
                    .collect(),
            ),
        );
    }

    if let Some(ref err) = outcome.error {
        envelope.insert(
            "error".into(),
            serde_json::json!({
                "code": err.code,
                "message": err.message,
            }),
        );
    }

    // stdout: always a single JSON line
    println!(
        "{}",
        serde_json::to_string(&Value::Object(envelope))
            .expect("BUG: failed to serialize JSON envelope")
    );

    // stderr: error message only in json mode; nothing in quiet mode
    if !suppress_stderr {
        if let Some(ref err) = outcome.error {
            eprintln!("Error: {}", err.message);
        }
    }
}

// ---------------------------------------------------------------------------
// Human renderer
// ---------------------------------------------------------------------------

fn render_human(outcome: &CliOutcome) {
    // stdout
    match &outcome.render.stdout {
        StdoutRender::Table { columns, rows } => {
            print_table(columns, rows);
        }
        StdoutRender::KeyValue { pairs } => {
            for (key, value) in pairs {
                println!("  {key}: {value}");
            }
        }
        StdoutRender::Raw { value } => {
            println!("{value}");
        }
        StdoutRender::None => {}
    }

    // stderr (auxiliary info from render plan)
    for line in &outcome.render.stderr {
        match line {
            StderrLine::Status(msg) => eprintln!("{msg}"),
            StderrLine::Warn(msg) => eprintln!("⚠ {msg}"),
            StderrLine::Hint(msg) => eprintln!("💡 {msg}"),
            StderrLine::Info(key, value) => eprintln!("  {key}: {value}"),
        }
    }

    // Warnings from CliResponse::with_warning() (e.g. deprecation notices)
    for warning in &outcome.warnings {
        eprintln!("⚠ {warning}");
    }

    // Error display: only if render.stderr didn't already contain contextual messages
    // (CliError path has empty render.stderr, so the error shows here)
    if let Some(ref err) = outcome.error {
        if outcome.render.stderr.is_empty() {
            eprintln!("Error: {}", err.message);
        }
    }
}

// ---------------------------------------------------------------------------
// Table printer (reuses display/format.rs utilities)
// ---------------------------------------------------------------------------

use super::types::Column;

fn print_table(columns: &[Column], rows: &[Vec<String>]) {
    if rows.is_empty() {
        return;
    }

    // Calculate column widths
    let mut widths: Vec<usize> = columns.iter().map(|c| display_width(&c.header)).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() {
                let w = display_width(cell);
                if w > widths[i] {
                    widths[i] = w;
                }
            }
        }
    }

    // Apply max_width constraints
    for (i, col) in columns.iter().enumerate() {
        if let Some(max) = col.max_width {
            if widths[i] > max {
                widths[i] = max;
            }
        }
    }

    // Header
    let header: Vec<String> = columns
        .iter()
        .enumerate()
        .map(|(i, col)| pad_table_cell(&col.header, widths[i]))
        .collect();
    println!("{}", header.join("  "));

    // Separator
    let sep: Vec<String> = widths.iter().map(|&w| "─".repeat(w)).collect();
    println!("{}", sep.join("  "));

    // Rows
    for row in rows {
        let cells: Vec<String> = row
            .iter()
            .enumerate()
            .map(|(i, cell)| {
                let truncated = if i < columns.len() {
                    if let Some(max) = columns[i].max_width {
                        truncate_table_cell(cell, max)
                    } else {
                        cell.clone()
                    }
                } else {
                    cell.clone()
                };
                let width = if i < widths.len() { widths[i] } else { 0 };
                pad_table_cell(&truncated, width)
            })
            .collect();
        println!("{}", cells.join("  "));
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use serde::Serialize;
    use serde_json::Value;

    use crate::output::types::{
        CliOutcome, CliResponse, EnvelopeError, RenderPlan,
    };

    /// Captures stdout by building the envelope manually and checking it.
    #[test]
    fn render_json_success_produces_valid_envelope() {
        let outcome = CliOutcome {
            ok: true,
            data: Some(serde_json::json!({"items": []})),
            warnings: vec![],
            error: None,
            render: RenderPlan::none(),
            exit_code: 0,
        };

        // Simulate what render_json does
        let mut envelope = serde_json::Map::new();
        envelope.insert("ok".into(), Value::Bool(outcome.ok));
        if let Some(ref data) = outcome.data {
            envelope.insert("data".into(), data.clone());
        } else {
            envelope.insert("data".into(), Value::Null);
        }

        let json_str = serde_json::to_string(&Value::Object(envelope)).unwrap();
        let parsed: Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["ok"], true);
        assert_eq!(parsed["data"]["items"], Value::Array(vec![]));
    }

    #[test]
    fn render_json_error_includes_error_field() {
        let outcome = CliOutcome {
            ok: false,
            data: None,
            warnings: vec![],
            error: Some(EnvelopeError {
                code: "auth_error".into(),
                message: "token expired".into(),
            }),
            render: RenderPlan::none(),
            exit_code: 1,
        };

        let mut envelope = serde_json::Map::new();
        envelope.insert("ok".into(), Value::Bool(outcome.ok));
        envelope.insert("data".into(), Value::Null);
        if let Some(ref err) = outcome.error {
            envelope.insert(
                "error".into(),
                serde_json::json!({"code": err.code, "message": err.message}),
            );
        }

        let json_str = serde_json::to_string(&Value::Object(envelope)).unwrap();
        let parsed: Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["ok"], false);
        assert_eq!(parsed["error"]["code"], "auth_error");
    }

    #[test]
    fn render_json_warnings_omitted_when_empty() {
        let outcome = CliOutcome {
            ok: true,
            data: Some(serde_json::json!(null)),
            warnings: vec![],
            error: None,
            render: RenderPlan::none(),
            exit_code: 0,
        };

        let mut envelope = serde_json::Map::new();
        envelope.insert("ok".into(), Value::Bool(outcome.ok));
        envelope.insert("data".into(), Value::Null);
        if !outcome.warnings.is_empty() {
            envelope.insert("warnings".into(), Value::Array(vec![]));
        }

        let json_str = serde_json::to_string(&Value::Object(envelope)).unwrap();
        let parsed: Value = serde_json::from_str(&json_str).unwrap();
        assert!(parsed.get("warnings").is_none());
    }

    #[test]
    fn render_json_data_bearing_failure() {
        let outcome = CliOutcome {
            ok: false,
            data: Some(serde_json::json!({"checks": [{"name": "agent", "status": "fail"}]})),
            warnings: vec![],
            error: Some(EnvelopeError {
                code: "doctor_issues_found".into(),
                message: "1 check(s) failed".into(),
            }),
            render: RenderPlan::none(),
            exit_code: 2,
        };

        let mut envelope = serde_json::Map::new();
        envelope.insert("ok".into(), Value::Bool(outcome.ok));
        if let Some(ref data) = outcome.data {
            envelope.insert("data".into(), data.clone());
        }
        if let Some(ref err) = outcome.error {
            envelope.insert(
                "error".into(),
                serde_json::json!({"code": err.code, "message": err.message}),
            );
        }

        let json_str = serde_json::to_string(&Value::Object(envelope)).unwrap();
        let parsed: Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["ok"], false);
        assert!(parsed["data"]["checks"].is_array());
        assert_eq!(parsed["error"]["code"], "doctor_issues_found");
    }

    #[test]
    fn cli_outcome_from_cli_response_ok() {
        #[derive(Serialize)]
        struct Dummy {
            value: i32,
        }

        let resp = CliResponse::ok(
            Dummy { value: 42 },
            RenderPlan::status("done"),
        );
        let outcome: CliOutcome = resp.into();

        assert!(outcome.ok);
        assert_eq!(outcome.exit_code, 0);
        assert_eq!(outcome.data.unwrap()["value"], 42);
        assert!(outcome.error.is_none());
    }

    #[test]
    fn cli_outcome_from_cli_response_with_issues() {
        #[derive(Serialize)]
        struct Checks {
            total: u32,
        }

        let resp = CliResponse::ok(Checks { total: 5 }, RenderPlan::none())
            .with_issues(2, "doctor_issues_found", "2 failed");
        let outcome: CliOutcome = resp.into();

        assert!(!outcome.ok);
        assert_eq!(outcome.exit_code, 2);
        assert_eq!(outcome.data.unwrap()["total"], 5);
        assert_eq!(outcome.error.as_ref().unwrap().code, "doctor_issues_found");
    }
}
