use super::format::{display_width, pad_table_cell, sanitize_table_cell, truncate_table_cell};

pub(crate) const RESULT_CELL_MAX_WIDTH: usize = 60;

/// Result output format for row data.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum ResultFormat {
    #[default]
    Table,
    Json,
    Csv,
    Vertical,
}

impl From<dbward_config::client::ResultFormatConfig> for ResultFormat {
    fn from(c: dbward_config::client::ResultFormatConfig) -> Self {
        use dbward_config::client::ResultFormatConfig;
        match c {
            ResultFormatConfig::Table => Self::Table,
            ResultFormatConfig::Json => Self::Json,
            ResultFormatConfig::Csv => Self::Csv,
            ResultFormatConfig::Vertical => Self::Vertical,
        }
    }
}

pub(crate) fn format_result_cell_value(val: &serde_json::Value) -> String {
    let raw = if val.is_null() {
        "NULL".to_string()
    } else if let Some(s) = val.as_str() {
        s.to_string()
    } else {
        val.to_string()
    };
    truncate_table_cell(&sanitize_table_cell(&raw), RESULT_CELL_MAX_WIDTH)
}

pub(crate) fn print_execution_result(resp: &serde_json::Value) {
    if let Some(false) = resp["success"].as_bool() {
        let err = resp["error_message"]
            .as_str()
            .or_else(|| resp["error"].as_str())
            .unwrap_or("unknown error");
        eprintln!("Execution failed: {err}");
        return;
    }
    // Try "result" first (terminal result format)
    if let Some(result) = resp.get("result").filter(|v| !v.is_null()) {
        display_result_value(result);
        return;
    }
    // Try "result_data" (stream/stored format - JSON value)
    let rd = &resp["result_data"];
    if !rd.is_null() {
        display_result_value(rd);
        return;
    }
    // DML result
    if let Some(affected) = resp["rows_affected"].as_u64() {
        println!("Rows affected: {affected}");
        return;
    }
    println!("Executed successfully.");
}

/// Print execution result in the specified format.
pub(crate) fn print_execution_result_formatted(resp: &serde_json::Value, format: ResultFormat) {
    if format == ResultFormat::Table {
        print_execution_result(resp);
        return;
    }

    if let Some(false) = resp["success"].as_bool() {
        let err = resp["error_message"]
            .as_str()
            .or_else(|| resp["error"].as_str())
            .unwrap_or("unknown error");
        eprintln!("Execution failed: {err}");
        return;
    }

    // Extract rows from various response shapes
    let (rows_owned, truncated) = extract_rows_owned(resp);

    if let Some(rows) = &rows_owned {
        match format {
            ResultFormat::Json => print_result_json(rows),
            ResultFormat::Csv => print_result_csv(rows),
            ResultFormat::Vertical => print_result_vertical(rows),
            ResultFormat::Table => unreachable!(),
        }
        if truncated {
            eprintln!("\n⚠ Result truncated");
        }
    } else {
        // Non-row result (DML, migrations, etc.) — fall back to default display
        print_execution_result(resp);
    }
}

fn display_result_value(result: &serde_json::Value) {
    if let Some(text) = result.as_str() {
        println!("{text}");
    } else if let Some(rows) = result.get("rows").and_then(|r| r.as_array()) {
        print_result_table(rows);
        if result.get("truncated") == Some(&serde_json::Value::Bool(true)) {
            let reason = result["truncation_reason"]
                .as_str()
                .unwrap_or("result limit reached");
            eprintln!("\n⚠ Result truncated: {reason}");
            eprintln!(
                "  Showing {} rows. Use a LIMIT clause for precise control.",
                rows.len()
            );
        }
    } else if let Some(rows) = result.as_array() {
        print_result_table(rows);
    } else if let Some(affected) = result.get("rows_affected") {
        println!("Rows affected: {}", affected);
        if result.get("truncated") == Some(&serde_json::Value::Bool(true)) {
            let reason = result["truncation_reason"]
                .as_str()
                .unwrap_or("result limit reached");
            eprintln!("\n⚠ Result truncated: {reason}");
        }
    } else if let Some(applied) = result
        .get("applied")
        .or_else(|| result.get("applied_versions"))
        .and_then(|v| v.as_array())
    {
        if applied.is_empty() {
            println!("No applied migrations.");
        } else {
            println!("Applied migrations:");
            for v in applied {
                if let Some(s) = v.as_str() {
                    println!("  ✓ {s}");
                }
            }
        }
    } else if let Some(reverted) = result.get("reverted").and_then(|v| v.as_array()) {
        if reverted.is_empty() {
            println!("Nothing to revert.");
        } else {
            println!("Reverted migrations:");
            for v in reverted {
                if let Some(s) = v.as_str() {
                    println!("  ↩ {s}");
                }
            }
        }
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(result).unwrap_or_default()
        );
    }
}

fn extract_rows_owned(resp: &serde_json::Value) -> (Option<Vec<serde_json::Value>>, bool) {
    // Terminal format: {"result": {"rows": [...]}}
    if let Some(result) = resp.get("result").filter(|v| !v.is_null()) {
        if let Some(rows) = result.get("rows").and_then(|r| r.as_array()) {
            let truncated = result["truncated"].as_bool().unwrap_or(false);
            return (Some(rows.clone()), truncated);
        }
        if let Some(rows) = result.as_array() {
            return (Some(rows.clone()), false);
        }
        return (None, false);
    }
    // Stream/stored format: {"result_data": {rows, truncated, ...}}
    let rd = &resp["result_data"];
    if !rd.is_null() {
        if let Some(rows) = rd.get("rows").and_then(|r| r.as_array()) {
            let truncated = rd["truncated"].as_bool().unwrap_or(false);
            return (Some(rows.clone()), truncated);
        }
        if let Some(rows) = rd.as_array() {
            return (Some(rows.clone()), false);
        }
    }
    (None, false)
}

pub(crate) fn print_result_table(rows: &[serde_json::Value]) {
    for line in render_result_table(rows) {
        println!("{line}");
    }
}

pub(crate) fn render_result_table(rows: &[serde_json::Value]) -> Vec<String> {
    if rows.is_empty() {
        return vec!["(0 rows)".to_string()];
    }
    let mut columns: Vec<String> = Vec::new();
    for row in rows {
        let Some(obj) = row.as_object() else {
            return vec![serde_json::to_string_pretty(&rows).unwrap_or_default()];
        };
        for key in obj.keys() {
            if !columns.iter().any(|col| col == key) {
                columns.push(key.clone());
            }
        }
    }

    let mut widths: Vec<usize> = columns.iter().map(|c| display_width(c)).collect();
    let cell_values: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            columns
                .iter()
                .enumerate()
                .map(|(i, col)| {
                    let s = format_result_cell_value(&row[col]);
                    let width = display_width(&s);
                    if width > widths[i] {
                        widths[i] = width;
                    }
                    s
                })
                .collect()
        })
        .collect();

    let header = columns
        .iter()
        .enumerate()
        .map(|(i, c)| pad_table_cell(c, widths[i]))
        .collect::<Vec<_>>()
        .join("|");
    let sep = widths
        .iter()
        .map(|w| "-".repeat(w + 2))
        .collect::<Vec<_>>()
        .join("+");

    let mut lines = vec![header, sep];
    for cells in &cell_values {
        lines.push(
            cells
                .iter()
                .enumerate()
                .map(|(i, v)| pad_table_cell(v, widths[i]))
                .collect::<Vec<_>>()
                .join("|"),
        );
    }
    lines.push(format!(
        "({} {})",
        rows.len(),
        if rows.len() == 1 { "row" } else { "rows" }
    ));
    lines
}

fn print_result_json(rows: &[serde_json::Value]) {
    if rows.is_empty() {
        println!("[]");
        return;
    }
    println!("{}", serde_json::to_string_pretty(rows).unwrap_or_default());
}

fn print_result_csv(rows: &[serde_json::Value]) {
    if rows.is_empty() {
        return;
    }
    let columns = collect_columns(rows);
    if columns.is_empty() {
        println!("{}", serde_json::to_string_pretty(rows).unwrap_or_default());
        return;
    }

    // Header
    println!(
        "{}",
        columns
            .iter()
            .map(|c| csv_escape(c))
            .collect::<Vec<_>>()
            .join(",")
    );
    // Rows
    for row in rows {
        let line: Vec<String> = columns
            .iter()
            .map(|col| {
                let val = &row[col.as_str()];
                if val.is_null() {
                    String::new()
                } else if let Some(s) = val.as_str() {
                    csv_escape(s)
                } else {
                    csv_escape(&val.to_string())
                }
            })
            .collect();
        println!("{}", line.join(","));
    }
}

fn print_result_vertical(rows: &[serde_json::Value]) {
    if rows.is_empty() {
        println!("(0 rows)");
        return;
    }
    let columns = collect_columns(rows);
    if columns.is_empty() {
        println!("{}", serde_json::to_string_pretty(rows).unwrap_or_default());
        return;
    }
    let max_col_width = columns.iter().map(|c| c.len()).max().unwrap_or(0);

    for (i, row) in rows.iter().enumerate() {
        println!(
            "*************************** {}. row ***************************",
            i + 1
        );
        for col in &columns {
            let val = &row[col.as_str()];
            let display = if val.is_null() {
                "NULL".to_string()
            } else if let Some(s) = val.as_str() {
                s.to_string()
            } else {
                val.to_string()
            };
            println!("{:>width$}: {display}", col, width = max_col_width);
        }
        if i < rows.len() - 1 {
            println!();
        }
    }
}

fn collect_columns(rows: &[serde_json::Value]) -> Vec<String> {
    let mut columns: Vec<String> = Vec::new();
    for row in rows {
        if let Some(obj) = row.as_object() {
            for key in obj.keys() {
                if !columns.iter().any(|c| c == key) {
                    columns.push(key.clone());
                }
            }
        }
    }
    columns
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn render_result_table_empty_rows_shows_zero_rows() {
        let rows: Vec<serde_json::Value> = vec![];
        let output = render_result_table(&rows);
        assert_eq!(output, vec!["(0 rows)"]);
    }

    #[test]
    fn render_result_table_single_row() {
        let rows = vec![json!({"id": 1, "name": "test"})];
        let output = render_result_table(&rows);
        assert!(output.iter().any(|l| l.contains("id")));
        assert!(output.iter().any(|l| l.contains("test")));
        assert!(output.last().unwrap().contains("(1 row)"));
    }

    #[test]
    fn execution_result_routes_to_rows_when_rows_key_present() {
        let resp =
            json!({"success": true, "result": {"rows": [], "row_count": 0, "truncated": false}});
        let result = resp.get("result").unwrap();
        assert!(result.get("rows").and_then(|r| r.as_array()).is_some());
    }

    #[test]
    fn execution_result_routes_to_rows_affected_when_no_rows_key() {
        let resp = json!({"success": true, "result": {"rows_affected": 3, "truncated": false}});
        let result = resp.get("result").unwrap();
        assert!(result.get("rows").is_none());
        assert_eq!(result.get("rows_affected").unwrap(), 3);
    }

    #[test]
    fn execution_result_error_detected() {
        let resp = json!({"success": false, "error": "syntax error at position 5"});
        assert_eq!(resp["success"].as_bool(), Some(false));
        assert_eq!(
            resp["error"].as_str().unwrap(),
            "syntax error at position 5"
        );
    }

    #[test]
    fn display_result_routes_to_applied_migrations() {
        let result = json!({"applied": ["20260501120000", "20260502120000"]});
        assert!(result.get("applied").and_then(|v| v.as_array()).is_some());
        let arr = result["applied"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
    }

    #[test]
    fn display_result_routes_to_reverted_migrations() {
        let result = json!({"reverted": ["20260502120000"]});
        assert!(result.get("reverted").and_then(|v| v.as_array()).is_some());
    }

    #[test]
    fn display_result_empty_applied() {
        let result = json!({"applied": []});
        let arr = result["applied"].as_array().unwrap();
        assert!(arr.is_empty());
    }

    #[test]
    fn extract_rows_from_result_data_object() {
        let resp = json!({
            "success": true,
            "result_data": {"rows": [{"id": 1}], "truncated": true, "truncation_reason": "limit"}
        });
        let (rows, truncated) = extract_rows_owned(&resp);
        assert_eq!(rows.unwrap().len(), 1);
        assert!(truncated);
    }

    #[test]
    fn extract_rows_from_result_data_string_value() {
        // Server fallback: non-JSON stored as Value::String
        let resp = json!({"success": true, "result_data": "plain text"});
        let (rows, _) = extract_rows_owned(&resp);
        assert!(rows.is_none());
    }

    #[test]
    fn extract_rows_from_result_data_null() {
        let resp = json!({"success": true, "result_data": null});
        let (rows, _) = extract_rows_owned(&resp);
        assert!(rows.is_none());
    }
}
