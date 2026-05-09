use serde_json;

pub(crate) const LIST_DETAIL_WIDTH: usize = 30;
pub(crate) const RESULT_CELL_MAX_WIDTH: usize = 60;

type RequestListRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
);

pub(crate) fn print_request_list(requests: &[serde_json::Value]) {
    let mut rows: Vec<RequestListRow> = Vec::new();
    for r in requests {
        let id = r["id"].as_str().unwrap_or("?");
        let short_id = id[..id.len().min(8)].to_string();
        let status = r["status"].as_str().unwrap_or("?").to_string();
        let user = r["created_by"].as_str().unwrap_or("?").to_string();
        let env = r["environment"].as_str().unwrap_or("?").to_string();
        let op = r["operation"].as_str().unwrap_or("?").to_string();
        let detail = r["detail"].as_str().unwrap_or("");
        let short_detail = truncate_table_cell(detail, LIST_DETAIL_WIDTH);
        let reason = r["reason"].as_str().unwrap_or("").to_string();
        let created = r["created_at"].as_str().unwrap_or("");
        let short_time = format_created_time(created);
        rows.push((
            short_id,
            status,
            user,
            env,
            op,
            short_detail,
            reason,
            short_time,
        ));
    }

    let has_reason = rows.iter().any(|r| !r.6.is_empty());
    let w = (
        rows.iter().map(|r| r.0.len()).max().unwrap_or(2).max(2) + 2,
        rows.iter().map(|r| r.1.len()).max().unwrap_or(6).max(6) + 2,
        rows.iter().map(|r| r.7.len()).max().unwrap_or(5).max(5) + 2,
        rows.iter().map(|r| r.2.len()).max().unwrap_or(4).max(4) + 2,
        rows.iter().map(|r| r.3.len()).max().unwrap_or(3).max(3) + 2,
        rows.iter().map(|r| r.4.len()).max().unwrap_or(2).max(2) + 2,
    );

    if has_reason {
        println!(
            "{:<w0$}{:<w1$}{:<w2$}{:<w3$}{:<w4$}{:<w5$}{:<dw$} REASON",
            "ID",
            "STATUS",
            "TIME",
            "USER",
            "ENV",
            "OP",
            "DETAIL",
            w0 = w.0,
            w1 = w.1,
            w2 = w.2,
            w3 = w.3,
            w4 = w.4,
            w5 = w.5,
            dw = LIST_DETAIL_WIDTH
        );
        for r in &rows {
            println!(
                "{:<w0$}{:<w1$}{:<w2$}{:<w3$}{:<w4$}{:<w5$}{:<dw$} {}",
                r.0,
                r.1,
                r.7,
                r.2,
                r.3,
                r.4,
                r.5,
                r.6,
                w0 = w.0,
                w1 = w.1,
                w2 = w.2,
                w3 = w.3,
                w4 = w.4,
                w5 = w.5,
                dw = LIST_DETAIL_WIDTH
            );
        }
    } else {
        println!(
            "{:<w0$}{:<w1$}{:<w2$}{:<w3$}{:<w4$}{:<w5$}DETAIL",
            "ID",
            "STATUS",
            "TIME",
            "USER",
            "ENV",
            "OP",
            w0 = w.0,
            w1 = w.1,
            w2 = w.2,
            w3 = w.3,
            w4 = w.4,
            w5 = w.5
        );
        for r in &rows {
            println!(
                "{:<w0$}{:<w1$}{:<w2$}{:<w3$}{:<w4$}{:<w5$}{}",
                r.0,
                r.1,
                r.7,
                r.2,
                r.3,
                r.4,
                r.5,
                w0 = w.0,
                w1 = w.1,
                w2 = w.2,
                w3 = w.3,
                w4 = w.4,
                w5 = w.5
            );
        }
    }
}

pub(crate) fn print_execution_result(resp: &serde_json::Value) {
    if let Some(false) = resp["success"].as_bool() {
        let err = resp["error"].as_str().unwrap_or("unknown error");
        eprintln!("Execution failed: {err}");
        return;
    }
    if let Some(result) = resp.get("result") {
        if result.is_null() {
            eprintln!("Executed successfully.");
        } else if let Some(text) = result.as_str() {
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
        } else {
            // Structured result with rows_affected or other format
            if let Some(affected) = result.get("rows_affected") {
                println!("Rows affected: {}", affected);
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(result).unwrap_or_default()
                );
            }
            if result.get("truncated") == Some(&serde_json::Value::Bool(true)) {
                let reason = result["truncation_reason"]
                    .as_str()
                    .unwrap_or("result limit reached");
                eprintln!("\n⚠ Result truncated: {reason}");
            }
        }
    } else {
        eprintln!("Executed successfully.");
    }
}

pub(crate) fn print_request_detail(body: &serde_json::Value) {
    let id = body["id"].as_str().unwrap_or("?");
    let status = body["status"].as_str().unwrap_or("?");
    let op = body["operation"].as_str().unwrap_or("?");
    let detail = body["detail"].as_str().unwrap_or("");
    let env = body["environment"].as_str().unwrap_or("?");
    let db = body["database_name"].as_str().unwrap_or("?");
    let user = body["created_by"].as_str().unwrap_or("?");
    let created = body["created_at"].as_str().unwrap_or("?");
    let updated = body["updated_at"].as_str().unwrap_or("?");
    let reason = body["reason"].as_str();
    let metadata = &body["metadata"];
    let idempotency_key = body["idempotency_key"].as_str();

    println!("Request {id}");
    println!("  Status:      {status}");
    println!("  Operation:   {op}");
    println!("  Detail:      {detail}");
    println!("  Environment: {env}");
    println!("  Database:    {db}");
    if let Some(r) = reason {
        println!("  Reason:      {r}");
    }
    if let Some(key) = idempotency_key {
        println!("  Idempotency: {key}");
    }
    if !metadata.is_null() {
        println!(
            "  Metadata:    {}",
            serde_json::to_string(metadata).unwrap_or_else(|_| "{}".to_string())
        );
    }
    println!("  Created by:  {user}");
    println!("  Created at:  {created}");
    println!("  Updated at:  {updated}");
    if let Some(resolved) = body["resolved_at"].as_str() {
        println!("  Resolved at: {resolved}");
    }
    if body.get("execution_token").is_some() {
        println!(
            "  Ready:       dbward request resume {}",
            short_request_id(id)
        );
    }

    // Approval progress
    if let Some(progress) = body.get("approval_progress") {
        let current = progress["current_step"].as_u64().unwrap_or(0);
        let total = progress["total_steps"].as_u64().unwrap_or(0);
        println!();
        println!("  Approval ({current}/{total} complete):");
        if let Some(steps) = progress["steps"].as_array() {
            for step in steps {
                let idx = step["index"].as_u64().unwrap_or(0);
                let mode = step["mode"].as_str().unwrap_or("all");
                let satisfied = step["satisfied"].as_bool().unwrap_or(false);
                let marker = if satisfied { "[ok]  " } else { "[wait]" };
                let approvers_desc: Vec<String> = step["approvers_required"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|a| {
                                let target = a["group"]
                                    .as_str()
                                    .map(|g| format!("group:{g}"))
                                    .or_else(|| a["role"].as_str().map(|r| format!("role:{r}")))?;
                                let min = a["min"].as_u64().unwrap_or(1);
                                Some(if min > 1 {
                                    format!("{target} x{min}")
                                } else {
                                    target
                                })
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let joiner = if mode == "any" { " | " } else { " + " };
                let desc = if approvers_desc.is_empty() {
                    "(no approvers configured)".to_string()
                } else {
                    approvers_desc.join(joiner)
                };
                println!("    {marker} Step {} [{mode}]: {desc}", idx + 1);
                if let Some(approvals) = step["approvals"].as_array() {
                    for a in approvals {
                        let who = a["user"].as_str().unwrap_or("?");
                        let at = a["at"].as_str().unwrap_or("");
                        let action = a["action"].as_str().unwrap_or("approve");
                        let verb = if action == "reject" {
                            "rejected by"
                        } else {
                            "approved by"
                        };
                        let short_time = if at.len() >= 16 { &at[11..16] } else { at };
                        if let Some(comment) = a["comment"].as_str().filter(|c| !c.is_empty()) {
                            println!("           {verb} {who} ({short_time}) - {comment}");
                        } else {
                            println!("           {verb} {who} ({short_time})");
                        }
                    }
                }
            }
        }
    }
}

pub(crate) fn print_approve_result(body: &serde_json::Value, id: &str) {
    let step = body["current_step"]
        .as_u64()
        .or_else(|| body["step_completed"].as_u64().map(|v| v + 1))
        .unwrap_or(0);
    let total = body["total_steps"].as_u64().unwrap_or(0);
    let status = body["status"].as_str().unwrap_or("pending");
    let short_id = short_request_id(id);

    println!("Approved step {step}/{total}");
    println!("Request: {short_id}");
    if status == "approved" || status == "dispatched" {
        println!(
            "All steps complete. Agent has been dispatched. Run: dbward request resume {short_id}"
        );
    } else {
        println!("Waiting for further approvals.");
    }
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

pub(crate) fn print_agents_status(body: &serde_json::Value) {
    let agents = match body["agents"].as_array() {
        Some(a) => a,
        None => {
            eprintln!("No agents registered.");
            return;
        }
    };
    if agents.is_empty() {
        eprintln!("No agents registered.");
        return;
    }

    println!(
        "{:<20} {:<10} {:<7} {:<12} {:<10}",
        "AGENT", "STATUS", "LOAD", "LAST SEEN", "UPTIME"
    );
    for a in agents {
        let id = a["id"].as_str().unwrap_or("?");
        let status = a["status"].as_str().unwrap_or("?");
        let in_flight = a["in_flight"].as_i64().unwrap_or(0);
        let max_concurrent = a["max_concurrent"].as_i64().unwrap_or(1);
        let ago = a["last_poll_ago_secs"].as_i64().unwrap_or(9999);
        let uptime = a["uptime_secs"].as_i64().unwrap_or(0);

        let load = format!("{}/{}", in_flight, max_concurrent);
        let last_seen = format_duration_ago(ago);
        let uptime_str = format_duration_short(uptime);

        println!(
            "{:<20} {:<10} {:<7} {:<12} {:<10}",
            id, status, load, last_seen, uptime_str
        );
    }

    // Print active jobs if any
    let has_active: Vec<_> = agents
        .iter()
        .filter(|a| {
            a["active_jobs"]
                .as_array()
                .map(|j| !j.is_empty())
                .unwrap_or(false)
        })
        .collect();

    if !has_active.is_empty() {
        println!("\nActive jobs:");
        for a in has_active {
            let id = a["id"].as_str().unwrap_or("?");
            println!("  {}:", id);
            if let Some(jobs) = a["active_jobs"].as_array() {
                for j in jobs {
                    let req_id = j["request_id"].as_str().unwrap_or("?");
                    let op = j["operation"].as_str().unwrap_or("?");
                    let short_id: String = req_id.chars().take(8).collect();
                    println!("    {}  {}", short_id, op);
                }
            }
        }
    }
}

pub(crate) fn format_duration_ago(secs: i64) -> String {
    if secs < 60 {
        format!("{}s ago", secs)
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else {
        format!("{}h ago", secs / 3600)
    }
}

pub(crate) fn format_duration_short(secs: i64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}
pub(crate) fn truncate_table_cell(value: &str, max_width: usize) -> String {
    if display_width(value) <= max_width {
        return value.to_string();
    }
    if max_width <= 3 {
        return ".".repeat(max_width);
    }
    let target = max_width - 3;
    let mut width = 0;
    let mut end = 0;
    for (i, c) in value.char_indices() {
        let w = unicode_width::UnicodeWidthChar::width(c).unwrap_or(0);
        if width + w > target {
            break;
        }
        width += w;
        end = i + c.len_utf8();
    }
    format!("{}...", &value[..end])
}

pub(crate) fn display_width(value: &str) -> usize {
    unicode_width::UnicodeWidthStr::width(value)
}

pub(crate) fn pad_table_cell(value: &str, width: usize) -> String {
    let padding = width.saturating_sub(display_width(value));
    format!(" {value}{} ", " ".repeat(padding))
}

pub(crate) fn sanitize_table_cell(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            '\n' | '\r' | '\t' => ' ',
            _ => ch,
        })
        .collect()
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

pub(crate) fn short_request_id(id: &str) -> &str {
    &id[..id.len().min(8)]
}

pub(crate) fn format_created_time(created_at: &str) -> String {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(created_at) {
        return dt.format("%H:%M").to_string();
    }

    for format in [
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M",
    ] {
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(created_at, format) {
            return dt.format("%H:%M").to_string();
        }
    }

    "?".to_string()
}
