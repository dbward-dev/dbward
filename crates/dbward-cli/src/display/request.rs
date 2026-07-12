use super::format::{format_created_time, short_request_id, truncate_table_cell};

pub(crate) const LIST_DETAIL_WIDTH: usize = 30;

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
        let user = r["requester"].as_str().unwrap_or("?").to_string();
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

pub(crate) fn print_request_detail(body: &serde_json::Value) {
    let id = body["id"].as_str().unwrap_or("?");
    let status = body["status"].as_str().unwrap_or("?");
    let op = body["operation"].as_str().unwrap_or("?");
    let detail = body["detail"].as_str().unwrap_or("");
    let env = body["environment"].as_str().unwrap_or("?");
    let db = body["database"].as_str().unwrap_or("?");
    let user = body["requester"].as_str().unwrap_or("?");
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

    // Context (risk, sql_review, explain)
    if let Some(ctx) = body.get("context").filter(|v| !v.is_null()) {
        let ctx_status = ctx["status"].as_str().unwrap_or("");
        if ctx_status == "collecting" {
            println!();
            println!("  Context:     (collecting...)");
        } else {
            println!();
            // Risk
            if let Some(risk) = ctx.get("risk").filter(|v| !v.is_null()) {
                let level = risk["level"].as_str().unwrap_or("?");
                let factors: Vec<&str> = risk["factors"]
                    .as_array()
                    .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
                    .unwrap_or_default();
                if factors.is_empty() {
                    println!("  Risk:        {level}");
                } else if factors.len() <= 3 {
                    println!("  Risk:        {level} ({})", factors.join(", "));
                } else {
                    println!(
                        "  Risk:        {level} ({}, ...+{})",
                        factors[..3].join(", "),
                        factors.len() - 3
                    );
                }
            }
            // SQL Review
            if let Some(review) = ctx.get("sql_review").filter(|v| !v.is_null()) {
                let findings = review["findings"].as_array().map(|a| a.len()).unwrap_or(0);
                if findings == 0 {
                    println!("  SQL Review:  passed");
                } else {
                    println!(
                        "  SQL Review:  {findings} warning{}",
                        if findings > 1 { "s" } else { "" }
                    );
                }
            }
            // Tables
            if let Some(tables_val) = ctx.get("tables").filter(|v| !v.is_null()) {
                let json_str = serde_json::to_string(tables_val).unwrap_or_default();
                let entries =
                    dbward_app::services::tables_display::parse_tables_json(Some(&json_str));
                if !entries.is_empty() {
                    let display: Vec<String> = entries
                        .iter()
                        .map(|e| {
                            let name = match &e.schema_name {
                                Some(s) if s != "public" => format!("{}.{}", s, e.name),
                                _ => e.name.clone(),
                            };
                            match e.estimated_rows {
                                Some(r) if r > 0 => format!("{name} (~{r} rows)"),
                                _ => name,
                            }
                        })
                        .collect();
                    println!("  Tables:      {}", display.join(", "));
                }
            }
            // Schema snapshot
            if let Some(ts) = ctx["schema_snapshot_collected_at"].as_str() {
                let short_ts = if ts.len() >= 19 { &ts[..19] } else { ts };
                println!("  Schema:      synced at {short_ts}");
            }
            // Explain
            if let Some(explain) = ctx.get("explain").filter(|v| !v.is_null()) {
                if let Some(arr) = explain.as_array() {
                    if arr.is_empty() {
                        println!("  Explain:     (no plan available)");
                    } else {
                        let multi = arr.len() > 1;
                        for (i, entry) in arr.iter().enumerate() {
                            if let Some(err) = entry["error"].as_str() {
                                let prefix = if multi {
                                    format!("[{}] ", i + 1)
                                } else {
                                    String::new()
                                };
                                let hint = entry["hint"]
                                    .as_str()
                                    .map(|h| format!(" ({h})"))
                                    .unwrap_or_default();
                                println!("  Explain:     {prefix}(error: {err}{hint})");
                                continue;
                            }
                            let lines = format_explain_tree(entry);
                            for (li, line) in lines.iter().enumerate() {
                                let label = if li == 0 && i == 0 {
                                    "  Explain:     "
                                } else {
                                    "               "
                                };
                                let prefix = if multi && li == 0 {
                                    format!("[{}] ", i + 1)
                                } else if multi {
                                    "    ".to_string()
                                } else {
                                    String::new()
                                };
                                println!("{label}{prefix}{line}");
                            }
                        }
                    }
                }
            } else if ctx_status == "ready" {
                println!("  Explain:     (no plan available)");
            }
        }
    }

    // Approval progress
    if let Some(progress) = body.get("approval_progress").filter(|v| !v.is_null()) {
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
                                let target = a["selector"].as_str()?;
                                let min = a["min"].as_u64().unwrap_or(1);
                                let current = a["current"].as_u64().unwrap_or(0);
                                let status = if current >= min { "✓" } else { "⏳" };
                                Some(format!("{target} {status} {current}/{min}"))
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

    // Decision trace
    if let Some(trace) = body.get("decision_trace").filter(|v| !v.is_null()) {
        println!();
        println!("  Decision:");
        if let Some(op) = trace["classification"]["resolved_operation"].as_str() {
            println!("    Operation:  {op}");
        }
        // SQL Review
        let parse_failed = trace["sql_review"]["parse_failed"]
            .as_bool()
            .unwrap_or(false);
        let findings = trace["sql_review"]["findings_count"].as_u64().unwrap_or(0);
        if parse_failed {
            println!("    SQL Review: skipped (parse failed)");
        } else if findings == 0 {
            println!("    SQL Review: passed");
        } else {
            println!(
                "    SQL Review: {findings} warning{}",
                if findings > 1 { "s" } else { "" }
            );
        }
        // Risk
        let level = trace["risk"]["level"].as_str().unwrap_or("?");
        let factors: Vec<&str> = trace["risk"]["factors"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        let threshold = trace["decision"]["auto_approve_threshold"].as_str();
        if factors.is_empty() {
            if let Some(t) = threshold {
                println!("    Risk:       {level} (threshold: {t})");
            } else {
                println!("    Risk:       {level}");
            }
        } else {
            let factors_str = factors.join(", ");
            if let Some(t) = threshold {
                println!("    Risk:       {level} ({factors_str}) (threshold: {t})");
            } else {
                println!("    Risk:       {level} ({factors_str})");
            }
        }
        // Workflow
        if let Some(wf) = trace["workflow"]["matched"].as_object() {
            let id = wf.get("id").and_then(|v| v.as_str()).unwrap_or("?");
            let db = wf.get("database").and_then(|v| v.as_str()).unwrap_or("*");
            let env = wf
                .get("environment")
                .and_then(|v| v.as_str())
                .unwrap_or("*");
            let steps = wf.get("step_count").and_then(|v| v.as_u64()).unwrap_or(0);
            println!(
                "    Workflow:   {id} ({db}:{env}, {steps} step{})",
                if steps != 1 { "s" } else { "" }
            );
        } else {
            println!("    Workflow:   none");
        }
        // Outcome
        let outcome = trace["decision"]["outcome"].as_str().unwrap_or("?");
        let reasons: Vec<&str> = trace["decision"]["reasons"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        if reasons.is_empty() {
            println!("    Outcome:    {outcome}");
        } else {
            println!("    Outcome:    {outcome} [{}]", reasons.join(", "));
        }
    }
}

pub(crate) fn print_approve_result(body: &serde_json::Value, id: &str) {
    let step = body["current_step"]
        .as_u64()
        .or_else(|| body["step_completed"].as_u64().map(|v| v + 1))
        .unwrap_or(0);
    let total = body["total_steps"].as_u64().unwrap_or(0);
    let status = dbward_api_types::requests::RequestStatus::from_json(&body["status"]);
    let short_id = short_request_id(id);
    let selector = body["matched_selector"].as_str().unwrap_or("unknown");

    println!("Approved as {selector} (step {step}/{total})");
    println!("Request: {short_id}");
    if matches!(
        status,
        dbward_api_types::requests::RequestStatus::Approved
            | dbward_api_types::requests::RequestStatus::Dispatched
    ) {
        println!("All steps complete. Run: dbward request resume {short_id}");
    } else {
        println!("Waiting for further approvals.");
    }
}

/// Format an explain entry's plan as an indented tree of nodes.
fn format_explain_tree(entry: &serde_json::Value) -> Vec<String> {
    dbward_app::services::explain_formatter::format_explain_tree(
        entry,
        &dbward_app::services::explain_formatter::FormatOptions::cli(),
    )
}
