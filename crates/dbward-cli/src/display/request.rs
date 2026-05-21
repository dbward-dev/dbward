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
                    println!("  SQL Review:  {findings} warning{}", if findings > 1 { "s" } else { "" });
                }
            }
            // Tables
            if let Some(tables) = ctx["tables"].as_array() {
                let names: Vec<&str> = tables.iter().filter_map(|v| v.as_str()).collect();
                if !names.is_empty() {
                    println!("  Tables:      {}", names.join(", "));
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
                        for (i, entry) in arr.iter().enumerate() {
                            let summary = summarize_explain_entry(entry);
                            if i == 0 {
                                println!("  Explain:     {summary}");
                            } else {
                                println!("               {summary}");
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
                                Some(if min > 1 {
                                    format!("{target} x{min}")
                                } else {
                                    target.to_string()
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

/// Extract a one-line summary from an explain entry's JSON plan.
/// Format: "NodeType on Table (rows=N, cost=X)"
fn summarize_explain_entry(entry: &serde_json::Value) -> String {
    // plan can be a string (text format) or array (JSON format from EXPLAIN JSON)
    if let Some(plan_str) = entry["plan"].as_str() {
        let preview: String = plan_str.chars().take(80).collect();
        return preview;
    }
    // JSON format: plan is an array of plan objects
    if let Some(first) = entry["plan"].as_array().and_then(|a| a.first()) {
        let plan_node = &first["Plan"];
        if !plan_node.is_null() {
            let node_type = plan_node["Node Type"].as_str().unwrap_or("?");
            let relation = plan_node["Relation Name"].as_str().unwrap_or("");
            let rows = plan_node["Plan Rows"].as_u64()
                .or_else(|| plan_node["Plans"].as_array()
                    .and_then(|p| p.first())
                    .and_then(|p| p["Plan Rows"].as_u64()))
                .unwrap_or(0);
            let cost = plan_node["Total Cost"].as_f64().unwrap_or(0.0);
            let child_node = plan_node["Plans"].as_array()
                .and_then(|p| p.first())
                .map(|p| p["Node Type"].as_str().unwrap_or(""))
                .unwrap_or("");

            let on_part = if relation.is_empty() { String::new() } else { format!(" on {relation}") };
            let via_part = if child_node.is_empty() { String::new() } else { format!(" via {child_node}") };
            return format!("{node_type}{on_part}{via_part} (rows={rows}, cost={cost:.0})");
        }
    }
    "(plan format unknown)".to_string()
}
