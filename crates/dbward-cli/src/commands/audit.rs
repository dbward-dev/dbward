use serde_json::Value;

use crate::output::CliError;
use crate::output::{CliResponse, Column, RenderPlan, StderrLine, StdoutRender};
use crate::server_client::ServerClient;

// ---------------------------------------------------------------------------
// Command implementation
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub async fn run_audit(
    sc: &ServerClient,
    limit: Option<u32>,
    user: Option<&str>,
    operation: Option<&str>,
    status: Option<&str>,
    event_type: Option<&str>,
    category: Option<&str>,
    outcome: Option<&str>,
    since: Option<&str>,
    until: Option<&str>,
    environment: Option<&str>,
    verify: bool,
    output_format: &str,
) -> Result<CliResponse<Value>, CliError> {
    if verify {
        return run_audit_verify(sc).await;
    }

    let body = sc
        .list_audit_events(
            limit,
            user,
            operation,
            status,
            event_type,
            category,
            outcome,
            environment,
            since,
            until,
        )
        .await?;

    let empty = vec![];
    let entries = body["events"].as_array().unwrap_or(&empty);
    let total = body["total"].as_u64().unwrap_or(0);

    // CSV output mode
    if output_format == "csv" {
        let csv = build_audit_csv(entries, total);
        let mut stderr = vec![];
        if total > entries.len() as u64 {
            stderr.push(StderrLine::Warn(format!(
                "Showing {} of {} events. Use --limit to export more.",
                entries.len(),
                total
            )));
        }
        let render = RenderPlan {
            stdout: StdoutRender::Raw { value: csv },
            stderr,
        };
        return Ok(CliResponse::ok(body, render));
    }

    // JSON output mode (handled by JSON renderer, but set raw output for human "json" flag)
    if output_format == "json" {
        let pretty = serde_json::to_string_pretty(&body["events"]).unwrap_or_default();
        let render = RenderPlan {
            stdout: StdoutRender::Raw { value: pretty },
            stderr: vec![],
        };
        return Ok(CliResponse::ok(body, render));
    }

    // Table output (default)
    if entries.is_empty() {
        let render = RenderPlan::empty_list("audit events");
        return Ok(CliResponse::ok(body, render));
    }

    let columns = vec![
        Column::new("ID").with_max_width(10),
        Column::new("TIMESTAMP").with_max_width(22),
        Column::new("USER").with_max_width(10),
        Column::new("EVENT").with_max_width(14),
        Column::new("ENV").with_max_width(10),
        Column::new("DATABASE").with_max_width(10),
        Column::new("OUTCOME").with_max_width(12),
        Column::new("DETAIL"),
    ];

    let rows: Vec<Vec<String>> = entries
        .iter()
        .map(|e| {
            let id = e["id"].as_str().unwrap_or("?");
            let short_id = &id[..id.len().min(8)];
            let ts = e["created_at"].as_str().unwrap_or("?");
            let ts_short = &ts[..ts.len().min(19)];
            let actor = e["actor_id"].as_str().unwrap_or("?");
            let et = e["event_type"].as_str().unwrap_or("?");
            let env = e["environment"].as_str().unwrap_or("-");
            let db = e["database_name"].as_str().unwrap_or("-");
            let oc = e["outcome"].as_str().unwrap_or("?");
            let detail = e["detail_fingerprint"].as_str().unwrap_or("");
            let short_detail = if detail.len() > 40 {
                format!("{}...", &detail[..37])
            } else {
                detail.to_string()
            };
            vec![
                short_id.to_string(),
                ts_short.to_string(),
                actor.to_string(),
                et.to_string(),
                env.to_string(),
                db.to_string(),
                oc.to_string(),
                short_detail,
            ]
        })
        .collect();

    let render = RenderPlan::table(columns, rows);
    Ok(CliResponse::ok(body, render))
}

async fn run_audit_verify(sc: &ServerClient) -> Result<CliResponse<Value>, CliError> {
    let resp = sc.get_json("/api/audit/verify").await?;
    let count = resp["total_events"].as_u64().unwrap_or(0);
    let intact = resp["valid"].as_bool().unwrap_or(false);

    if intact {
        let render = RenderPlan {
            stdout: StdoutRender::None,
            stderr: vec![StderrLine::Status(format!(
                "✓ Hash chain intact ({count} events verified)"
            ))],
        };
        Ok(CliResponse::ok(resp, render))
    } else {
        let broken = resp["first_broken_id"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();
        let render = RenderPlan {
            stdout: StdoutRender::None,
            stderr: vec![StderrLine::Status(format!(
                "✗ Hash chain BROKEN at event {broken} ({count} events verified before break)"
            ))],
        };
        Ok(CliResponse::ok(resp, render).with_issues(
            1,
            "integrity_violation",
            format!("hash chain broken at event {broken}"),
        ))
    }
}

// ---------------------------------------------------------------------------
// CSV builder
// ---------------------------------------------------------------------------

fn build_audit_csv(entries: &[Value], _total: u64) -> String {
    let mut out = String::new();
    out.push_str("id,event_type,event_category,outcome,actor_id,created_at,environment,database_name,operation,client_ip,resource_type,resource_id,request_id,event_hash,reason\n");
    for e in entries {
        let escape = |s: &str| -> String {
            if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
                format!("\"{}\"", s.replace('"', "\"\""))
            } else {
                s.to_string()
            }
        };
        let f = |key: &str| e[key].as_str().unwrap_or("").to_string();
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
            escape(&f("id")),
            escape(&f("event_type")),
            escape(&f("event_category")),
            escape(&f("outcome")),
            escape(&f("actor_id")),
            escape(&f("created_at")),
            escape(&f("environment")),
            escape(&f("database_name")),
            escape(&f("operation")),
            escape(&f("client_ip")),
            escape(&f("resource_type")),
            escape(&f("resource_id")),
            escape(&f("request_id")),
            escape(&f("event_hash")),
            escape(&f("reason")),
        ));
    }
    out
}
