use crate::error::CliError;
use crate::server_client::ServerClient;

#[allow(clippy::too_many_arguments)]
pub async fn run_audit(
    sc: &ServerClient,
    json_output: bool,
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
    output: &str,
) -> Result<(), CliError> {
    if verify {
        let resp = sc.get_json("/api/audit/verify").await?;
        if json_output {
            println!("{}", serde_json::to_string_pretty(&resp)?);
        } else {
            let count = resp["total_events"].as_u64().unwrap_or(0);
            let intact = resp["valid"].as_bool().unwrap_or(false);
            if intact {
                println!("✓ Hash chain intact ({count} events verified)");
            } else {
                let broken = resp["first_broken_id"].as_str().unwrap_or("unknown");
                eprintln!(
                    "✗ Hash chain BROKEN at event {broken} ({count} events verified before break)"
                );
                std::process::exit(1);
            }
        }
        return Ok(());
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

    if json_output {
        println!("{}", serde_json::to_string_pretty(&body)?);
        return Ok(());
    }
    if output == "json" {
        println!("{}", serde_json::to_string_pretty(&body["events"])?);
        return Ok(());
    }
    if output == "csv" {
        print_audit_csv(&body);
        return Ok(());
    }

    print_audit_table(&body);
    Ok(())
}

fn print_audit_csv(body: &serde_json::Value) {
    let empty = vec![];
    let entries = body["events"].as_array().unwrap_or(&empty);
    let total = body["total"].as_u64().unwrap_or(0);
    if total > entries.len() as u64 {
        eprintln!(
            "⚠ Showing {} of {} events. Use --limit to export more.",
            entries.len(),
            total
        );
    }
    println!(
        "id,event_type,event_category,outcome,actor_id,created_at,environment,database_name,operation,client_ip,resource_type,resource_id,request_id,event_hash,reason"
    );
    for e in entries {
        let escape = |s: &str| {
            if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
                format!("\"{}\"", s.replace('"', "\"\""))
            } else {
                s.to_string()
            }
        };
        let f = |key: &str| e[key].as_str().unwrap_or("").to_string();
        println!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
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
        );
    }
}

fn print_audit_table(body: &serde_json::Value) {
    let empty = vec![];
    let entries = body["events"].as_array().unwrap_or(&empty);
    if entries.is_empty() {
        println!("No audit events.");
        return;
    }
    println!(
        "{:<10} {:<22} {:<10} {:<14} {:<10} {:<10} {:<12} DETAIL",
        "ID", "TIMESTAMP", "USER", "EVENT", "ENV", "DATABASE", "OUTCOME"
    );
    for e in entries {
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
        println!(
            "{:<10} {:<22} {:<10} {:<14} {:<10} {:<10} {:<12} {}",
            short_id, ts_short, actor, et, env, db, oc, short_detail
        );
    }
}
