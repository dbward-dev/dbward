use crate::error::CliError;
use crate::server_client::ServerClient;

pub async fn run_preflight(
    sc: &ServerClient,
    db_name: &str,
    env_str: &str,
    sql: &str,
    include_explain: bool,
    explain_timeout_ms: u64,
    json_output: bool,
) -> Result<(), CliError> {
    let result = sc
        .preflight(db_name, env_str, sql, include_explain, explain_timeout_ms)
        .await?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );
        if result["status"].as_str() == Some("blocked") {
            std::process::exit(1);
        }
        return Ok(());
    }

    // Human-readable output
    let status = result["status"].as_str().unwrap_or("unknown");
    let risk = result["risk"].as_str().unwrap_or("unknown");
    let stmt_type = result["classification"]["statement_type"]
        .as_str()
        .unwrap_or("-");
    let operation = result["classification"]["operation"]
        .as_str()
        .unwrap_or("-");

    eprintln!();
    eprintln!("  Status:      {status}");
    eprintln!("  Risk:        {risk}");
    eprintln!("  Statement:   {stmt_type} ({operation})");

    // Review findings
    if let Some(findings) = result["review"]["findings"].as_array() {
        if findings.is_empty() {
            eprintln!("  Findings:    none");
        } else {
            eprintln!("  Findings:");
            for f in findings {
                let action = f["action"].as_str().unwrap_or("?");
                let code = f["code"].as_str().unwrap_or("?");
                let msg = f["message"].as_str().unwrap_or("");
                let marker = if action == "block" { "BLOCK" } else { "WARN" };
                eprintln!("    [{marker}] {code}: {msg}");
            }
        }
    }

    // Policy
    if let Some(policy) = result.get("policy") {
        let auto = policy["would_auto_approve"].as_bool().unwrap_or(false);
        let needs_approval = policy["requires_approval"].as_bool().unwrap_or(false);
        if auto {
            eprintln!("  Approval:    auto-approve");
        } else if needs_approval {
            let approvers: Vec<&str> = policy["approvers"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v["selector"].as_str()).collect())
                .unwrap_or_default();
            if approvers.is_empty() {
                eprintln!("  Approval:    required");
            } else {
                eprintln!("  Approval:    required ({})", approvers.join(", "));
            }
        } else {
            eprintln!("  Approval:    not required");
        }
    }

    // Impact (EXPLAIN)
    if let Some(impact) = result.get("impact") {
        let impact_status = impact["status"].as_str().unwrap_or("skipped");
        match impact_status {
            "completed" => {
                eprintln!("  EXPLAIN:     completed");
                // Extract plan summary from explain_plan
                if let Some(plan) = impact.get("explain_plan")
                    && let Some(arr) = plan.as_array()
                {
                    for entry in arr {
                        let p = &entry["Plan"];
                        let node = p["Node Type"].as_str().unwrap_or("?");
                        let rows = p["Plan Rows"].as_f64().map(|r| r as i64);
                        let cost = p["Total Cost"].as_f64();
                        // Check for index usage in child plans
                        let index = p["Plans"]
                            .as_array()
                            .and_then(|plans| {
                                plans.iter().find_map(|child| {
                                    child["Index Name"].as_str().map(|idx| {
                                        format!(
                                            "{} using {}",
                                            child["Node Type"].as_str().unwrap_or("Scan"),
                                            idx
                                        )
                                    })
                                })
                            })
                            .or_else(|| {
                                p["Index Name"]
                                    .as_str()
                                    .map(|idx| format!("{node} using {idx}"))
                            });

                        let mut summary = String::new();
                        if let Some(idx_info) = index {
                            summary.push_str(&idx_info);
                        } else {
                            summary.push_str(node);
                        }
                        if let Some(r) = rows {
                            summary.push_str(&format!(" (rows: {r}"));
                            if let Some(c) = cost {
                                summary.push_str(&format!(", cost: {c:.2}"));
                            }
                            summary.push(')');
                        }
                        eprintln!("    Plan: {summary}");
                    }
                }
            }
            "skipped" => {}
            other => eprintln!("  EXPLAIN:     {other}"),
        }
    }

    // Fix hints
    if let Some(hints) = result["fix_hints"].as_array()
        && !hints.is_empty()
    {
        eprintln!();
        eprintln!("  Suggestions:");
        for h in hints {
            if let Some(s) = h.as_str() {
                eprintln!("    - {s}");
            }
        }
    }

    // Next actions
    if let Some(actions) = result["next_actions"].as_array()
        && !actions.is_empty()
    {
        eprintln!();
        eprintln!("  Next steps:");
        for a in actions {
            if let Some(s) = a.as_str() {
                eprintln!("    - {s}");
            }
        }
    }

    eprintln!();

    // Exit with non-zero if blocked
    if status == "blocked" {
        std::process::exit(1);
    }

    Ok(())
}
