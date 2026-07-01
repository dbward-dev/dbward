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
        println!("{}", serde_json::to_string_pretty(&result).unwrap_or_default());
        return Ok(());
    }

    // Human-readable output
    let status = result["status"].as_str().unwrap_or("unknown");
    let risk = result["risk"].as_str().unwrap_or("unknown");

    let status_icon = match status {
        "requestable" => "✅",
        "blocked" => "🚫",
        "warning" => "⚠️",
        _ => "❓",
    };

    eprintln!("{status_icon} Status: {status}  |  Risk: {risk}");
    eprintln!();

    // Review findings
    if let Some(findings) = result["review"]["findings"].as_array() {
        if !findings.is_empty() {
            eprintln!("📋 Review findings:");
            for f in findings {
                let action = f["action"].as_str().unwrap_or("?");
                let code = f["code"].as_str().unwrap_or("?");
                let msg = f["message"].as_str().unwrap_or("");
                let icon = if action == "block" { "❌" } else { "⚠️" };
                eprintln!("  {icon} [{code}] {msg}");
            }
            eprintln!();
        }
    }

    // Policy
    if let Some(policy) = result.get("policy") {
        let can_submit = policy["caller_can_submit"].as_bool().unwrap_or(false);
        let auto = policy["would_auto_approve"].as_bool().unwrap_or(false);
        let needs_approval = policy["requires_approval"].as_bool().unwrap_or(false);
        eprintln!("📜 Policy:");
        eprintln!("  Can submit: {can_submit}  |  Auto-approve: {auto}  |  Needs approval: {needs_approval}");
        if let Some(approvers) = policy["approvers"].as_array() {
            if !approvers.is_empty() {
                let names: Vec<&str> = approvers
                    .iter()
                    .filter_map(|a| a["selector"].as_str())
                    .collect();
                eprintln!("  Approvers: {}", names.join(", "));
            }
        }
        eprintln!();
    }

    // Impact (EXPLAIN)
    if let Some(impact) = result.get("impact") {
        let impact_status = impact["status"].as_str().unwrap_or("skipped");
        if impact_status != "skipped" {
            eprintln!("🔍 EXPLAIN: {impact_status}");
            if impact_status == "completed" {
                if let Some(rows) = impact["estimated_rows"].as_i64() {
                    eprintln!("  Estimated rows: {rows}");
                }
            }
            eprintln!();
        }
    }

    // Fix hints
    if let Some(hints) = result["fix_hints"].as_array() {
        if !hints.is_empty() {
            eprintln!("💡 Suggestions:");
            for h in hints {
                if let Some(s) = h.as_str() {
                    eprintln!("  • {s}");
                }
            }
            eprintln!();
        }
    }

    // Next actions
    if let Some(actions) = result["next_actions"].as_array() {
        if !actions.is_empty() {
            eprintln!("➡️  Next:");
            for a in actions {
                if let Some(s) = a.as_str() {
                    eprintln!("  • {s}");
                }
            }
        }
    }

    // Exit with non-zero if blocked
    if status == "blocked" {
        std::process::exit(1);
    }

    Ok(())
}
