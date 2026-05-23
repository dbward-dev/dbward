use crate::error::CliError;
use crate::server_client::ServerClient;

pub async fn run_resolve(
    sc: &ServerClient,
    json_output: bool,
    database: &str,
    environment: &str,
    operation: Option<&str>,
) -> Result<(), CliError> {
    let mut url = format!("/api/policy-resolution?database={database}&environment={environment}",);
    if let Some(op) = operation {
        url.push_str(&format!("&operation={op}"));
    }

    let resp = sc.get_json(&url).await?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    // Human output
    let db = resp["database"].as_str().unwrap_or("");
    let env = resp["environment"].as_str().unwrap_or("");
    let registered = resp["registered"].as_bool().unwrap_or(false);

    if !registered {
        println!("Database:    {db}");
        println!("Environment: {env}");
        println!("Decision:    deny (database not registered)");
        return Ok(());
    }

    // Matrix mode
    if let Some(resolutions) = resp["resolutions"].as_array() {
        println!("Database:    {db}");
        println!("Environment: {env}");
        println!();
        // Compute column widths based on data
        let wf_width = resolutions
            .iter()
            .map(|r| r["workflow_id"].as_str().unwrap_or("-").len())
            .max()
            .unwrap_or(8)
            .max(8);
        println!(
            "  {:<16} {:<wf_width$} {:<16} DECISION",
            "OPERATION", "WORKFLOW", "MATCHED BY"
        );
        for r in resolutions {
            let op = r["operation"].as_str().unwrap_or("");
            let wf_id = r["workflow_id"].as_str().unwrap_or("-");
            let matched = r["matched_by"].as_str().unwrap_or("-");
            let decision = r["decision_preview"].as_str().unwrap_or("");
            let reason = r["reason_code"].as_str().unwrap_or("");
            let decision_display = if reason.is_empty() || reason == "risk_unknown_until_analyzed" {
                decision.to_string()
            } else {
                format!("{decision} ({reason})")
            };
            println!("  {op:<16} {wf_id:<wf_width$} {matched:<16} {decision_display}");
        }
        return Ok(());
    }

    // Single operation mode
    let op = resp["operation"].as_str().unwrap_or("");
    let decision = resp["decision_preview"].as_str().unwrap_or("");
    let reason = resp["reason_code"].as_str().unwrap_or("");

    println!("Database:    {db}");
    println!("Environment: {env}");
    println!("Operation:   {op}");

    if let Some(wf) = resp["workflow"].as_object() {
        let wf_id = wf.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let matched_by = wf.get("matched_by").and_then(|v| v.as_str()).unwrap_or("");
        let steps = wf.get("steps").and_then(|v| v.as_array());
        let step_count = steps.map(|s| s.len()).unwrap_or(0);
        println!("Workflow:    {wf_id} (matched by {matched_by}, {step_count} step(s))");
        if let Some(steps) = steps {
            for (i, step) in steps.iter().enumerate() {
                let approvers = step["approvers"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                let mode = step["mode"].as_str().unwrap_or("all");
                let min = step["min"].as_u64().unwrap_or(1);
                println!("  Step {}:    {} ({mode}, min {min})", i + 1, approvers);
            }
        }

        // Only show auto_approve / execution_policy when workflow matched
        if let Some(aa) = resp["auto_approve"].as_object() {
            let max_risk = aa.get("max_risk").and_then(|v| v.as_str());
            let display = match max_risk {
                Some(level) => format!("risk ≤ {level}"),
                None => "disabled".to_string(),
            };
            let flags: Vec<&str> = [
                aa.get("allow_read_only")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                    .then_some("allow_read_only"),
                aa.get("allow_safe_ddl")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                    .then_some("allow_safe_ddl"),
            ]
            .into_iter()
            .flatten()
            .collect();
            let flags_str = if flags.is_empty() {
                String::new()
            } else {
                format!(" ({})", flags.join(", "))
            };
            println!("Auto-approve: {display}{flags_str}");
        }

        if let Some(ep) = resp["execution_policy"].as_object() {
            let timeout = ep
                .get("statement_timeout_secs")
                .and_then(|v| v.as_u64())
                .unwrap_or(30);
            println!("Timeout:     {timeout}s");
        }
    } else {
        println!("Workflow:    none");
    }

    let reason_display = match reason {
        "read_only_low_risk" => "read_only",
        "empty_steps" => "empty steps",
        "no_matching_workflow" => "no matching workflow",
        "db_not_registered" => "database not registered",
        "risk_unknown_until_analyzed" => "risk unknown until SQL analyzed",
        other => other,
    };
    println!("Decision:    {decision} ({reason_display})");

    Ok(())
}
