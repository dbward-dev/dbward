use serde::Serialize;
use serde_json::Value;

use crate::error::CliError;
use crate::output::{CliResponse, RenderPlan, StdoutRender};
use crate::server_client::ServerClient;

// ---------------------------------------------------------------------------
// Output type
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct PolicyResolveOutput {
    #[serde(flatten)]
    pub raw: Value,
}

// ---------------------------------------------------------------------------
// Command implementation
// ---------------------------------------------------------------------------

pub async fn run_resolve(
    sc: &ServerClient,
    database: &str,
    environment: &str,
    operation: Option<&str>,
) -> Result<CliResponse<PolicyResolveOutput>, CliError> {
    let mut url = format!("/api/policy-resolution?database={database}&environment={environment}");
    if let Some(op) = operation {
        url.push_str(&format!("&operation={op}"));
    }

    let resp = sc.get_json(&url).await?;

    // Build human-readable key-value output
    let mut lines = Vec::new();

    let db = resp["database"].as_str().unwrap_or("");
    let env = resp["environment"].as_str().unwrap_or("");
    let registered = resp["registered"].as_bool().unwrap_or(false);

    if !registered {
        lines.push(format!("Database:    {db}"));
        lines.push(format!("Environment: {env}"));
        lines.push("Decision:    deny (database not registered)".into());
        let render = RenderPlan {
            stdout: StdoutRender::Raw { value: lines.join("\n") },
            stderr: vec![],
        };
        return Ok(CliResponse::ok(PolicyResolveOutput { raw: resp }, render));
    }

    // Matrix mode
    if let Some(resolutions) = resp["resolutions"].as_array() {
        lines.push(format!("Database:    {db}"));
        lines.push(format!("Environment: {env}"));
        lines.push(String::new());

        let wf_width = resolutions
            .iter()
            .map(|r| r["workflow_id"].as_str().unwrap_or("-").len())
            .max()
            .unwrap_or(8)
            .max(8);
        lines.push(format!(
            "  {:<16} {:<wf_width$} {:<16} DECISION",
            "OPERATION", "WORKFLOW", "MATCHED BY"
        ));
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
            lines.push(format!("  {op:<16} {wf_id:<wf_width$} {matched:<16} {decision_display}"));
        }
        let render = RenderPlan {
            stdout: StdoutRender::Raw { value: lines.join("\n") },
            stderr: vec![],
        };
        return Ok(CliResponse::ok(PolicyResolveOutput { raw: resp }, render));
    }

    // Single operation mode
    let op = resp["operation"].as_str().unwrap_or("");
    let decision = resp["decision_preview"].as_str().unwrap_or("");
    let reason = resp["reason_code"].as_str().unwrap_or("");

    lines.push(format!("Database:    {db}"));
    lines.push(format!("Environment: {env}"));
    lines.push(format!("Operation:   {op}"));

    if let Some(wf) = resp["workflow"].as_object() {
        let wf_id = wf.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let matched_by = wf.get("matched_by").and_then(|v| v.as_str()).unwrap_or("");
        let steps = wf.get("steps").and_then(|v| v.as_array());
        let step_count = steps.map(|s| s.len()).unwrap_or(0);
        lines.push(format!("Workflow:    {wf_id} (matched by {matched_by}, {step_count} step(s))"));
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
                lines.push(format!("  Step {}:    {} ({mode}, min {min})", i + 1, approvers));
            }
        }

        if let Some(aa) = resp["auto_approve"].as_object() {
            let mode = aa.get("mode").and_then(|v| v.as_str()).unwrap_or("unknown");
            let display = match mode {
                "always" => "always (all requests auto-approved)".to_string(),
                "risk_based" => {
                    let max_risk = aa
                        .get("max_risk_level")
                        .and_then(|v| v.as_str())
                        .unwrap_or("none");
                    format!("risk ≤ {max_risk}")
                }
                other => other.to_string(),
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
            lines.push(format!("Auto-approve: {display}{flags_str}"));
        } else if resp.get("auto_approve").is_some_and(|v| v.is_null()) {
            lines.push("Auto-approve: disabled (no auto_approve configured)".into());
        }

        if let Some(ep) = resp["execution_policy"].as_object() {
            let timeout = ep
                .get("statement_timeout_secs")
                .and_then(|v| v.as_u64())
                .unwrap_or(30);
            lines.push(format!("Timeout:     {timeout}s"));
            let mig_timeout = ep
                .get("migration_statement_timeout_secs")
                .and_then(|v| v.as_u64());
            match mig_timeout {
                Some(0) | None => lines.push("Mig timeout: unlimited".into()),
                Some(t) => lines.push(format!("Mig timeout: {t}s")),
            }
        }
    } else {
        lines.push("Workflow:    none".into());
    }

    let reason_display = match reason {
        "explicit_always" => "always auto-approve",
        "no_auto_approve" => "no auto-approve configured",
        "risk_unknown_until_analyzed" => "risk unknown until SQL analyzed",
        "no_matching_workflow" => "no matching workflow",
        "db_not_registered" => "database not registered",
        other => other,
    };
    lines.push(format!("Decision:    {decision} ({reason_display})"));

    let render = RenderPlan {
        stdout: StdoutRender::Raw { value: lines.join("\n") },
        stderr: vec![],
    };
    Ok(CliResponse::ok(PolicyResolveOutput { raw: resp }, render))
}
