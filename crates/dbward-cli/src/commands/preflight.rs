use serde::Serialize;
use serde_json::Value;

use crate::error::CliError;
use crate::output::{CliResponse, RenderPlan, StderrLine, StdoutRender};
use crate::server_client::ServerClient;

// ---------------------------------------------------------------------------
// Output type
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct PreflightOutput {
    #[serde(flatten)]
    pub raw: Value,
}

// ---------------------------------------------------------------------------
// Command implementation
// ---------------------------------------------------------------------------

pub async fn run_preflight(
    sc: &ServerClient,
    db_name: &str,
    env_str: &str,
    sql: &str,
    include_explain: bool,
    explain_timeout_ms: u64,
) -> Result<CliResponse<PreflightOutput>, CliError> {
    let result = sc
        .preflight(db_name, env_str, sql, include_explain, explain_timeout_ms)
        .await?;

    let status = result["status"].as_str().unwrap_or("unknown");
    let is_blocked = status == "blocked";

    // Build key-value pairs for human display
    let mut pairs = Vec::new();

    pairs.push(("Status".into(), status.to_string()));

    // Risk
    let risk = result["risk"].as_str().unwrap_or("unknown");
    let factors: Vec<String> = result["risk_assessment"]["factors"]
        .as_array()
        .map(|arr| dbward_app::services::risk_display::format_risk_factors(arr))
        .unwrap_or_default();
    if factors.is_empty() {
        pairs.push(("Risk".into(), risk.to_string()));
    } else if factors.len() == 1 {
        pairs.push(("Risk".into(), format!("{risk} ({})", factors[0])));
    } else {
        let detail = factors.iter().take(5).map(|f| format!("- {f}")).collect::<Vec<_>>().join("\n               ");
        let suffix = if factors.len() > 5 { format!("\n               (+{} more)", factors.len() - 5) } else { String::new() };
        pairs.push(("Risk".into(), format!("{risk}\n               {detail}{suffix}")));
    }

    // Statement type
    let stmt_type = result["classification"]["statement_type"]
        .as_str()
        .unwrap_or("-");
    let operation = result["classification"]["operation"]
        .as_str()
        .unwrap_or("-");
    pairs.push(("Statement".into(), format!("{stmt_type} ({operation})")));

    // Review findings
    if let Some(findings) = result["review"]["findings"].as_array() {
        if findings.is_empty() {
            pairs.push(("Findings".into(), "none".into()));
        } else {
            let findings_str: Vec<String> = findings
                .iter()
                .map(|f| {
                    let action = f["action"].as_str().unwrap_or("?");
                    let code = f["code"].as_str().unwrap_or("?");
                    let msg = f["message"].as_str().unwrap_or("");
                    let marker = if action == "block" { "BLOCK" } else { "WARN" };
                    format!("[{marker}] {code}: {msg}")
                })
                .collect();
            pairs.push(("Findings".into(), findings_str.join("\n    ")));
        }
    }

    // Policy
    if let Some(policy) = result.get("policy") {
        let auto = policy["would_auto_approve"].as_bool().unwrap_or(false);
        let needs_approval = policy["requires_approval"].as_bool().unwrap_or(false);
        let approval_str = if auto {
            "auto-approve".to_string()
        } else if needs_approval {
            let approvers: Vec<&str> = policy["approvers"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v["selector"].as_str()).collect())
                .unwrap_or_default();
            if approvers.is_empty() {
                "required".to_string()
            } else {
                format!("required ({})", approvers.join(", "))
            }
        } else {
            "not required".to_string()
        };
        pairs.push(("Approval".into(), approval_str));
    }

    // Impact (EXPLAIN)
    if let Some(impact) = result.get("impact") {
        let impact_status = impact["status"].as_str().unwrap_or("skipped");
        match impact_status {
            "completed" => {
                if let Some(plan) = impact.get("explain_plan")
                    && let Some(arr) = plan.as_array()
                {
                    for entry in arr {
                        let p = &entry["Plan"];
                        let node = p["Node Type"].as_str().unwrap_or("?");
                        let rows = p["Plan Rows"].as_f64().map(|r| r as i64);
                        let cost = p["Total Cost"].as_f64();
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
                        pairs.push(("EXPLAIN".into(), summary));
                    }
                } else {
                    pairs.push(("EXPLAIN".into(), "completed".into()));
                }
            }
            "skipped" => {}
            other => pairs.push(("EXPLAIN".into(), other.to_string())),
        }
    }

    // Build stderr lines for suggestions and next steps
    let mut stderr = Vec::new();

    if let Some(hints) = result["fix_hints"].as_array()
        && !hints.is_empty()
    {
        stderr.push(StderrLine::Status(String::new()));
        for h in hints {
            if let Some(s) = h.as_str() {
                stderr.push(StderrLine::Hint(s.to_string()));
            }
        }
    }

    if let Some(actions) = result["next_actions"].as_array()
        && !actions.is_empty()
    {
        stderr.push(StderrLine::Status(String::new()));
        for a in actions {
            if let Some(s) = a.as_str() {
                stderr.push(StderrLine::Hint(s.to_string()));
            }
        }
    }

    let render = RenderPlan {
        stdout: StdoutRender::KeyValue { pairs },
        stderr,
    };

    let output = PreflightOutput { raw: result };

    if is_blocked {
        Ok(CliResponse::ok(output, render)
            .with_issues(1, "blocked", "SQL blocked by review rules"))
    } else {
        Ok(CliResponse::ok(output, render))
    }
}
