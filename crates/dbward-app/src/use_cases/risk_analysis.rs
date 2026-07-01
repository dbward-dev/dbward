//! Shared risk-analysis helpers used by both `create_request` and `preflight`.

use dbward_domain::policies::workflow::Workflow;
use dbward_domain::services::risk_scorer::{SchemaStatus, TableRiskInfo};
use dbward_domain::services::table_extractor::TableRef;
use dbward_domain::services::status_constants;
use dbward_domain::values::Operation;

use crate::ports::SchemaRepo;

/// Resolve SchemaStatus from the schema snapshot record.
pub fn resolve_schema_status(
    schema_repo: &dyn SchemaRepo,
    database: &str,
    environment: &str,
) -> SchemaStatus {
    match schema_repo.get_snapshot(database, environment) {
        Ok(Some(s)) if s.status == status_constants::schema::READY => SchemaStatus::Ready,
        Ok(Some(_)) => SchemaStatus::Failed,
        _ => SchemaStatus::NotSynced,
    }
}

/// Parse the raw JSON from `get_tables_for` into `Vec<TableRiskInfo>`.
/// The JSON contains a `constraints` array from which we derive cascade FK info.
pub fn parse_table_risk_info(json: &str) -> Vec<TableRiskInfo> {
    serde_json::from_str::<Vec<serde_json::Value>>(json)
        .ok()
        .map(|arr| {
            arr.iter()
                .map(|t| {
                    let has_cascade = t
                        .get("constraints")
                        .and_then(|c| c.as_array())
                        .map(|cs| {
                            cs.iter().any(|c| {
                                c.get("on_delete")
                                    .and_then(|d| d.as_str())
                                    .map(|d| d == "CASCADE")
                                    .unwrap_or(false)
                            })
                        })
                        .unwrap_or(false);
                    TableRiskInfo {
                        name: t
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string(),
                        estimated_rows: t
                            .get("estimated_rows")
                            .and_then(|r| r.as_i64())
                            .unwrap_or(0),
                        has_cascade_fk: has_cascade,
                        cascade_targets: t
                            .get("constraints")
                            .and_then(|c| c.as_array())
                            .map(|cs| {
                                cs.iter()
                                    .filter(|c| {
                                        c.get("on_delete").and_then(|d| d.as_str())
                                            == Some("CASCADE")
                                    })
                                    .filter_map(|c| {
                                        c.get("referenced_table")
                                            .and_then(|t| t.as_str())
                                            .map(String::from)
                                    })
                                    .collect()
                            })
                            .unwrap_or_default(),
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Fetch table risk info from the schema repo and parse it.
pub fn resolve_table_risk(
    schema_repo: &dyn SchemaRepo,
    database: &str,
    environment: &str,
    tables: &[TableRef],
) -> Vec<TableRiskInfo> {
    if tables.is_empty() {
        return vec![];
    }
    schema_repo
        .get_tables_for(database, environment, tables)
        .ok()
        .flatten()
        .map(|json| parse_table_risk_info(&json))
        .unwrap_or_default()
}

/// Compute `allow_read_only` consistent with create_request logic.
pub fn compute_allow_read_only(operation: Operation, workflow: Option<&Workflow>) -> bool {
    operation.is_read_only()
        && workflow
            .and_then(|w| w.auto_approve.as_ref())
            .map(|aa| aa.allow_read_only)
            .unwrap_or(false)
}

/// Compute `safe_ddl` consistent with create_request logic.
/// `all_stmts_safe_ddl` should be: stmts.len() == 1 && all stmts pass is_safe_ddl_statement.
pub fn compute_safe_ddl(
    workflow: Option<&Workflow>,
    all_stmts_safe_ddl: bool,
    findings_empty: bool,
) -> bool {
    workflow
        .and_then(|w| w.auto_approve.as_ref())
        .map(|aa| aa.allow_safe_ddl)
        .unwrap_or(false)
        && all_stmts_safe_ddl
        && findings_empty
}

/// Get `max_estimated_rows` from workflow config (default: 1000).
pub fn max_estimated_rows(workflow: Option<&Workflow>) -> i64 {
    workflow
        .and_then(|w| w.auto_approve.as_ref())
        .map(|aa| aa.max_estimated_rows)
        .unwrap_or(1000)
}
