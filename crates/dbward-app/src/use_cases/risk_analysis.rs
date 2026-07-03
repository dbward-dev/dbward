//! Shared risk-analysis helpers used by both `create_request` and `preflight`.

use dbward_domain::policies::workflow::Workflow;
use dbward_domain::services::risk_scorer::{SchemaStatus, TableRiskInfo};
use dbward_domain::services::status_constants;
use dbward_domain::services::table_extractor::TableRef;
use dbward_domain::values::Operation;

use crate::ports::SchemaRepo;

/// Resolve SchemaStatus from the schema snapshot record.
/// Returns (status, collected_at) to avoid double DB lookup.
pub fn resolve_schema_status(
    schema_repo: &dyn SchemaRepo,
    database: &str,
    environment: &str,
) -> (SchemaStatus, Option<String>) {
    match schema_repo.get_snapshot(database, environment) {
        Ok(Some(s)) if s.status == status_constants::schema::READY => {
            (SchemaStatus::Ready, Some(s.collected_at))
        }
        Ok(Some(s)) => (SchemaStatus::Failed, Some(s.collected_at)),
        _ => (SchemaStatus::NotSynced, None),
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
pub fn compute_allow_read_only(operation: Operation, workflow: &Workflow) -> bool {
    operation.is_read_only()
        && workflow
            .auto_approve
            .as_ref()
            .map(|aa| aa.allow_read_only)
            .unwrap_or(false)
}

/// Compute `safe_ddl` consistent with create_request logic.
/// `all_stmts_safe_ddl` should be: stmts.len() == 1 && all stmts pass is_safe_ddl_statement.
pub fn compute_safe_ddl(
    workflow: &Workflow,
    all_stmts_safe_ddl: bool,
    findings_empty: bool,
) -> bool {
    workflow
        .auto_approve
        .as_ref()
        .map(|aa| aa.allow_safe_ddl)
        .unwrap_or(false)
        && all_stmts_safe_ddl
        && findings_empty
}

/// Get `max_estimated_rows` from workflow config (default: 1000).
pub fn max_estimated_rows(workflow: &Workflow) -> i64 {
    workflow
        .auto_approve
        .as_ref()
        .map(|aa| aa.max_estimated_rows)
        .unwrap_or(1000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbward_domain::policies::{AutoApproveMode, AutoApproveSettings};
    use dbward_domain::values::{DatabaseName, Environment};

    fn make_workflow(allow_read_only: bool) -> Workflow {
        Workflow {
            id: "wf-test".into(),
            database: DatabaseName::wildcard(),
            environment: Environment::wildcard(),
            operations: vec![],
            auto_approve: Some(AutoApproveSettings {
                mode: AutoApproveMode::Always,
                max_risk_level: None,
                allow_read_only,
                allow_safe_ddl: true,
                max_estimated_rows: 1000,
            }),
            steps: vec![],
            require_reason: false,
            allow_self_approve: false,
            allow_same_approver_across_steps: false,
            explain: true,
            pending_ttl_secs: None,
            statement_timeout_secs: None,
            approval_ttl_secs: None,
            created_at: None,
            updated_at: None,
        }
    }

    #[test]
    fn parse_table_risk_info_with_cascade() {
        let json = r#"[
            {
                "name": "orders",
                "estimated_rows": 50000,
                "constraints": [
                    {
                        "name": "fk_order_user",
                        "on_delete": "CASCADE",
                        "referenced_table": "users"
                    },
                    {
                        "name": "fk_order_product",
                        "on_delete": "SET NULL",
                        "referenced_table": "products"
                    }
                ]
            }
        ]"#;

        let info = parse_table_risk_info(json);
        assert_eq!(info.len(), 1);
        assert_eq!(info[0].name, "orders");
        assert_eq!(info[0].estimated_rows, 50000);
        assert!(info[0].has_cascade_fk);
        assert_eq!(info[0].cascade_targets, vec!["users".to_string()]);
    }

    #[test]
    fn parse_table_risk_info_empty_json() {
        let info = parse_table_risk_info("[]");
        assert!(info.is_empty());
    }

    #[test]
    fn parse_table_risk_info_invalid_json() {
        let info = parse_table_risk_info("not json");
        assert!(info.is_empty());
    }

    #[test]
    fn parse_table_risk_info_no_constraints() {
        let json = r#"[{"name": "simple", "estimated_rows": 100}]"#;
        let info = parse_table_risk_info(json);
        assert_eq!(info.len(), 1);
        assert_eq!(info[0].name, "simple");
        assert_eq!(info[0].estimated_rows, 100);
        assert!(!info[0].has_cascade_fk);
        assert!(info[0].cascade_targets.is_empty());
    }

    #[test]
    fn compute_allow_read_only_query_with_allow() {
        let wf = make_workflow(true);
        assert!(compute_allow_read_only(Operation::ExecuteSelect, &wf));
    }

    #[test]
    fn compute_allow_read_only_query_without_allow() {
        let wf = make_workflow(false);
        assert!(!compute_allow_read_only(Operation::ExecuteSelect, &wf));
    }

    #[test]
    fn compute_allow_read_only_execute_always_false() {
        let wf = make_workflow(true);
        assert!(!compute_allow_read_only(Operation::ExecuteDml, &wf));
    }

    #[test]
    fn compute_allow_read_only_no_auto_approve() {
        let mut wf = make_workflow(true);
        wf.auto_approve = None;
        assert!(!compute_allow_read_only(Operation::ExecuteSelect, &wf));
    }

    #[test]
    fn max_estimated_rows_from_workflow() {
        let wf = make_workflow(true);
        assert_eq!(max_estimated_rows(&wf), 1000);
    }

    #[test]
    fn max_estimated_rows_no_auto_approve() {
        let mut wf = make_workflow(true);
        wf.auto_approve = None;
        assert_eq!(max_estimated_rows(&wf), 1000); // default
    }
}
