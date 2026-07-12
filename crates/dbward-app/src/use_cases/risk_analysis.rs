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
                        cascade_children: vec![],
                        cascade_children_truncated: false,
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

// --- CASCADE reverse-lookup (SLACK-9) ---

use dbward_domain::services::risk_scorer::CascadeChildInfo;
use std::collections::{HashMap, HashSet, VecDeque};

const MAX_CASCADE_DEPTH: u8 = 3;

fn canonical_key(schema: &str, name: &str) -> String {
    format!("{}.{}", schema.to_lowercase(), name.to_lowercase())
}

/// Build a reverse-lookup CASCADE graph from the full schema snapshot.
/// Returns a map: canonical_key(target) → (cascade_children, truncated).
pub fn build_cascade_graph(
    snapshot_json: &str,
    delete_targets: &[TableRef],
) -> HashMap<String, (Vec<CascadeChildInfo>, bool)> {
    let full: serde_json::Value = match serde_json::from_str(snapshot_json) {
        Ok(v) => v,
        Err(_) => return HashMap::new(),
    };
    let all_tables = match full.get("tables").and_then(|t| t.as_array()) {
        Some(t) => t,
        None => return HashMap::new(),
    };

    // 1. Build reverse map: parent_canonical_key → Vec<(child_name, child_schema, child_rows)>
    let mut reverse_map: HashMap<String, Vec<(String, String, i64)>> = HashMap::new();
    for table in all_tables {
        let child_name = table["name"].as_str().unwrap_or("");
        let child_schema = table["schema_name"].as_str().unwrap_or("public");
        let child_rows = table["estimated_rows"].as_i64().unwrap_or(0);

        let Some(constraints) = table["constraints"].as_array() else {
            continue;
        };
        for c in constraints {
            if c["on_delete"].as_str() != Some("CASCADE") {
                continue;
            }
            let Some(ref_table) = c["referenced_table"].as_str() else {
                continue;
            };
            // Fallback: if referenced_schema is absent, assume same schema as child
            let ref_schema = c
                .get("referenced_schema")
                .and_then(|s| s.as_str())
                .unwrap_or(child_schema);

            let parent_key = canonical_key(ref_schema, ref_table);
            reverse_map.entry(parent_key).or_default().push((
                child_name.to_string(),
                child_schema.to_string(),
                child_rows,
            ));
        }
    }

    // 2. BFS from each delete target
    let mut result = HashMap::new();
    for target in delete_targets {
        let target_key = match &target.schema {
            Some(s) => canonical_key(s, &target.name),
            None => {
                // Ambiguity resolution: find unique schema for this table name
                let candidates: Vec<&str> = all_tables
                    .iter()
                    .filter(|t| {
                        t["name"].as_str().map(|n| n.to_lowercase())
                            == Some(target.name.to_lowercase())
                    })
                    .filter_map(|t| t["schema_name"].as_str())
                    .collect();
                match candidates.len() {
                    1 => canonical_key(candidates[0], &target.name),
                    _ => continue, // ambiguous or not found → skip
                }
            }
        };

        let mut children: Vec<CascadeChildInfo> = Vec::new();
        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<(String, u8)> = VecDeque::new();
        let mut truncated = false;

        visited.insert(target_key.clone());
        queue.push_back((target_key.clone(), 0));

        while let Some((current_key, depth)) = queue.pop_front() {
            if depth >= MAX_CASCADE_DEPTH {
                // Only mark truncated if there are UNVISITED, non-self children
                if let Some(kids) = reverse_map.get(&current_key) {
                    let has_unvisited = kids.iter().any(|(cn, cs, _)| {
                        let ck = canonical_key(cs, cn);
                        ck != target_key && !visited.contains(&ck)
                    });
                    if has_unvisited {
                        truncated = true;
                    }
                }
                continue;
            }
            let Some(kids) = reverse_map.get(&current_key) else {
                continue;
            };
            for (child_name, child_schema, child_rows) in kids {
                let child_key = canonical_key(child_schema, child_name);

                // Self-referencing FK: include once at depth=1, never recurse
                if child_key == target_key {
                    if depth == 0 {
                        children.push(CascadeChildInfo {
                            table_name: child_name.clone(),
                            schema_name: Some(child_schema.clone()),
                            estimated_rows: *child_rows,
                            depth: 1,
                        });
                    }
                    continue;
                }

                if visited.contains(&child_key) {
                    continue;
                }
                visited.insert(child_key.clone());

                children.push(CascadeChildInfo {
                    table_name: child_name.clone(),
                    schema_name: Some(child_schema.clone()),
                    estimated_rows: *child_rows,
                    depth: depth + 1,
                });
                queue.push_back((child_key, depth + 1));
            }
        }

        // Dedup: same child referenced by multiple FKs
        children
            .sort_by(|a, b| (&a.schema_name, &a.table_name).cmp(&(&b.schema_name, &b.table_name)));
        children.dedup_by(|a, b| a.table_name == b.table_name && a.schema_name == b.schema_name);

        result.insert(target_key, (children, truncated));
    }
    result
}

/// Enrich TableRiskInfo entries with cascade children from the cascade graph.
/// Uses schema_name from the raw JSON for canonical key matching (NOT positional).
pub fn enrich_with_cascade_children(
    table_risk_info: &mut [TableRiskInfo],
    tables_raw_json: &str,
    cascade_map: &HashMap<String, (Vec<CascadeChildInfo>, bool)>,
) {
    // Build name→schema lookup from the filtered tables JSON
    let entries: Vec<serde_json::Value> = serde_json::from_str(tables_raw_json).unwrap_or_default();

    for info in table_risk_info.iter_mut() {
        // Find matching entry by name (case-insensitive). If multiple schemas
        // have the same name, skip (ambiguity already filtered by extract_tables_from_snapshot_json).
        let matching: Vec<&str> = entries
            .iter()
            .filter(|e| {
                e["name"]
                    .as_str()
                    .map(|n| n.eq_ignore_ascii_case(&info.name))
                    .unwrap_or(false)
            })
            .filter_map(|e| e["schema_name"].as_str())
            .collect();
        let schema = match matching.len() {
            1 => matching[0],
            _ => "public",
        };
        let key = canonical_key(schema, &info.name);
        if let Some((children, trunc)) = cascade_map.get(&key) {
            info.cascade_children = children.clone();
            info.cascade_children_truncated = *trunc;
        }
    }
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

    // --- build_cascade_graph tests ---

    use super::{build_cascade_graph, enrich_with_cascade_children};

    fn make_snapshot(tables_json: &str) -> String {
        format!(r#"{{"tables": {}}}"#, tables_json)
    }

    #[test]
    fn cascade_graph_basic_chain() {
        let snap = make_snapshot(
            r#"[
            {"name": "users", "schema_name": "public", "estimated_rows": 1000, "constraints": []},
            {"name": "orders", "schema_name": "public", "estimated_rows": 5000, "constraints": [
                {"name": "fk", "on_delete": "CASCADE", "referenced_table": "users"}
            ]},
            {"name": "items", "schema_name": "public", "estimated_rows": 20000, "constraints": [
                {"name": "fk", "on_delete": "CASCADE", "referenced_table": "orders"}
            ]}
        ]"#,
        );
        let targets = vec![TableRef {
            schema: Some("public".into()),
            name: "users".into(),
        }];
        let result = build_cascade_graph(&snap, &targets);
        let (children, truncated) = result.get("public.users").unwrap();
        assert!(!truncated);
        assert_eq!(children.len(), 2);
        assert!(
            children
                .iter()
                .any(|c| c.table_name == "orders" && c.depth == 1)
        );
        assert!(
            children
                .iter()
                .any(|c| c.table_name == "items" && c.depth == 2)
        );
    }

    #[test]
    fn cascade_graph_circular_reference() {
        let snap = make_snapshot(
            r#"[
            {"name": "a", "schema_name": "public", "estimated_rows": 100, "constraints": [
                {"name": "fk", "on_delete": "CASCADE", "referenced_table": "b"}
            ]},
            {"name": "b", "schema_name": "public", "estimated_rows": 200, "constraints": [
                {"name": "fk", "on_delete": "CASCADE", "referenced_table": "a"}
            ]}
        ]"#,
        );
        let targets = vec![TableRef {
            schema: Some("public".into()),
            name: "a".into(),
        }];
        let result = build_cascade_graph(&snap, &targets);
        let (children, truncated) = result.get("public.a").unwrap();
        assert!(!truncated);
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].table_name, "b");
    }

    #[test]
    fn cascade_graph_self_referencing_fk() {
        let snap = make_snapshot(
            r#"[
            {"name": "categories", "schema_name": "public", "estimated_rows": 500, "constraints": [
                {"name": "fk_parent", "on_delete": "CASCADE", "referenced_table": "categories"}
            ]}
        ]"#,
        );
        let targets = vec![TableRef {
            schema: Some("public".into()),
            name: "categories".into(),
        }];
        let result = build_cascade_graph(&snap, &targets);
        let (children, truncated) = result.get("public.categories").unwrap();
        assert!(!truncated);
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].table_name, "categories");
        assert_eq!(children[0].depth, 1);
    }

    #[test]
    fn cascade_graph_depth_truncation() {
        // Chain: a → b → c → d → e (depth 4, exceeds max 3)
        let snap = make_snapshot(
            r#"[
            {"name": "a", "schema_name": "public", "estimated_rows": 10, "constraints": []},
            {"name": "b", "schema_name": "public", "estimated_rows": 20, "constraints": [
                {"name": "fk", "on_delete": "CASCADE", "referenced_table": "a"}
            ]},
            {"name": "c", "schema_name": "public", "estimated_rows": 30, "constraints": [
                {"name": "fk", "on_delete": "CASCADE", "referenced_table": "b"}
            ]},
            {"name": "d", "schema_name": "public", "estimated_rows": 40, "constraints": [
                {"name": "fk", "on_delete": "CASCADE", "referenced_table": "c"}
            ]},
            {"name": "e", "schema_name": "public", "estimated_rows": 50, "constraints": [
                {"name": "fk", "on_delete": "CASCADE", "referenced_table": "d"}
            ]}
        ]"#,
        );
        let targets = vec![TableRef {
            schema: Some("public".into()),
            name: "a".into(),
        }];
        let result = build_cascade_graph(&snap, &targets);
        let (children, truncated) = result.get("public.a").unwrap();
        assert!(truncated);
        assert_eq!(children.len(), 3); // b, c, d (depth 1,2,3)
        assert!(children.iter().all(|c| c.depth <= 3));
    }

    #[test]
    fn cascade_graph_ambiguous_target_skipped() {
        let snap = make_snapshot(
            r#"[
            {"name": "users", "schema_name": "public", "estimated_rows": 100, "constraints": []},
            {"name": "users", "schema_name": "tenant", "estimated_rows": 200, "constraints": []}
        ]"#,
        );
        // Unqualified "users" matches both schemas → ambiguous → skipped
        let targets = vec![TableRef {
            schema: None,
            name: "users".into(),
        }];
        let result = build_cascade_graph(&snap, &targets);
        assert!(result.is_empty());
    }

    #[test]
    fn cascade_graph_referenced_schema_none_uses_child_schema() {
        // referenced_schema not in constraint → fallback to child's schema
        let snap = make_snapshot(
            r#"[
            {"name": "users", "schema_name": "app", "estimated_rows": 1000, "constraints": []},
            {"name": "orders", "schema_name": "app", "estimated_rows": 5000, "constraints": [
                {"name": "fk", "on_delete": "CASCADE", "referenced_table": "users"}
            ]}
        ]"#,
        );
        let targets = vec![TableRef {
            schema: Some("app".into()),
            name: "users".into(),
        }];
        let result = build_cascade_graph(&snap, &targets);
        let (children, _) = result.get("app.users").unwrap();
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].table_name, "orders");
    }

    #[test]
    fn cascade_graph_dedup_multiple_fks() {
        let snap = make_snapshot(
            r#"[
            {"name": "users", "schema_name": "public", "estimated_rows": 1000, "constraints": []},
            {"name": "orders", "schema_name": "public", "estimated_rows": 5000, "constraints": [
                {"name": "fk_user", "on_delete": "CASCADE", "referenced_table": "users"},
                {"name": "fk_created_by", "on_delete": "CASCADE", "referenced_table": "users"}
            ]}
        ]"#,
        );
        let targets = vec![TableRef {
            schema: Some("public".into()),
            name: "users".into(),
        }];
        let result = build_cascade_graph(&snap, &targets);
        let (children, _) = result.get("public.users").unwrap();
        assert_eq!(children.len(), 1); // deduped
    }

    #[test]
    fn cascade_graph_truncation_false_when_only_cycles() {
        // a → b → a (cycle only at depth limit)
        // depth 3 reached at b, but b's only child is a (target, visited) → not truncated
        let snap = make_snapshot(
            r#"[
            {"name": "a", "schema_name": "public", "estimated_rows": 10, "constraints": []},
            {"name": "b", "schema_name": "public", "estimated_rows": 20, "constraints": [
                {"name": "fk", "on_delete": "CASCADE", "referenced_table": "a"}
            ]},
            {"name": "c", "schema_name": "public", "estimated_rows": 30, "constraints": [
                {"name": "fk", "on_delete": "CASCADE", "referenced_table": "b"}
            ]},
            {"name": "d", "schema_name": "public", "estimated_rows": 40, "constraints": [
                {"name": "fk_cycle", "on_delete": "CASCADE", "referenced_table": "c"},
                {"name": "fk_back", "on_delete": "CASCADE", "referenced_table": "a"}
            ]}
        ]"#,
        );
        let targets = vec![TableRef {
            schema: Some("public".into()),
            name: "a".into(),
        }];
        let result = build_cascade_graph(&snap, &targets);
        let (children, truncated) = result.get("public.a").unwrap();
        // d references both c and a. d is at depth 3.
        // At depth=3, d's children via reverse map would need checking...
        // Actually d is a leaf here (no one references d), so truncated depends on what's at depth=3
        assert_eq!(children.len(), 3); // b(1), c(2), d(3)
        // d has no children in reverse map, so not truncated
        assert!(!truncated);
    }

    #[test]
    fn enrich_populates_cascade_children() {
        let snap = make_snapshot(
            r#"[
            {"name": "users", "schema_name": "public", "estimated_rows": 1000, "constraints": []},
            {"name": "orders", "schema_name": "public", "estimated_rows": 5000, "constraints": [
                {"name": "fk", "on_delete": "CASCADE", "referenced_table": "users"}
            ]}
        ]"#,
        );
        let targets = vec![TableRef {
            schema: Some("public".into()),
            name: "users".into(),
        }];
        let cascade_map = build_cascade_graph(&snap, &targets);

        let tables_raw = r#"[{"name": "users", "schema_name": "public", "estimated_rows": 1000, "constraints": []}]"#;
        let mut risk_info = vec![TableRiskInfo {
            name: "users".into(),
            estimated_rows: 1000,
            has_cascade_fk: false,
            cascade_targets: vec![],
            cascade_children: vec![],
            cascade_children_truncated: false,
        }];
        enrich_with_cascade_children(&mut risk_info, tables_raw, &cascade_map);
        assert_eq!(risk_info[0].cascade_children.len(), 1);
        assert_eq!(risk_info[0].cascade_children[0].table_name, "orders");
        assert!(!risk_info[0].cascade_children_truncated);
    }
}
