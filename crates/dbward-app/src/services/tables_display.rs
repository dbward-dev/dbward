//! Parse tables_json with backward compatibility.
//! Supports legacy format (string array), rich format (schema snapshot), and intermediate format.

use serde_json::Value;

/// Parsed table entry for display.
#[derive(Debug, Clone, PartialEq)]
pub struct TableEntry {
    pub name: String,
    pub schema_name: Option<String>,
    pub estimated_rows: Option<i64>,
    pub has_cascade_fk: bool,
    pub cascade_targets: Vec<String>,
}

/// Parse tables_json with backward compatibility.
/// Returns empty vec if json is None or unparseable.
///
/// Handles three formats:
/// 1. Legacy: `["users", "public.orders"]` (string array)
/// 2. Rich: `[{name, schema_name, estimated_rows, constraints, ...}]` (schema snapshot)
/// 3. Intermediate: `[{name, estimated_rows, has_cascade_fk, cascade_targets}]` (derived)
pub fn parse_tables_json(json: Option<&str>) -> Vec<TableEntry> {
    let Some(json) = json else {
        return vec![];
    };
    let Ok(arr) = serde_json::from_str::<Vec<Value>>(json) else {
        return vec![];
    };
    arr.iter()
        .map(|v| {
            if let Some(name) = v.as_str() {
                // Legacy format: plain string (e.g. "users" or "public.orders").
                // We intentionally do NOT split on '.' because table names can contain dots.
                // schema_name stays None; the display layer shows the raw string as-is.
                TableEntry {
                    name: name.to_string(),
                    schema_name: None,
                    estimated_rows: None,
                    has_cascade_fk: false,
                    cascade_targets: vec![],
                }
            } else {
                // Object format: extract from schema snapshot or derived format
                let has_cascade = v
                    .get("has_cascade_fk")
                    .and_then(|b| b.as_bool())
                    .unwrap_or_else(|| {
                        // Compute from raw constraints array (schema snapshot format)
                        v["constraints"]
                            .as_array()
                            .map(|cs| {
                                cs.iter()
                                    .any(|c| c["on_delete"].as_str() == Some("CASCADE"))
                            })
                            .unwrap_or(false)
                    });
                let cascade_targets = v
                    .get("cascade_targets")
                    .and_then(|a| a.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|s| s.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_else(|| {
                        // Derive from raw constraints (schema snapshot format)
                        v["constraints"]
                            .as_array()
                            .map(|cs| {
                                cs.iter()
                                    .filter(|c| c["on_delete"].as_str() == Some("CASCADE"))
                                    .filter_map(|c| {
                                        c["referenced_table"].as_str().map(String::from)
                                    })
                                    .collect()
                            })
                            .unwrap_or_default()
                    });
                TableEntry {
                    name: v["name"].as_str().unwrap_or("?").to_string(),
                    schema_name: v["schema_name"].as_str().map(String::from),
                    estimated_rows: v["estimated_rows"].as_i64(),
                    has_cascade_fk: has_cascade,
                    cascade_targets,
                }
            }
        })
        .collect()
}

/// Format table names only (for compact CLI summary line).
pub fn format_table_names(entries: &[TableEntry]) -> String {
    entries
        .iter()
        .map(|e| match &e.schema_name {
            Some(s) if s != "public" => format!("{}.{}", s, e.name),
            _ => e.name.clone(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_legacy_string_array() {
        let json = r#"["users", "orders"]"#;
        let entries = parse_tables_json(Some(json));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "users");
        assert_eq!(entries[1].name, "orders");
        assert_eq!(entries[0].estimated_rows, None);
        assert!(!entries[0].has_cascade_fk);
    }

    #[test]
    fn parse_legacy_schema_qualified() {
        let json = r#"["public.users", "billing.invoices"]"#;
        let entries = parse_tables_json(Some(json));
        assert_eq!(entries[0].name, "public.users");
        assert_eq!(entries[1].name, "billing.invoices");
    }

    #[test]
    fn parse_rich_schema_snapshot() {
        let json = r#"[{
            "name": "orders",
            "schema_name": "public",
            "estimated_rows": 50000,
            "columns": [],
            "constraints": [
                {"name": "fk_items", "on_delete": "CASCADE", "referenced_table": "order_items"},
                {"name": "fk_pay", "on_delete": "SET NULL", "referenced_table": "payments"}
            ],
            "indexes": []
        }]"#;
        let entries = parse_tables_json(Some(json));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "orders");
        assert_eq!(entries[0].schema_name, Some("public".to_string()));
        assert_eq!(entries[0].estimated_rows, Some(50000));
        assert!(entries[0].has_cascade_fk);
        assert_eq!(entries[0].cascade_targets, vec!["order_items"]);
    }

    #[test]
    fn parse_rich_no_constraints() {
        let json = r#"[{
            "name": "users",
            "schema_name": "public",
            "estimated_rows": 10000,
            "constraints": []
        }]"#;
        let entries = parse_tables_json(Some(json));
        assert!(!entries[0].has_cascade_fk);
        assert!(entries[0].cascade_targets.is_empty());
    }

    #[test]
    fn parse_intermediate_format() {
        let json = r#"[{
            "name": "orders",
            "estimated_rows": 50000,
            "has_cascade_fk": true,
            "cascade_targets": ["order_items", "payments"]
        }]"#;
        let entries = parse_tables_json(Some(json));
        assert_eq!(entries[0].name, "orders");
        assert_eq!(entries[0].estimated_rows, Some(50000));
        assert!(entries[0].has_cascade_fk);
        assert_eq!(entries[0].cascade_targets, vec!["order_items", "payments"]);
    }

    #[test]
    fn parse_none() {
        let entries = parse_tables_json(None);
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_invalid_json() {
        let entries = parse_tables_json(Some("not json at all"));
        assert!(entries.is_empty());
    }

    #[test]
    fn format_table_names_with_schema() {
        let entries = vec![
            TableEntry {
                name: "users".to_string(),
                schema_name: Some("public".to_string()),
                estimated_rows: Some(1000),
                has_cascade_fk: false,
                cascade_targets: vec![],
            },
            TableEntry {
                name: "invoices".to_string(),
                schema_name: Some("billing".to_string()),
                estimated_rows: Some(500),
                has_cascade_fk: false,
                cascade_targets: vec![],
            },
        ];
        let result = format_table_names(&entries);
        assert_eq!(result, "users, billing.invoices");
    }
}
