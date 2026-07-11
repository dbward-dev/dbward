//! Shared EXPLAIN plan formatting helpers.
//! Used by CLI (display/request.rs) and Slack (block_kit.rs).

use serde_json::Value;

/// Options for formatting EXPLAIN plan trees.
#[derive(Debug, Clone)]
pub struct FormatOptions {
    /// Maximum depth to recurse into the plan tree.
    pub max_depth: usize,
    /// Maximum output lines (supplementary safeguard). None = unlimited.
    pub max_lines: Option<usize>,
    /// Text appended when depth or line limit is hit.
    pub truncation_hint: &'static str,
}

impl FormatOptions {
    /// Full tree options for CLI display.
    pub fn cli() -> Self {
        Self {
            max_depth: 6,
            max_lines: None,
            truncation_hint: "... (use --json for full plan)",
        }
    }

    /// Compact options for Slack Modal.
    /// max_depth=3 shows join methods AND leaf table access nodes.
    pub fn slack() -> Self {
        Self {
            max_depth: 3,
            max_lines: Some(6),
            truncation_hint: "...",
        }
    }
}

/// Format one explain entry's plan as lines of text.
/// Handles PG JSON, MySQL JSON, and text formats.
pub fn format_explain_tree(entry: &Value, opts: &FormatOptions) -> Vec<String> {
    // Text format: cap at 10 lines (text plans lack structural depth info so we
    // can't depth-limit them), then apply opts.max_lines as secondary safeguard.
    if let Some(plan_str) = entry["plan"].as_str() {
        let all_lines: Vec<String> = plan_str.lines().map(|l| l.to_string()).collect();
        let total = all_lines.len();
        let capped: Vec<String> = all_lines.into_iter().take(10).collect();
        let mut lines = apply_max_lines(capped, opts);
        // If we capped at 10 and there were more, append truncation hint
        if total > 10
            && !lines
                .last()
                .is_some_and(|l| l.contains(opts.truncation_hint))
        {
            lines.push(format!(
                "{} (+{} more lines)",
                opts.truncation_hint,
                total - 10
            ));
        }
        return lines;
    }
    // PG JSON format: [{"Plan": {...}}]
    if let Some(plan_node) = entry["plan"]
        .as_array()
        .and_then(|a| a.first())
        .map(|f| &f["Plan"])
        .filter(|p| !p.is_null())
    {
        let mut lines = Vec::new();
        walk_plan_node(plan_node, 0, opts, &mut lines);
        return apply_max_lines(lines, opts);
    }
    // PG JSON format (direct object): {"Plan": {...}}
    if let Some(plan_node) = entry["plan"].get("Plan").filter(|p| !p.is_null()) {
        let mut lines = Vec::new();
        walk_plan_node(plan_node, 0, opts, &mut lines);
        return apply_max_lines(lines, opts);
    }
    // MySQL JSON format: {"query_block": {...}}
    if let Some(qb) = entry["plan"].get("query_block").filter(|v| !v.is_null()) {
        let mut lines = Vec::new();
        walk_mysql_query_block(qb, 0, opts, &mut lines);
        return apply_max_lines(lines, opts);
    }
    vec!["(plan format unknown)".to_string()]
}

fn apply_max_lines(lines: Vec<String>, opts: &FormatOptions) -> Vec<String> {
    match opts.max_lines {
        Some(max) if lines.len() > max => {
            let mut truncated = lines[..max].to_vec();
            truncated.push(format!(
                "{} (+{} more nodes)",
                opts.truncation_hint,
                lines.len() - max
            ));
            truncated
        }
        _ => lines,
    }
}

fn walk_plan_node(node: &Value, depth: usize, opts: &FormatOptions, out: &mut Vec<String>) {
    if depth > opts.max_depth {
        let indent = "  ".repeat(depth);
        out.push(format!("{indent}{}", opts.truncation_hint));
        return;
    }
    let node_type = node["Node Type"].as_str().unwrap_or("?");
    let relation = node["Relation Name"].as_str().unwrap_or("");
    let rows = node["Plan Rows"].as_u64().unwrap_or(0);
    let cost = node["Total Cost"].as_f64().unwrap_or(0.0);
    let filter = node["Filter"].as_str();

    let indent = "  ".repeat(depth);
    let on_part = if relation.is_empty() {
        String::new()
    } else {
        format!(" on {relation}")
    };
    let mut line = format!("{indent}{node_type}{on_part} (rows={rows}, cost={cost:.0})");
    if let Some(f) = filter {
        let short_filter: String = f.chars().take(60).collect();
        line.push_str(&format!("  Filter: {short_filter}"));
    }
    out.push(line);

    if let Some(plans) = node["Plans"].as_array() {
        for child in plans {
            walk_plan_node(child, depth + 1, opts, out);
        }
    }
}

fn walk_mysql_query_block(qb: &Value, depth: usize, opts: &FormatOptions, out: &mut Vec<String>) {
    if depth > opts.max_depth {
        let indent = "  ".repeat(depth);
        out.push(format!("{indent}{}", opts.truncation_hint));
        return;
    }
    let indent = "  ".repeat(depth);
    let cost = qb["cost_info"]["query_cost"].as_str().unwrap_or("?");
    out.push(format!("{indent}query_block (cost={cost})"));

    // Single table access
    if let Some(table) = qb.get("table").filter(|v| !v.is_null()) {
        walk_mysql_table(table, depth + 1, opts, out);
    }
    // Nested loop join
    if let Some(nl) = qb["nested_loop"].as_array() {
        let indent2 = "  ".repeat(depth + 1);
        out.push(format!("{indent2}nested_loop"));
        for item in nl {
            if let Some(t) = item.get("table") {
                walk_mysql_table(t, depth + 2, opts, out);
            }
        }
    }
    // Ordering operation
    if let Some(ordering) = qb.get("ordering_operation").filter(|v| !v.is_null()) {
        let indent2 = "  ".repeat(depth + 1);
        let using_filesort = ordering["using_filesort"].as_bool().unwrap_or(false);
        let fs = if using_filesort { " (filesort)" } else { "" };
        out.push(format!("{indent2}ordering_operation{fs}"));
        if let Some(nl) = ordering["nested_loop"].as_array() {
            for item in nl {
                if let Some(t) = item.get("table") {
                    walk_mysql_table(t, depth + 2, opts, out);
                }
            }
        }
        if let Some(t) = ordering.get("table").filter(|v| !v.is_null()) {
            walk_mysql_table(t, depth + 2, opts, out);
        }
    }
    // Grouping operation
    if let Some(grouping) = qb.get("grouping_operation").filter(|v| !v.is_null()) {
        let indent2 = "  ".repeat(depth + 1);
        out.push(format!("{indent2}grouping_operation"));
        if let Some(nl) = grouping["nested_loop"].as_array() {
            for item in nl {
                if let Some(t) = item.get("table") {
                    walk_mysql_table(t, depth + 2, opts, out);
                }
            }
        }
    }
}

fn walk_mysql_table(table: &Value, depth: usize, opts: &FormatOptions, out: &mut Vec<String>) {
    if depth > opts.max_depth {
        return;
    }
    let indent = "  ".repeat(depth);
    let name = table["table_name"].as_str().unwrap_or("?");
    let access = table["access_type"].as_str().unwrap_or("?");
    let rows = table["rows_examined_per_scan"]
        .as_u64()
        .or_else(|| table["rows_produced_per_join"].as_u64())
        .unwrap_or(0);
    let filtered = table["filtered"].as_f64().unwrap_or(100.0);
    let mut line = format!("{indent}{access} on {name} (rows={rows}, filtered={filtered:.0}%)");
    if let Some(cond) = table["attached_condition"].as_str() {
        let short: String = cond.chars().take(50).collect();
        line.push_str(&format!("  WHERE: {short}"));
    }
    out.push(line);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn pg_plan_with_children() {
        let entry = json!({
            "sql": "DELETE FROM orders WHERE id < 100",
            "plan": [{"Plan": {
                "Node Type": "ModifyTable",
                "Plan Rows": 0,
                "Total Cost": 150.0,
                "Plans": [{
                    "Node Type": "Seq Scan",
                    "Relation Name": "orders",
                    "Plan Rows": 50000,
                    "Total Cost": 120.0,
                    "Filter": "(id < 100)"
                }]
            }}]
        });
        let lines = format_explain_tree(&entry, &FormatOptions::cli());
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("ModifyTable"));
        assert!(lines[1].contains("Seq Scan on orders"));
        assert!(lines[1].contains("rows=50000"));
        assert!(lines[1].contains("Filter: (id < 100)"));
    }

    #[test]
    fn pg_plan_single_node() {
        let entry = json!({
            "plan": [{"Plan": {
                "Node Type": "Seq Scan",
                "Relation Name": "users",
                "Plan Rows": 1000,
                "Total Cost": 50.0
            }}]
        });
        let lines = format_explain_tree(&entry, &FormatOptions::cli());
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("Seq Scan on users"));
        assert!(lines[0].contains("rows=1000"));
    }

    #[test]
    fn pg_plan_direct_object() {
        let entry = json!({
            "plan": {"Plan": {
                "Node Type": "Index Scan",
                "Relation Name": "users",
                "Plan Rows": 1,
                "Total Cost": 8.0
            }}
        });
        let lines = format_explain_tree(&entry, &FormatOptions::cli());
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("Index Scan on users"));
    }

    #[test]
    fn mysql_query_block() {
        let entry = json!({
            "plan": {"query_block": {
                "cost_info": {"query_cost": "45.20"},
                "nested_loop": [
                    {"table": {
                        "table_name": "orders",
                        "access_type": "ALL",
                        "rows_examined_per_scan": 50000,
                        "filtered": 30.0,
                        "attached_condition": "orders.created_at < '2024-01-01'"
                    }},
                    {"table": {
                        "table_name": "users",
                        "access_type": "eq_ref",
                        "rows_examined_per_scan": 1,
                        "filtered": 100.0
                    }}
                ]
            }}
        });
        let lines = format_explain_tree(&entry, &FormatOptions::cli());
        assert_eq!(lines.len(), 4); // query_block, nested_loop, 2 tables
        assert!(lines[0].contains("query_block (cost=45.20)"));
        assert!(lines[1].contains("nested_loop"));
        assert!(lines[2].contains("ALL on orders"));
        assert!(lines[2].contains("rows=50000"));
        assert!(lines[3].contains("eq_ref on users"));
    }

    #[test]
    fn mysql_ordering_operation() {
        let entry = json!({
            "plan": {"query_block": {
                "cost_info": {"query_cost": "10.00"},
                "ordering_operation": {
                    "using_filesort": true,
                    "table": {
                        "table_name": "products",
                        "access_type": "ALL",
                        "rows_examined_per_scan": 200,
                        "filtered": 100.0
                    }
                }
            }}
        });
        let lines = format_explain_tree(&entry, &FormatOptions::cli());
        assert!(
            lines
                .iter()
                .any(|l| l.contains("ordering_operation (filesort)"))
        );
        assert!(lines.iter().any(|l| l.contains("ALL on products")));
    }

    #[test]
    fn text_format() {
        let entry = json!({
            "plan": "Seq Scan on users\n  Filter: (id > 10)\nRows: 100"
        });
        let lines = format_explain_tree(&entry, &FormatOptions::cli());
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "Seq Scan on users");
    }

    #[test]
    fn unknown_format() {
        let entry = json!({"plan": 42});
        let lines = format_explain_tree(&entry, &FormatOptions::cli());
        assert_eq!(lines, vec!["(plan format unknown)"]);
    }

    #[test]
    fn compact_truncation() {
        // Create a plan with many children to exceed max_lines=6
        let entry = json!({
            "plan": [{"Plan": {
                "Node Type": "Append",
                "Plan Rows": 1000,
                "Total Cost": 500.0,
                "Plans": [
                    {"Node Type": "Seq Scan", "Relation Name": "t1", "Plan Rows": 100, "Total Cost": 50.0},
                    {"Node Type": "Seq Scan", "Relation Name": "t2", "Plan Rows": 100, "Total Cost": 50.0},
                    {"Node Type": "Seq Scan", "Relation Name": "t3", "Plan Rows": 100, "Total Cost": 50.0},
                    {"Node Type": "Seq Scan", "Relation Name": "t4", "Plan Rows": 100, "Total Cost": 50.0},
                    {"Node Type": "Seq Scan", "Relation Name": "t5", "Plan Rows": 100, "Total Cost": 50.0},
                    {"Node Type": "Seq Scan", "Relation Name": "t6", "Plan Rows": 100, "Total Cost": 50.0},
                    {"Node Type": "Seq Scan", "Relation Name": "t7", "Plan Rows": 100, "Total Cost": 50.0}
                ]
            }}]
        });
        let lines = format_explain_tree(&entry, &FormatOptions::slack());
        // max_lines=6, so 6 lines + 1 truncation hint = 7
        assert_eq!(lines.len(), 7);
        assert!(lines.last().unwrap().contains("(+"));
        assert!(lines.last().unwrap().contains("more nodes"));
    }

    #[test]
    fn depth_limit() {
        // Deeply nested plan (PG Plans array elements are direct node objects)
        let entry = json!({
            "plan": [{"Plan": {
                "Node Type": "Nested Loop",
                "Plan Rows": 10,
                "Total Cost": 100.0,
                "Plans": [{
                    "Node Type": "Nested Loop",
                    "Plan Rows": 5,
                    "Total Cost": 80.0,
                    "Plans": [{
                        "Node Type": "Nested Loop",
                        "Plan Rows": 3,
                        "Total Cost": 60.0,
                        "Plans": [{
                            "Node Type": "Nested Loop",
                            "Plan Rows": 2,
                            "Total Cost": 40.0,
                            "Plans": [{
                                "Node Type": "Seq Scan",
                                "Relation Name": "deep_table",
                                "Plan Rows": 1,
                                "Total Cost": 10.0
                            }]
                        }]
                    }]
                }]
            }}]
        });
        // With slack options (max_depth=3), depth 4+ should be truncated
        let lines = format_explain_tree(&entry, &FormatOptions::slack());
        assert!(lines.iter().any(|l| l.contains("...")));
        // Should NOT contain deep_table (it's at depth 4)
        assert!(!lines.iter().any(|l| l.contains("deep_table")));
    }
}
