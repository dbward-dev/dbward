//! Shared risk factor formatting for Slack and CLI display.
//! Handles both structured (v2) and legacy Debug-string (v1) formats.
//! Also provides the canonical serialization for risk factors.

use serde_json::Value;

/// Serialize risk factors into structured JSON values.
/// This is the single source of truth for how factors are stored/returned in APIs.
pub fn serialize_factors(
    factors: &[dbward_domain::services::risk_scorer::RiskFactor],
) -> Vec<Value> {
    use dbward_domain::services::risk_scorer::RiskFactor;
    factors
        .iter()
        .map(|f| {
            let mut obj = serde_json::json!({"name": f.name()});
            match f {
                RiskFactor::CascadeDelete { targets } => {
                    obj["targets"] = serde_json::json!(targets);
                }
                RiskFactor::LargeTable { rows } => {
                    obj["rows"] = serde_json::json!(rows);
                }
                RiskFactor::ManyWarnings { count } => {
                    obj["count"] = serde_json::json!(count);
                }
                RiskFactor::ReadOnly
                | RiskFactor::SafeDdl
                | RiskFactor::DropOperation
                | RiskFactor::MultiStatement
                | RiskFactor::SchemaNotSynced => {}
            }
            obj
        })
        .collect()
}

/// Format risk factors into human-readable strings.
///
/// Handles two formats:
/// - v2 (structured): `[{"name": "cascade_delete", "targets": ["t1"]}]`
/// - v1 (legacy Debug): `["CascadeDelete { targets: [\"t1\"] }"]`
pub fn format_risk_factors(factors: &[Value]) -> Vec<String> {
    factors.iter().map(format_single_factor).collect()
}

fn format_single_factor(f: &Value) -> String {
    if let Some(obj) = f.as_object() {
        format_structured_factor(obj)
    } else if let Some(s) = f.as_str() {
        format_legacy_factor(s)
    } else {
        "Unknown factor".to_string()
    }
}

fn format_structured_factor(obj: &serde_json::Map<String, Value>) -> String {
    let name = obj
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    match name {
        "cascade_delete" => {
            let targets = obj
                .get("targets")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            if targets.is_empty() {
                "Cascade delete".to_string()
            } else {
                format!("Cascade delete affects: {targets}")
            }
        }
        "large_table" => {
            let rows = obj.get("rows").and_then(|v| v.as_i64()).unwrap_or(0);
            format!("Large table: {} rows", format_number(rows))
        }
        "many_warnings" => {
            let count = obj.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
            format!("{count} review warnings")
        }
        "drop_operation" => "DROP/TRUNCATE operation".to_string(),
        "multi_statement" => "Multiple DML statements".to_string(),
        "schema_not_synced" => "Schema not available".to_string(),
        "read_only" => "Read-only query".to_string(),
        "safe_ddl" => "Safe DDL operation".to_string(),
        other => capitalize_snake(other),
    }
}

/// Best-effort parse of legacy Debug-format factor strings.
/// Falls back to displaying the raw string.
fn format_legacy_factor(s: &str) -> String {
    if s.starts_with("CascadeDelete") {
        // Try to extract targets from "CascadeDelete { targets: [\"t1\", \"t2\"] }"
        if let Some(start) = s.find('[')
            && let Some(end) = s.rfind(']')
        {
            let inner = &s[start + 1..end];
            let targets: Vec<&str> = inner
                .split(',')
                .map(|t| t.trim().trim_matches('"').trim_matches('\\'))
                .filter(|t| !t.is_empty())
                .collect();
            if !targets.is_empty() {
                return format!("Cascade delete affects: {}", targets.join(", "));
            }
        }
        "Cascade delete".to_string()
    } else if s.starts_with("LargeTable") {
        // Try to extract rows from "LargeTable { rows: 100000 }"
        if let Some(pos) = s.find("rows:") {
            let after = &s[pos + 5..];
            let num_str: String = after
                .trim()
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if let Ok(rows) = num_str.parse::<i64>() {
                return format!("Large table: {} rows", format_number(rows));
            }
        }
        "Large table".to_string()
    } else if s.starts_with("ManyWarnings") {
        if let Some(pos) = s.find("count:") {
            let after = &s[pos + 6..];
            let num_str: String = after
                .trim()
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if let Ok(count) = num_str.parse::<u64>() {
                return format!("{count} review warnings");
            }
        }
        "Many warnings".to_string()
    } else if s == "DropOperation" {
        "DROP/TRUNCATE operation".to_string()
    } else if s == "MultiStatement" {
        "Multiple DML statements".to_string()
    } else if s == "SchemaNotSynced" {
        "Schema not available".to_string()
    } else if s == "ReadOnly" {
        "Read-only query".to_string()
    } else if s == "SafeDdl" {
        "Safe DDL operation".to_string()
    } else {
        // Graceful degradation: show raw string
        s.to_string()
    }
}

/// Format a number with comma separators: 100000 → "100,000"
pub fn format_number(n: i64) -> String {
    if n < 0 {
        // Use unsigned_abs() to avoid overflow on i64::MIN
        return format!("-{}", format_unsigned(n.unsigned_abs()));
    }
    format_unsigned(n as u64)
}

fn format_unsigned(n: u64) -> String {
    let s = n.to_string();
    let len = s.len();
    if len <= 3 {
        return s;
    }
    let mut result = String::with_capacity(len + len / 3);
    let remainder = len % 3;
    if remainder > 0 {
        result.push_str(&s[..remainder]);
        if len > remainder {
            result.push(',');
        }
    }
    for (i, chunk) in s.as_bytes()[remainder..].chunks(3).enumerate() {
        if i > 0 {
            result.push(',');
        }
        result.push_str(std::str::from_utf8(chunk).unwrap_or(""));
    }
    result
}

fn capitalize_snake(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut capitalize_next = true;
    for c in s.chars() {
        if c == '_' {
            result.push(' ');
            capitalize_next = true;
        } else if capitalize_next {
            result.extend(c.to_uppercase());
            capitalize_next = false;
        } else {
            result.push(c);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn structured_cascade_delete() {
        let factors =
            vec![json!({"name": "cascade_delete", "targets": ["order_items", "payments"]})];
        let result = format_risk_factors(&factors);
        assert_eq!(
            result,
            vec!["Cascade delete affects: order_items, payments"]
        );
    }

    #[test]
    fn structured_large_table() {
        let factors = vec![json!({"name": "large_table", "rows": 100000})];
        let result = format_risk_factors(&factors);
        assert_eq!(result, vec!["Large table: 100,000 rows"]);
    }

    #[test]
    fn structured_many_warnings() {
        let factors = vec![json!({"name": "many_warnings", "count": 5})];
        let result = format_risk_factors(&factors);
        assert_eq!(result, vec!["5 review warnings"]);
    }

    #[test]
    fn structured_simple_factors() {
        let factors = vec![
            json!({"name": "drop_operation"}),
            json!({"name": "multi_statement"}),
            json!({"name": "schema_not_synced"}),
            json!({"name": "read_only"}),
            json!({"name": "safe_ddl"}),
        ];
        let result = format_risk_factors(&factors);
        assert_eq!(
            result,
            vec![
                "DROP/TRUNCATE operation",
                "Multiple DML statements",
                "Schema not available",
                "Read-only query",
                "Safe DDL operation",
            ]
        );
    }

    #[test]
    fn structured_unknown_factor_uses_capitalize_snake() {
        let factors = vec![json!({"name": "new_future_factor"})];
        let result = format_risk_factors(&factors);
        assert_eq!(result, vec!["New Future Factor"]);
    }

    #[test]
    fn legacy_cascade_delete() {
        let factors = vec![json!(
            "CascadeDelete { targets: [\"order_items\", \"payments\"] }"
        )];
        let result = format_risk_factors(&factors);
        assert_eq!(
            result,
            vec!["Cascade delete affects: order_items, payments"]
        );
    }

    #[test]
    fn legacy_large_table() {
        let factors = vec![json!("LargeTable { rows: 100000 }")];
        let result = format_risk_factors(&factors);
        assert_eq!(result, vec!["Large table: 100,000 rows"]);
    }

    #[test]
    fn legacy_many_warnings() {
        let factors = vec![json!("ManyWarnings { count: 4 }")];
        let result = format_risk_factors(&factors);
        assert_eq!(result, vec!["4 review warnings"]);
    }

    #[test]
    fn legacy_simple_factors() {
        let factors = vec![
            json!("DropOperation"),
            json!("MultiStatement"),
            json!("SchemaNotSynced"),
            json!("ReadOnly"),
            json!("SafeDdl"),
        ];
        let result = format_risk_factors(&factors);
        assert_eq!(
            result,
            vec![
                "DROP/TRUNCATE operation",
                "Multiple DML statements",
                "Schema not available",
                "Read-only query",
                "Safe DDL operation",
            ]
        );
    }

    #[test]
    fn legacy_unparseable_string_shows_raw() {
        let factors = vec![json!("SomethingCompletelyNew { x: 42 }")];
        let result = format_risk_factors(&factors);
        assert_eq!(result, vec!["SomethingCompletelyNew { x: 42 }"]);
    }

    #[test]
    fn empty_factors() {
        let factors: Vec<Value> = vec![];
        let result = format_risk_factors(&factors);
        assert!(result.is_empty());
    }

    #[test]
    fn mixed_v1_and_v2() {
        let factors = vec![
            json!({"name": "cascade_delete", "targets": ["items"]}),
            json!("LargeTable { rows: 50000 }"),
        ];
        let result = format_risk_factors(&factors);
        assert_eq!(
            result,
            vec!["Cascade delete affects: items", "Large table: 50,000 rows",]
        );
    }

    #[test]
    fn format_number_basic() {
        assert_eq!(format_number(0), "0");
        assert_eq!(format_number(999), "999");
        assert_eq!(format_number(1000), "1,000");
        assert_eq!(format_number(100000), "100,000");
        assert_eq!(format_number(1000000), "1,000,000");
        assert_eq!(format_number(12345678), "12,345,678");
    }

    #[test]
    fn format_number_negative() {
        assert_eq!(format_number(-1000), "-1,000");
    }

    #[test]
    fn format_number_i64_min_does_not_panic() {
        let result = format_number(i64::MIN);
        assert_eq!(result, "-9,223,372,036,854,775,808");
    }

    #[test]
    fn cascade_delete_empty_targets() {
        let factors = vec![json!({"name": "cascade_delete", "targets": []})];
        let result = format_risk_factors(&factors);
        assert_eq!(result, vec!["Cascade delete"]);
    }
}
