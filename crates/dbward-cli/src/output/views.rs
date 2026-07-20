use serde::Serialize;

use super::types::{Column, StdoutRender};

/// Query result in a transport-neutral representation. Shared by CLI and MCP.
#[derive(Serialize, Clone, Debug)]
pub struct QueryResultView {
    pub columns: Option<Vec<String>>,
    pub rows: Option<Vec<Vec<serde_json::Value>>>,
    pub rows_affected: Option<u64>,
    pub truncated: bool,
}

impl QueryResultView {
    /// Render this view as a `StdoutRender` based on the requested result format.
    pub fn to_stdout_render(&self, format: crate::display::ResultFormat) -> StdoutRender {
        use crate::display::ResultFormat;

        // rows_affected only (DML without result set) — show as plain text regardless of format
        if self.columns.is_none() && self.rows.is_none() {
            if let Some(affected) = self.rows_affected {
                return StdoutRender::Raw {
                    value: format!("Rows affected: {affected}"),
                };
            }
            return StdoutRender::Raw {
                value: "Executed successfully.".into(),
            };
        }

        // Empty result set (0 rows)
        if self.rows.as_ref().is_some_and(|r| r.is_empty()) {
            return StdoutRender::Raw {
                value: "(0 rows)".into(),
            };
        }

        match format {
            ResultFormat::Table => self.render_table(),
            ResultFormat::Csv => StdoutRender::Raw {
                value: self.render_csv(),
            },
            ResultFormat::Vertical => StdoutRender::Raw {
                value: self.render_vertical(),
            },
            ResultFormat::Json => StdoutRender::Raw {
                value: serde_json::to_string_pretty(self).unwrap_or_default(),
            },
        }
    }

    fn render_table(&self) -> StdoutRender {
        let Some(cols) = &self.columns else {
            return StdoutRender::Raw {
                value: "Executed successfully.".into(),
            };
        };

        let rows = self.rows.as_deref().unwrap_or(&[]);
        if rows.is_empty() {
            return StdoutRender::Raw {
                value: "(0 rows)".into(),
            };
        }

        let columns: Vec<Column> = cols
            .iter()
            .map(|c| Column::new(c.as_str()).with_max_width(60))
            .collect();
        let str_rows: Vec<Vec<String>> = rows
            .iter()
            .map(|row| row.iter().map(format_cell).collect())
            .collect();

        StdoutRender::Table {
            columns,
            rows: str_rows,
        }
    }

    fn render_csv(&self) -> String {
        let cols = self.columns.as_deref().unwrap_or(&[]);
        let rows = self.rows.as_deref().unwrap_or(&[]);

        let mut out = String::new();
        // Header (escaped)
        let header_cells: Vec<String> = cols.iter().map(|c| csv_escape(c)).collect();
        out.push_str(&header_cells.join(","));
        out.push('\n');
        // Rows
        for row in rows {
            let cells: Vec<String> = row.iter().map(csv_cell).collect();
            out.push_str(&cells.join(","));
            out.push('\n');
        }
        out
    }

    fn render_vertical(&self) -> String {
        let cols = self.columns.as_deref().unwrap_or(&[]);
        let rows = self.rows.as_deref().unwrap_or(&[]);

        let mut out = String::new();
        for (i, row) in rows.iter().enumerate() {
            out.push_str(&format!("*** Row {} ***\n", i + 1));
            for (j, val) in row.iter().enumerate() {
                let col_name = cols.get(j).map(|s| s.as_str()).unwrap_or("?");
                out.push_str(&format!("{col_name}: {}\n", format_cell(val)));
            }
            if i < rows.len() - 1 {
                out.push('\n');
            }
        }
        out
    }
}

impl QueryResultView {
    /// Build a view model from the server JSON response.
    ///
    /// The server returns rows as `Vec<Object>` (e.g. `[{"id": 1, "name": "foo"}, ...]`).
    /// This method extracts column names from the keys of the first row and converts
    /// each object into a positional `Vec<Value>` for uniform downstream rendering.
    pub fn from_server_response(resp: &serde_json::Value) -> Self {
        let result = if !resp["result"].is_null() {
            &resp["result"]
        } else if !resp["result_data"].is_null() {
            &resp["result_data"]
        } else {
            &serde_json::Value::Null
        };

        let (columns, rows) = Self::extract_rows(result);

        let rows_affected = resp["rows_affected"]
            .as_u64()
            .or_else(|| result["rows_affected"].as_u64());
        let truncated = resp["truncated"].as_bool().unwrap_or(false)
            || result["truncated"].as_bool().unwrap_or(false);

        Self {
            columns,
            rows,
            rows_affected,
            truncated,
        }
    }

    /// Parse the rows from result JSON. Supports two formats:
    /// 1. Object rows: `{"rows": [{"col": val}, ...]}` — columns inferred from first row keys
    /// 2. Array rows (legacy): `{"columns": [...], "rows": [[val, ...], ...]}` — explicit columns
    fn extract_rows(
        result: &serde_json::Value,
    ) -> (Option<Vec<String>>, Option<Vec<Vec<serde_json::Value>>>) {
        let raw_rows = match result["rows"].as_array() {
            Some(arr) if !arr.is_empty() => arr,
            _ => return (None, None),
        };

        // Detect format from the first element
        if let Some(first_obj) = raw_rows[0].as_object() {
            // Object rows format: [{"col1": val1, "col2": val2}, ...]
            let columns: Vec<String> = first_obj.keys().cloned().collect();
            let rows: Vec<Vec<serde_json::Value>> = raw_rows
                .iter()
                .filter_map(|row| {
                    row.as_object().map(|obj| {
                        columns
                            .iter()
                            .map(|col| obj.get(col).cloned().unwrap_or(serde_json::Value::Null))
                            .collect()
                    })
                })
                .collect();
            (Some(columns), Some(rows))
        } else if raw_rows[0].is_array() {
            // Legacy array rows format: columns provided separately
            let columns = result["columns"].as_array().map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            });
            let rows: Vec<Vec<serde_json::Value>> = raw_rows
                .iter()
                .filter_map(|v| v.as_array().cloned())
                .collect();
            (columns, Some(rows))
        } else {
            (None, None)
        }
    }
}

// ---------------------------------------------------------------------------
// Cell formatting helpers
// ---------------------------------------------------------------------------

fn format_cell(val: &serde_json::Value) -> String {
    if val.is_null() {
        "NULL".to_string()
    } else if let Some(s) = val.as_str() {
        s.to_string()
    } else {
        val.to_string()
    }
}

fn csv_cell(val: &serde_json::Value) -> String {
    let s = format_cell(val);
    csv_escape(&s)
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // --- Object rows format (actual server response) ---

    #[test]
    fn from_server_response_object_rows() {
        let resp = json!({
            "success": true,
            "result_data": {
                "rows": [
                    {"id": 1, "name": "alice"},
                    {"id": 2, "name": "bob"}
                ],
                "truncated": false
            }
        });
        let view = QueryResultView::from_server_response(&resp);
        let cols = view.columns.unwrap();
        assert!(cols.contains(&"id".to_string()));
        assert!(cols.contains(&"name".to_string()));
        assert_eq!(view.rows.as_ref().unwrap().len(), 2);
        // Verify row values are in column order
        let id_idx = cols.iter().position(|c| c == "id").unwrap();
        let name_idx = cols.iter().position(|c| c == "name").unwrap();
        assert_eq!(view.rows.as_ref().unwrap()[0][id_idx], json!(1));
        assert_eq!(view.rows.as_ref().unwrap()[0][name_idx], json!("alice"));
        assert!(!view.truncated);
    }

    #[test]
    fn from_server_response_object_rows_single_column() {
        let resp = json!({
            "success": true,
            "result_data": {
                "rows": [{"count": 42}],
                "truncated": false
            }
        });
        let view = QueryResultView::from_server_response(&resp);
        assert_eq!(view.columns, Some(vec!["count".into()]));
        assert_eq!(view.rows.as_ref().unwrap().len(), 1);
        assert_eq!(view.rows.as_ref().unwrap()[0][0], json!(42));
    }

    #[test]
    fn from_server_response_object_rows_with_null_values() {
        let resp = json!({
            "success": true,
            "result_data": {
                "rows": [
                    {"id": 1, "email": null},
                    {"id": 2, "email": "bob@example.com"}
                ],
                "truncated": false
            }
        });
        let view = QueryResultView::from_server_response(&resp);
        let cols = view.columns.as_ref().unwrap();
        let email_idx = cols.iter().position(|c| c == "email").unwrap();
        assert_eq!(view.rows.as_ref().unwrap()[0][email_idx], json!(null));
        assert_eq!(
            view.rows.as_ref().unwrap()[1][email_idx],
            json!("bob@example.com")
        );
    }

    // --- Legacy array rows format ---

    #[test]
    fn from_server_response_with_result_field_array_rows() {
        let resp = json!({
            "success": true,
            "result": {
                "columns": ["id", "name"],
                "rows": [[1, "alice"], [2, "bob"]],
            }
        });
        let view = QueryResultView::from_server_response(&resp);
        assert_eq!(view.columns, Some(vec!["id".into(), "name".into()]));
        assert_eq!(view.rows.as_ref().unwrap().len(), 2);
        assert!(!view.truncated);
        assert!(view.rows_affected.is_none());
    }

    #[test]
    fn from_server_response_with_result_data_field_array_rows() {
        let resp = json!({
            "success": true,
            "result_data": {
                "columns": ["count"],
                "rows": [[42]],
            }
        });
        let view = QueryResultView::from_server_response(&resp);
        assert_eq!(view.columns, Some(vec!["count".into()]));
        assert_eq!(view.rows.as_ref().unwrap().len(), 1);
    }

    // --- rows_affected only ---

    #[test]
    fn from_server_response_rows_affected_only() {
        let resp = json!({
            "success": true,
            "rows_affected": 5,
            "result_data": {}
        });
        let view = QueryResultView::from_server_response(&resp);
        assert_eq!(view.rows_affected, Some(5));
        assert!(view.columns.is_none());
        assert!(view.rows.is_none());
    }

    #[test]
    fn from_server_response_rows_affected_nested() {
        let resp = json!({
            "success": true,
            "result": {
                "rows_affected": 10
            }
        });
        let view = QueryResultView::from_server_response(&resp);
        assert_eq!(view.rows_affected, Some(10));
    }

    // --- Truncated ---

    #[test]
    fn from_server_response_truncated_top_level() {
        let resp = json!({
            "success": true,
            "truncated": true,
            "result_data": {
                "rows": [{"x": 1}],
            }
        });
        let view = QueryResultView::from_server_response(&resp);
        assert!(view.truncated);
    }

    #[test]
    fn from_server_response_nested_truncated() {
        let resp = json!({
            "success": true,
            "result": {
                "rows": [{"x": 1}],
                "truncated": true,
            }
        });
        let view = QueryResultView::from_server_response(&resp);
        assert!(view.truncated);
    }

    // --- Non-tabular results (migrate etc.) ---

    #[test]
    fn from_server_response_migrate_applied() {
        let resp = json!({
            "success": true,
            "result_data": {
                "applied": ["20240101_create_users.sql", "20240102_add_email.sql"]
            }
        });
        let view = QueryResultView::from_server_response(&resp);
        // Non-tabular: no rows, no columns, no rows_affected
        assert!(view.columns.is_none());
        assert!(view.rows.is_none());
        assert!(view.rows_affected.is_none());
    }

    #[test]
    fn from_server_response_migrate_status() {
        let resp = json!({
            "success": true,
            "result_data": {
                "applied_versions": ["20240101120000", "20240102090000"]
            }
        });
        let view = QueryResultView::from_server_response(&resp);
        assert!(view.columns.is_none());
        assert!(view.rows.is_none());
    }

    // --- Empty ---

    #[test]
    fn from_server_response_empty() {
        let resp = json!({"success": true});
        let view = QueryResultView::from_server_response(&resp);
        assert!(view.columns.is_none());
        assert!(view.rows.is_none());
        assert!(view.rows_affected.is_none());
        assert!(!view.truncated);
    }

    #[test]
    fn from_server_response_empty_rows_array() {
        let resp = json!({
            "success": true,
            "result_data": {
                "rows": [],
                "truncated": false
            }
        });
        let view = QueryResultView::from_server_response(&resp);
        // Empty array → treated as no rows
        assert!(view.columns.is_none());
        assert!(view.rows.is_none());
    }

    // --- Serialization ---

    #[test]
    fn serializes_to_json() {
        let view = QueryResultView {
            columns: Some(vec!["a".into()]),
            rows: Some(vec![vec![serde_json::json!(1)]]),
            rows_affected: None,
            truncated: false,
        };
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["columns"], json!(["a"]));
        assert_eq!(json["rows"], json!([[1]]));
        assert_eq!(json["truncated"], false);
    }

    // --- Column order preservation (REF-3) ---

    #[test]
    fn from_server_response_preserves_column_order() {
        // Keys inserted in non-alphabetical order: name, id, email.
        // Without preserve_order, BTreeMap would sort to: email, id, name.
        let resp = json!({
            "success": true,
            "result_data": {
                "rows": [
                    {"name": "alice", "id": 1, "email": "a@x.com"},
                    {"name": "bob", "id": 2, "email": "b@x.com"}
                ],
                "truncated": false
            }
        });
        let view = QueryResultView::from_server_response(&resp);
        assert_eq!(
            view.columns,
            Some(vec!["name".into(), "id".into(), "email".into()]),
            "column order must match JSON object insertion order (SELECT clause order)"
        );
        // Row values must also follow column order
        assert_eq!(view.rows.as_ref().unwrap()[0][0], json!("alice"));
        assert_eq!(view.rows.as_ref().unwrap()[0][1], json!(1));
        assert_eq!(view.rows.as_ref().unwrap()[0][2], json!("a@x.com"));
    }

    #[test]
    fn from_server_response_preserves_many_columns_order() {
        // Use many columns to catch partial ordering issues
        let resp = json!({
            "success": true,
            "result_data": {
                "rows": [{"z": 1, "a": 2, "m": 3, "b": 4, "y": 5}],
                "truncated": false
            }
        });
        let view = QueryResultView::from_server_response(&resp);
        assert_eq!(
            view.columns,
            Some(vec![
                "z".into(),
                "a".into(),
                "m".into(),
                "b".into(),
                "y".into()
            ]),
            "column order must be preserved regardless of alphabetical sorting"
        );
    }
}
