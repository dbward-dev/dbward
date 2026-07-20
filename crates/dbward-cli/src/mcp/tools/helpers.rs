use serde_json::Value;

/// Rewrite known server validation errors to actionable MCP messages.
pub(super) fn rewrite_error(msg: &str) -> String {
    if msg.contains("reason is required") {
        "This workflow requires a reason. Pass the 'reason' parameter.".into()
    } else if msg.contains("not registered") {
        format!("{msg} Use dbward_inspect_schema to see available databases.")
    } else {
        msg.to_string()
    }
}

pub(super) fn format_result(resp: &Value) -> Result<String, String> {
    if resp["success"].as_bool() == Some(false) {
        let err = resp["error_message"]
            .as_str()
            .or_else(|| resp["error"].as_str())
            .unwrap_or("unknown error");
        return Err(format!("Execution failed: {err}"));
    }

    let view = crate::output::views::QueryResultView::from_server_response(resp);

    // Query results with actual rows -> use structured view
    if view.rows.as_ref().is_some_and(|r| !r.is_empty()) || view.rows_affected.is_some() {
        return Ok(
            serde_json::to_string_pretty(&view).unwrap_or_else(|_| "Executed successfully.".into())
        );
    }

    // Non-tabular results (migrate, etc.) -> pretty-print raw data
    let result = if !resp["result"].is_null() {
        &resp["result"]
    } else if !resp["result_data"].is_null() {
        &resp["result_data"]
    } else {
        return Ok("Executed successfully.".to_string());
    };

    if let Some(text) = result.as_str() {
        Ok(text.to_string())
    } else {
        Ok(serde_json::to_string_pretty(result).unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn format_result_error_response() {
        let resp = json!({"success": false, "error_message": "table not found"});
        let err = format_result(&resp).unwrap_err();
        assert!(err.contains("table not found"));
    }

    #[test]
    fn format_result_error_fallback_field() {
        let resp = json!({"success": false, "error": "connection refused"});
        let err = format_result(&resp).unwrap_err();
        assert!(err.contains("connection refused"));
    }

    #[test]
    fn format_result_query_with_object_rows() {
        let resp = json!({
            "success": true,
            "result_data": {
                "rows": [{"id": 1, "name": "alice"}],
                "truncated": false
            }
        });
        let out = format_result(&resp).unwrap();
        // Should produce structured JSON with columns/rows
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert!(parsed["columns"].is_array());
        assert!(parsed["rows"].is_array());
    }

    #[test]
    fn format_result_dml_rows_affected() {
        let resp = json!({
            "success": true,
            "rows_affected": 3,
            "result_data": {}
        });
        let out = format_result(&resp).unwrap();
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["rows_affected"], 3);
    }

    #[test]
    fn format_result_migrate_applied() {
        let resp = json!({
            "success": true,
            "result_data": {
                "applied": ["20240101_create_users.sql"]
            }
        });
        let out = format_result(&resp).unwrap();
        // Non-tabular: pretty-printed raw data
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["applied"], json!(["20240101_create_users.sql"]));
    }

    #[test]
    fn format_result_migrate_status() {
        let resp = json!({
            "success": true,
            "result_data": {
                "applied_versions": ["20240101120000"]
            }
        });
        let out = format_result(&resp).unwrap();
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert!(parsed["applied_versions"].is_array());
    }

    #[test]
    fn format_result_string_result() {
        let resp = json!({
            "success": true,
            "result_data": "Migration applied successfully"
        });
        let out = format_result(&resp).unwrap();
        assert_eq!(out, "Migration applied successfully");
    }

    #[test]
    fn format_result_no_result_field() {
        let resp = json!({"success": true});
        let out = format_result(&resp).unwrap();
        assert_eq!(out, "Executed successfully.");
    }

    #[test]
    fn format_result_empty_rows() {
        let resp = json!({
            "success": true,
            "result_data": {
                "rows": [],
                "truncated": false
            }
        });
        let out = format_result(&resp).unwrap();
        // Empty rows → falls through to pretty-print
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["rows"], json!([]));
    }
}
