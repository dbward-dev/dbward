use serde::Serialize;

/// Query result in a transport-neutral representation. Shared by CLI and MCP.
#[derive(Serialize, Clone, Debug)]
pub struct QueryResultView {
    pub columns: Option<Vec<String>>,
    pub rows: Option<Vec<Vec<serde_json::Value>>>,
    pub rows_affected: Option<u64>,
    pub truncated: bool,
}

impl QueryResultView {
    /// Build a view model from the server JSON response.
    pub fn from_server_response(resp: &serde_json::Value) -> Self {
        let result = if !resp["result"].is_null() {
            &resp["result"]
        } else if !resp["result_data"].is_null() {
            &resp["result_data"]
        } else {
            &serde_json::Value::Null
        };

        let columns = result["columns"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect());
        let rows = result["rows"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_array().cloned()).collect());
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn from_server_response_with_result_field() {
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
    fn from_server_response_with_result_data_field() {
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

    #[test]
    fn from_server_response_rows_affected() {
        let resp = json!({
            "success": true,
            "rows_affected": 5,
            "result": {}
        });
        let view = QueryResultView::from_server_response(&resp);
        assert_eq!(view.rows_affected, Some(5));
        assert!(view.columns.is_none());
        assert!(view.rows.is_none());
    }

    #[test]
    fn from_server_response_truncated() {
        let resp = json!({
            "success": true,
            "truncated": true,
            "result": {
                "columns": ["x"],
                "rows": [[1]],
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
                "columns": ["x"],
                "rows": [[1]],
                "truncated": true,
            }
        });
        let view = QueryResultView::from_server_response(&resp);
        assert!(view.truncated);
    }

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
}
