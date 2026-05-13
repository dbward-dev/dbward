use dbward_api_types::agent::ResultBody;

/// Unified result from operation handlers.
pub(crate) enum ExecutionResult {
    Query { data: String, truncated: bool },
    Execute { rows_affected: u64 },
    Migrate { data: String },
}

impl From<ExecutionResult> for ResultBody {
    fn from(r: ExecutionResult) -> Self {
        match r {
            ExecutionResult::Query { data, truncated } => ResultBody {
                success: true,
                result_data: Some(data),
                error_message: None,
                rows_affected: None,
                truncated: Some(truncated),
                total_rows: None,
            },
            ExecutionResult::Execute { rows_affected } => ResultBody {
                success: true,
                result_data: Some(
                    serde_json::json!({ "rows_affected": rows_affected }).to_string(),
                ),
                error_message: None,
                rows_affected: Some(rows_affected),
                truncated: None,
                total_rows: None,
            },
            ExecutionResult::Migrate { data } => ResultBody {
                success: true,
                result_data: Some(data),
                error_message: None,
                rows_affected: None,
                truncated: None,
                total_rows: None,
            },
        }
    }
}

pub(crate) fn error_body(msg: String) -> ResultBody {
    ResultBody {
        success: false,
        result_data: None,
        error_message: Some(msg),
        rows_affected: None,
        truncated: None,
        total_rows: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_result_conversion() {
        let r = ExecutionResult::Query {
            data: r#"{"rows":[]}"#.into(),
            truncated: true,
        };
        let body: ResultBody = r.into();
        assert!(body.success);
        assert_eq!(body.truncated, Some(true));
        assert!(body.rows_affected.is_none());
    }

    #[test]
    fn execute_result_conversion() {
        let r = ExecutionResult::Execute { rows_affected: 42 };
        let body: ResultBody = r.into();
        assert!(body.success);
        assert_eq!(body.rows_affected, Some(42));
        assert!(body.truncated.is_none());
    }

    #[test]
    fn migrate_result_conversion() {
        let r = ExecutionResult::Migrate {
            data: r#"{"applied":["001"]}"#.into(),
        };
        let body: ResultBody = r.into();
        assert!(body.success);
        assert_eq!(body.result_data.unwrap(), r#"{"applied":["001"]}"#);
    }

    #[test]
    fn error_body_fields() {
        let body = error_body("boom".into());
        assert!(!body.success);
        assert_eq!(body.error_message.unwrap(), "boom");
        assert!(body.result_data.is_none());
    }
}
