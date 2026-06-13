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
    let result = &resp["result"];
    if !result.is_null() {
        if let Some(text) = result.as_str() {
            return Ok(text.to_string());
        }
        return Ok(serde_json::to_string_pretty(result).unwrap_or_default());
    }
    // Stream/stored format: result_data is a JSON value
    let rd = &resp["result_data"];
    if !rd.is_null() {
        if let Some(text) = rd.as_str() {
            return Ok(text.to_string());
        }
        return Ok(serde_json::to_string_pretty(rd).unwrap_or_default());
    }
    if let Some(affected) = resp["rows_affected"].as_u64() {
        return Ok(format!("Rows affected: {affected}"));
    }
    Ok("Executed successfully.".to_string())
}
