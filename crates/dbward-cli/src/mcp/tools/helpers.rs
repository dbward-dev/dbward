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
    Ok(serde_json::to_string_pretty(&view).unwrap_or_else(|_| "Executed successfully.".into()))
}
