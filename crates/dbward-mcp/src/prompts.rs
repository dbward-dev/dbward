use serde_json::{Value, json};

/// Handle prompts/get for remote-capable prompts.
/// Returns (description, messages) or error message.
pub fn get_prompt(name: &str, args: &Value) -> Result<(String, Vec<Value>), String> {
    match name {
        "explain_request" => {
            let request_id = required_arg(args, "request_id")?;
            Ok((
                "Explain what a request will do and its impact".into(),
                vec![
                    json!({"role": "user", "content": {"type": "text", "text": format!(
                        "Explain what request {request_id} will do. Read the request details from dbward://requests/{request_id} and describe:\n1. What SQL will be executed\n2. Which database and environment\n3. Potential impact\n4. Who needs to approve it"
                    )}}),
                ],
            ))
        }
        "draft_migration" => {
            let description = required_arg(args, "description")?;
            Ok((
                "Generate migration SQL from a description".into(),
                vec![
                    json!({"role": "user", "content": {"type": "text", "text": format!(
                        "Generate a migration SQL file for the following change:\n\n{description}\n\nProvide both up and down sections in dbmate format:\n```sql\n-- migrate:up\n<SQL>\n\n-- migrate:down\n<SQL>\n```\n\nConsider: backwards compatibility, index needs, NOT NULL defaults, large table locking."
                    )}}),
                ],
            ))
        }
        "summarize_audit_trail" => Ok((
            "Summarize recent audit events".into(),
            vec![json!({"role": "user", "content": {"type": "text", "text":
                "Summarize the recent audit events from dbward://audit/recent. Group by actor and operation type. Highlight any failures or unusual patterns."
            }})],
        )),
        "prepare_approval_comment" => {
            let request_id = required_arg(args, "request_id")?;
            Ok((
                "Draft an approval comment for a request".into(),
                vec![
                    json!({"role": "user", "content": {"type": "text", "text": format!(
                        "Review request {request_id} (read from dbward://requests/{request_id}) and draft an approval comment. Include:\n1. What was reviewed\n2. Risk assessment (low/medium/high)\n3. Any conditions or follow-up actions"
                    )}}),
                ],
            ))
        }
        _ => Err(format!("Unknown prompt: {name}")),
    }
}

fn required_arg<'a>(args: &'a Value, name: &str) -> Result<&'a str, String> {
    args[name]
        .as_str()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| format!("Missing required argument: {name}"))
}
