use serde_json::{Value, json};
use std::path::{Path, PathBuf};

pub(crate) fn tools_definitions() -> Value {
    json!([
        {
            "name": "dbward_execute_query",
            "description": "Execute a SQL query. The query is submitted for approval and executed by an agent.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "sql": {"type": "string", "description": "SQL statement to execute"},
                    "database": {"type": "string", "description": "Target database name"},
                    "environment": {"type": "string", "description": "Environment (development/staging/production)"},
                    "reason": {"type": "string", "description": "Reason for execution (required by some workflows)"}
                },
                "required": ["sql"]
            }
        },
        {
            "name": "dbward_migrate_status",
            "description": "Show migration status (applied/pending)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "database": {"type": "string", "description": "Target database name"},
                    "environment": {"type": "string", "description": "Environment"}
                }
            }
        },
        {
            "name": "dbward_migrate_up",
            "description": "Apply pending database migrations",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "count": {"type": "integer", "description": "Max migrations to apply"},
                    "database": {"type": "string", "description": "Target database name"},
                    "environment": {"type": "string", "description": "Environment"}
                }
            }
        },
        {
            "name": "dbward_migrate_down",
            "description": "Rollback database migrations",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "count": {"type": "integer", "description": "Migrations to rollback", "default": 1},
                    "database": {"type": "string", "description": "Target database name"},
                    "environment": {"type": "string", "description": "Environment"}
                }
            }
        },
        {
            "name": "dbward_migrate_create",
            "description": "Create a new migration file (local only, no server needed)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Migration name (e.g. create_users)"}
                },
                "required": ["name"]
            }
        },
        {
            "name": "dbward_check_request",
            "description": "Check request status. Waits up to timeout seconds for status change.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "request_id": {"type": "string", "description": "Request ID to check"},
                    "timeout": {"type": "integer", "description": "Seconds to wait for status change (default 30, max 60)", "default": 30}
                },
                "required": ["request_id"]
            }
        },
        {
            "name": "dbward_get_result",
            "description": "Get the execution result of a completed request",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "request_id": {"type": "string", "description": "Request ID"}
                },
                "required": ["request_id"]
            }
        },
        {
            "name": "dbward_list_pending",
            "description": "List requests pending approval",
            "inputSchema": {"type": "object", "properties": {}}
        },
        {
            "name": "dbward_who_can_approve",
            "description": "Show who can approve a specific request (roles, groups, steps)",
            "inputSchema": {"type": "object", "properties": {"request_id": {"type": "string"}}, "required": ["request_id"]}
        },
        {
            "name": "dbward_find_similar_requests",
            "description": "Find past requests similar to the given SQL or operation",
            "inputSchema": {"type": "object", "properties": {"sql": {"type": "string"}, "operation": {"type": "string"}, "limit": {"type": "integer", "default": 5}}}
        },
        {
            "name": "dbward_preview_impact",
            "description": "Preview the impact of a SQL statement (EXPLAIN output)",
            "inputSchema": {"type": "object", "properties": {"sql": {"type": "string"}, "database": {"type": "string"}, "environment": {"type": "string"}}, "required": ["sql"]}
        },
        {
            "name": "dbward_explain_policy_failure",
            "description": "Explain why a request was blocked or requires approval",
            "inputSchema": {"type": "object", "properties": {"request_id": {"type": "string"}, "operation": {"type": "string"}, "environment": {"type": "string"}, "database": {"type": "string"}}}
        },
        {
            "name": "dbward_list_schemas",
            "description": "List tables and schemas in the target database",
            "inputSchema": {"type": "object", "properties": {"database": {"type": "string"}, "environment": {"type": "string"}}}
        },
        {
            "name": "dbward_describe_table",
            "description": "Show column definitions for a table",
            "inputSchema": {"type": "object", "properties": {"table": {"type": "string"}, "database": {"type": "string"}, "environment": {"type": "string"}}, "required": ["table"]}
        },
        {
            "name": "dbward_compare_schema",
            "description": "Show pending migration files that would change the schema",
            "inputSchema": {"type": "object", "properties": {"database": {"type": "string"}}}
        }
    ])
}

pub(crate) fn resources_definitions() -> Value {
    json!([
        {"uri": "dbward://migrations/status", "name": "Migration Status", "description": "Applied and pending migrations", "mimeType": "application/json"},
        {"uri": "dbward://requests/pending", "name": "Pending Requests", "description": "Requests awaiting approval", "mimeType": "application/json"},
        {"uri": "dbward://audit/recent", "name": "Recent Audit Events", "description": "Last 10 audit events", "mimeType": "application/json"}
    ])
}

pub(crate) fn resource_templates_definitions() -> Value {
    json!([
        {
            "uriTemplate": "dbward://requests/{request_id}",
            "name": "Request Details",
            "description": "Details for a specific request",
            "mimeType": "application/json"
        }
    ])
}

pub(crate) async fn handle_resources_read(
    id: Option<Value>,
    params: &Value,
    client: &crate::server_client::ServerClient,
    _db_name: &str,
) -> Value {
    let uri = params["uri"].as_str().unwrap_or("");
    if uri.is_empty() {
        return crate::mcp::jsonrpc_error(id, -32602, "Missing required parameter: uri");
    }

    let content = match read_resource(uri, client).await {
        Ok(content) => content,
        Err(ResourceReadError::NotFound(message)) => {
            return crate::mcp::jsonrpc_error(id, -32002, message);
        }
        Err(ResourceReadError::Internal(message)) => {
            return crate::mcp::jsonrpc_error(id, -32603, message);
        }
    };

    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "contents": [{"uri": uri, "mimeType": "application/json", "text": content}]
        }
    })
}

enum ResourceReadError {
    NotFound(String),
    Internal(String),
}

pub(crate) async fn read_resource(
    uri: &str,
    client: &crate::server_client::ServerClient,
) -> Result<String, ResourceReadError> {
    let value = match uri {
        "dbward://migrations/status" => client
            .get_json("/api/requests?operation=migrate_status&limit=1")
            .await
            .map_err(|e| {
                ResourceReadError::Internal(format!("Failed to read resource {uri}: {e}"))
            })?,
        "dbward://requests/pending" => client
            .get_json("/api/requests?status=pending&limit=20")
            .await
            .map_err(|e| {
                ResourceReadError::Internal(format!("Failed to read resource {uri}: {e}"))
            })?,
        "dbward://audit/recent" => client
            .get_json("/api/audit/events?limit=10")
            .await
            .map_err(|e| {
                ResourceReadError::Internal(format!("Failed to read resource {uri}: {e}"))
            })?,
        _ if uri.starts_with("dbward://requests/") => {
            let req_id = uri.strip_prefix("dbward://requests/").unwrap_or("");
            let (req_id, suffix) = req_id.split_once('/').unwrap_or((req_id, ""));
            if req_id.is_empty() {
                return Err(ResourceReadError::NotFound(format!(
                    "Resource not found: {uri}"
                )));
            }
            match suffix {
                "" => client.get_request(req_id).await.map_err(|e| {
                    ResourceReadError::Internal(format!("Failed to read resource {uri}: {e}"))
                })?,
                _ => {
                    return Err(ResourceReadError::NotFound(format!(
                        "Resource not found: {uri}"
                    )));
                }
            }
        }
        _ => {
            return Err(ResourceReadError::NotFound(format!(
                "Resource not found: {uri}"
            )));
        }
    };

    Ok(value.to_string())
}

pub(crate) fn prompts_definitions() -> Value {
    json!([
        {"name": "review_migration", "description": "Review a migration SQL file for safety issues", "arguments": [{"name": "file_path", "description": "Path to migration file", "required": true}]},
        {"name": "explain_request", "description": "Explain what a request will do and its impact", "arguments": [{"name": "request_id", "description": "Request ID", "required": true}]},
        {"name": "draft_migration", "description": "Generate migration SQL from a description", "arguments": [{"name": "description", "description": "What the migration should do", "required": true}]},
        {"name": "draft_rollback", "description": "Generate rollback SQL for a migration", "arguments": [{"name": "migration_file", "description": "Path to migration file to rollback", "required": true}]},
        {"name": "summarize_audit_trail", "description": "Summarize recent audit events", "arguments": [{"name": "since", "description": "Start date (ISO 8601)", "required": false}, {"name": "database", "description": "Filter by database", "required": false}]},
        {"name": "prepare_approval_comment", "description": "Draft an approval comment for a request", "arguments": [{"name": "request_id", "description": "Request ID to review", "required": true}]}
    ])
}

pub(crate) fn handle_prompts_get(
    id: Option<Value>,
    params: &Value,
    migrations_dir: &std::path::Path,
) -> Value {
    let name = params["name"].as_str().unwrap_or("");
    let args = &params["arguments"];

    if name.is_empty() {
        return crate::mcp::jsonrpc_error(id, -32602, "Missing required parameter: name");
    }

    let (description, messages) = match name {
        "review_migration" => {
            let file_path = match required_arg(args, "file_path") {
                Ok(value) => value,
                Err(message) => return crate::mcp::jsonrpc_error(id, -32602, message),
            };
            let content = match read_migration_file(migrations_dir, file_path) {
                Ok(content) => content,
                Err(message) => return crate::mcp::jsonrpc_error(id, -32602, message),
            };
            (
                "Review a migration SQL file for safety issues",
                vec![
                    json!({"role": "user", "content": {"type": "text", "text": format!(
                        "Review this migration SQL for safety issues (locking, data loss, backwards compatibility):\n\n```sql\n{content}\n```\n\nCheck for:\n1. Long-running locks (ALTER TABLE on large tables)\n2. Data loss (DROP COLUMN without backup)\n3. Backwards incompatibility (NOT NULL without default)\n4. Missing indexes for new foreign keys\n5. Transaction safety"
                    )}}),
                ],
            )
        }
        "explain_request" => {
            let request_id = match required_arg(args, "request_id") {
                Ok(value) => value,
                Err(message) => return crate::mcp::jsonrpc_error(id, -32602, message),
            };
            (
                "Explain what a request will do and its impact",
                vec![
                    json!({"role": "user", "content": {"type": "text", "text": format!(
                        "Explain what request {request_id} will do. Read the request details from dbward://requests/{request_id} and describe:\n1. What SQL will be executed\n2. Which database and environment\n3. Potential impact\n4. Who needs to approve it"
                    )}}),
                ],
            )
        }
        "draft_migration" => {
            let description = match required_arg(args, "description") {
                Ok(value) => value,
                Err(message) => return crate::mcp::jsonrpc_error(id, -32602, message),
            };
            (
                "Generate migration SQL from a description",
                vec![
                    json!({"role": "user", "content": {"type": "text", "text": format!(
                        "Generate a migration SQL file for the following change:\n\n{description}\n\nProvide both up and down sections in dbmate format:\n```sql\n-- migrate:up\n<SQL>\n\n-- migrate:down\n<SQL>\n```\n\nConsider: backwards compatibility, index needs, NOT NULL defaults, large table locking."
                    )}}),
                ],
            )
        }
        "draft_rollback" => {
            let file_path = match required_arg(args, "migration_file") {
                Ok(value) => value,
                Err(message) => return crate::mcp::jsonrpc_error(id, -32602, message),
            };
            let content = match read_migration_file(migrations_dir, file_path) {
                Ok(content) => content,
                Err(message) => return crate::mcp::jsonrpc_error(id, -32602, message),
            };
            (
                "Generate rollback SQL for a migration",
                vec![
                    json!({"role": "user", "content": {"type": "text", "text": format!(
                        "Generate a safe rollback plan for this migration:\n\n```sql\n{content}\n```\n\nConsider data preservation and application compatibility."
                    )}}),
                ],
            )
        }
        "summarize_audit_trail" => (
            "Summarize recent audit events",
            vec![json!({"role": "user", "content": {"type": "text", "text":
                "Summarize the recent audit events from dbward://audit/recent. Group by actor and operation type. Highlight any failures or unusual patterns."
            }})],
        ),
        "prepare_approval_comment" => {
            let request_id = match required_arg(args, "request_id") {
                Ok(value) => value,
                Err(message) => return crate::mcp::jsonrpc_error(id, -32602, message),
            };
            (
                "Draft an approval comment for a request",
                vec![
                    json!({"role": "user", "content": {"type": "text", "text": format!(
                        "Review request {request_id} (read from dbward://requests/{request_id}) and draft an approval comment. Include:\n1. What was reviewed\n2. Risk assessment (low/medium/high)\n3. Any conditions or follow-up actions"
                    )}}),
                ],
            )
        }
        _ => {
            return crate::mcp::jsonrpc_error(id, -32602, format!("Unknown prompt: {name}"));
        }
    };

    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "description": description,
            "messages": messages
        }
    })
}

pub(crate) fn required_arg<'a>(args: &'a Value, name: &str) -> Result<&'a str, String> {
    let value = args[name]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    value.ok_or_else(|| format!("Missing required argument: {name}"))
}

#[derive(Debug)]
pub(crate) struct TableReference {
    pub schema: Option<String>,
    pub table: String,
}

pub(crate) fn parse_table_reference(input: &str) -> Result<TableReference, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("Missing required argument: table".to_string());
    }
    let parts: Vec<&str> = trimmed.split('.').collect();
    match parts.as_slice() {
        [table] => Ok(TableReference {
            schema: None,
            table: validate_sql_identifier(table, "table")?.to_string(),
        }),
        [schema, table] => Ok(TableReference {
            schema: Some(validate_sql_identifier(schema, "schema")?.to_string()),
            table: validate_sql_identifier(table, "table")?.to_string(),
        }),
        _ => Err("table must be in the form 'table' or 'schema.table'".to_string()),
    }
}

pub(crate) fn validate_sql_identifier<'a>(value: &'a str, kind: &str) -> Result<&'a str, String> {
    if value.is_empty() {
        return Err(format!("{kind} must not be empty"));
    }
    let mut chars = value.chars();
    let first = chars.next().unwrap();
    if !(first.is_ascii_alphabetic() || first == '_') {
        return Err(format!("{kind} must start with a letter or underscore"));
    }
    if chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        Ok(value)
    } else {
        Err(format!(
            "{kind} may only contain ASCII letters, digits, and underscores"
        ))
    }
}

pub(crate) fn sql_string_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

pub(crate) fn normalize_preview_sql(sql: &str) -> Result<String, String> {
    let trimmed = sql.trim();
    if trimmed.is_empty() {
        return Err("Missing required argument: sql".to_string());
    }
    let statement = trimmed.strip_suffix(';').unwrap_or(trimmed).trim_end();
    if statement.is_empty() {
        return Err("sql must not be empty".to_string());
    }
    if statement.contains(';') {
        return Err("preview_impact only accepts a single SQL statement".to_string());
    }
    Ok(statement.to_string())
}

pub(crate) fn normalized_similarity_terms(sql: &str) -> Vec<String> {
    sql.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|term| term.len() >= 3)
        .map(|term| term.to_ascii_lowercase())
        .collect()
}

pub(crate) fn matches_similarity_terms(candidate: &str, terms: &[String]) -> bool {
    if terms.is_empty() {
        return true;
    }
    let haystack = candidate.to_ascii_lowercase();
    terms.iter().all(|term| haystack.contains(term))
}

pub(crate) fn format_approval_progress(
    request_id: &str,
    status: &Value,
    progress: &Value,
) -> String {
    let current = progress["current_step"].as_u64().unwrap_or(0);
    let total = progress["total_steps"].as_u64().unwrap_or(0);
    let mut out = format!(
        "Request {request_id} status: {}\nApproval path ({current}/{total} complete):\n",
        status.as_str().unwrap_or("unknown")
    );
    if let Some(steps) = progress["steps"].as_array() {
        for step in steps {
            let idx = step["index"].as_u64().unwrap_or(0) + 1;
            let mode = step["mode"].as_str().unwrap_or("all");
            let satisfied = step["satisfied"].as_bool().unwrap_or(false);
            let marker = if satisfied { "[ok]" } else { "[wait]" };
            let desc = step["approvers_required"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|a| {
                            let target = a["group"]
                                .as_str()
                                .map(|g| format!("group:{g}"))
                                .or_else(|| a["role"].as_str().map(|r| format!("role:{r}")))?;
                            let min = a["min"].as_u64().unwrap_or(1);
                            Some(if min > 1 {
                                format!("{target} x{min}")
                            } else {
                                target
                            })
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let joiner = if mode == "any" { " | " } else { " + " };
            let summary = if desc.is_empty() {
                "(no approvers configured)".to_string()
            } else {
                desc.join(joiner)
            };
            out.push_str(&format!("  {marker} Step {idx} [{mode}]: {summary}\n"));
        }
    }
    out
}

pub(crate) fn read_migration_file(
    migrations_dir: &Path,
    requested_path: &str,
) -> Result<String, String> {
    let full_path = resolve_migration_path(migrations_dir, requested_path)?;
    std::fs::read_to_string(&full_path)
        .map_err(|_| format!("Could not read migration file: {}", full_path.display()))
}

pub(crate) fn resolve_migration_path(
    migrations_dir: &Path,
    requested_path: &str,
) -> Result<PathBuf, String> {
    let relative = Path::new(requested_path);
    if relative.is_absolute() {
        return Err("Absolute paths are not allowed".to_string());
    }
    if relative.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir
                | std::path::Component::RootDir
                | std::path::Component::Prefix(_)
        )
    }) {
        return Err("Migration file path escapes the migrations directory".to_string());
    }

    let base = migrations_dir.canonicalize().map_err(|_| {
        format!(
            "Could not resolve migrations directory: {}",
            migrations_dir.display()
        )
    })?;
    let candidate = base.join(relative);
    let resolved = candidate
        .canonicalize()
        .map_err(|_| format!("Could not resolve migration file: {}", candidate.display()))?;

    if !resolved.starts_with(&base) {
        return Err("Migration file path escapes the migrations directory".to_string());
    }

    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_response_has_protocol_version() {
        let resp = crate::mcp::handle_initialize(Some(json!(1)));
        assert_eq!(resp["result"]["protocolVersion"], "2025-11-05");
        assert_eq!(resp["result"]["serverInfo"]["name"], "dbward");
        assert_eq!(resp["result"]["capabilities"]["resources"], json!({}));
    }

    #[test]
    fn tools_definitions_include_all_tools() {
        let defs = tools_definitions();
        let names: Vec<&str> = defs
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"dbward_execute_query"));
        assert!(names.contains(&"dbward_migrate_create"));
        assert!(names.contains(&"dbward_check_request"));
        assert!(names.contains(&"dbward_get_result"));
    }

    #[test]
    fn prompts_get_rejects_missing_required_argument() {
        let resp = handle_prompts_get(
            Some(json!(1)),
            &json!({"name": "draft_migration", "arguments": {}}),
            Path::new("/tmp"),
        );

        assert_eq!(resp["error"]["code"], -32602);
        assert_eq!(
            resp["error"]["message"],
            "Missing required argument: description"
        );
    }

    #[test]
    fn resolve_migration_path_rejects_path_traversal() {
        let base = std::env::temp_dir().join(format!("dbward-mcp-test-{}", std::process::id()));
        std::fs::create_dir_all(base.join("migrations")).unwrap();

        let err = resolve_migration_path(&base.join("migrations"), "../secret.sql").unwrap_err();
        assert_eq!(err, "Migration file path escapes the migrations directory");

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn parse_table_reference_rejects_invalid_identifier() {
        let err = parse_table_reference("users;DROP TABLE users").unwrap_err();
        assert_eq!(
            err,
            "table may only contain ASCII letters, digits, and underscores"
        );
    }

    #[test]
    fn parse_table_reference_accepts_schema_qualified_name() {
        let parsed = parse_table_reference("public.users").unwrap();
        assert_eq!(parsed.schema.as_deref(), Some("public"));
        assert_eq!(parsed.table, "users");
    }

    #[test]
    fn normalize_preview_sql_rejects_multi_statement_input() {
        let err = normalize_preview_sql("SELECT 1; DROP TABLE users").unwrap_err();
        assert_eq!(err, "preview_impact only accepts a single SQL statement");
    }

    #[test]
    fn normalize_preview_sql_trims_single_trailing_semicolon() {
        let sql = normalize_preview_sql(" SELECT 1; ").unwrap();
        assert_eq!(sql, "SELECT 1");
    }

    #[test]
    fn format_approval_progress_uses_summary_not_raw_snapshot() {
        let text = format_approval_progress(
            "req_123",
            &json!("pending"),
            &json!({
                "current_step": 0,
                "total_steps": 1,
                "steps": [{
                    "index": 0,
                    "mode": "all",
                    "satisfied": false,
                    "approvers_required": [{"role": "admin", "min": 1}]
                }]
            }),
        );
        assert!(text.contains("Request req_123 status: pending"));
        assert!(text.contains("Step 1 [all]: role:admin"));
    }
}
