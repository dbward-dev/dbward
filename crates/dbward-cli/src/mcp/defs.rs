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
            "name": "dbward_wait_request",
            "description": "Check request status or wait for completion. Returns result if executed, or current status otherwise. Set include_result=false for status-only check.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "request_id": {"type": "string", "description": "Request ID"},
                    "timeout": {"type": "integer", "description": "Max wait seconds for pending requests (default: 60)"},
                    "include_result": {"type": "boolean", "description": "If true (default), resume and return result. If false, return status only."}
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
            "name": "dbward_inspect_schema",
            "description": "Inspect database schema. Omit 'table' to list all tables. Provide 'table' (e.g. 'users' or 'public.users') to show column definitions. Server auto-selects environment.",
            "inputSchema": {"type": "object", "properties": {"table": {"type": "string", "description": "Table name to describe (e.g. 'users' or 'public.users'). Omit to list all tables."}, "database": {"type": "string", "description": "Target database name"}}}
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
        },
        {
            "uriTemplate": "dbward://schema/{database}",
            "name": "Database Schema",
            "description": "Table list with row counts (from agent-collected snapshot)",
            "mimeType": "application/json"
        },
        {
            "uriTemplate": "dbward://schema/{database}/{table}",
            "name": "Table Schema",
            "description": "Column, constraint, and index details for a specific table",
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
        return super::server::jsonrpc_error(id, -32602, "Missing required parameter: uri");
    }

    let content = match read_resource(uri, client).await {
        Ok(content) => content,
        Err(ResourceReadError::NotFound(message)) => {
            return super::server::jsonrpc_error(id, -32002, message);
        }
        Err(ResourceReadError::Forbidden(message)) => {
            return super::server::jsonrpc_error(id, -32002, message);
        }
        Err(ResourceReadError::Internal(message)) => {
            return super::server::jsonrpc_error(id, -32603, message);
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

pub(crate) enum ResourceReadError {
    NotFound(String),
    Forbidden(String),
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
        _ if uri.starts_with("dbward://schema/") => {
            let path = uri.strip_prefix("dbward://schema/").unwrap_or("");
            let (db, table) = match path.split_once('/') {
                Some((d, t)) => (d, Some(t)),
                None => (path, None),
            };
            if db.is_empty() {
                return Err(ResourceReadError::NotFound(format!(
                    "Resource not found: {uri}"
                )));
            }
            let api_path = if let Some(t) = table {
                let decoded = percent_decode(t);
                if decoded.is_empty() || decoded.contains(['&', '#', '=', '?', '\n', '\r', '\0']) {
                    return Err(ResourceReadError::NotFound(format!(
                        "Invalid table name: {decoded}"
                    )));
                }
                format!("/api/schemas/{db}?table={}", encode_query_value(&decoded))
            } else {
                format!("/api/schemas/{db}")
            };
            let resp = client.get_json(&api_path).await;
            match resp {
                Ok(v) => v,
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("403") || msg.contains("forbidden") {
                        return Err(ResourceReadError::Forbidden(format!(
                            "Access denied to schema for '{db}'"
                        )));
                    } else if msg.contains("404")
                        || msg.contains("not_found")
                        || msg.contains("not found")
                    {
                        return Err(ResourceReadError::NotFound(msg));
                    }
                    return Err(ResourceReadError::Internal(format!(
                        "Failed to read schema: {e}"
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
        return super::server::jsonrpc_error(id, -32602, "Missing required parameter: name");
    }

    let (description, messages) = match name {
        "review_migration" => {
            let file_path = match required_arg(args, "file_path") {
                Ok(value) => value,
                Err(message) => return super::server::jsonrpc_error(id, -32602, message),
            };
            let content = match read_migration_file(migrations_dir, file_path) {
                Ok(content) => content,
                Err(message) => return super::server::jsonrpc_error(id, -32602, message),
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
                Err(message) => return super::server::jsonrpc_error(id, -32602, message),
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
                Err(message) => return super::server::jsonrpc_error(id, -32602, message),
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
                Err(message) => return super::server::jsonrpc_error(id, -32602, message),
            };
            let content = match read_migration_file(migrations_dir, file_path) {
                Ok(content) => content,
                Err(message) => return super::server::jsonrpc_error(id, -32602, message),
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
                Err(message) => return super::server::jsonrpc_error(id, -32602, message),
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
            return super::server::jsonrpc_error(id, -32602, format!("Unknown prompt: {name}"));
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
#[allow(dead_code)] // Used in tests; inspect_schema now uses server API
pub(crate) struct TableReference {
    pub schema: Option<String>,
    pub table: String,
}

#[allow(dead_code)]
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

#[allow(dead_code)]
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

#[allow(dead_code)]
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
    const SQL_KEYWORDS: &[&str] = &[
        "select", "from", "where", "insert", "update", "delete", "set", "into", "values", "join",
        "inner", "left", "right", "outer", "and", "not", "null", "order", "group", "having",
        "limit", "offset", "create", "alter", "drop", "table", "index", "begin", "commit",
        "rollback",
    ];
    sql.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|term| term.len() >= 3)
        .map(|term| term.to_ascii_lowercase())
        .filter(|term| !SQL_KEYWORDS.contains(&term.as_str()))
        .collect()
}

pub(crate) fn matches_similarity_terms(candidate: &str, terms: &[String]) -> bool {
    if terms.is_empty() {
        return false;
    }
    let haystack = candidate.to_ascii_lowercase();
    let matched = terms
        .iter()
        .filter(|term| haystack.contains(term.as_str()))
        .count();
    // At least 50% of structural terms must match
    matched * 2 >= terms.len()
}

/// Normalized containment match for short queries where terms extraction yields nothing.
pub(crate) fn matches_normalized(candidate: &str, query: &str) -> bool {
    let normalize = |s: &str| {
        s.to_ascii_lowercase()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .trim_end_matches(';')
            .to_string()
    };
    let nq = normalize(query);
    if nq.is_empty() {
        return false;
    }
    normalize(candidate).contains(&nq)
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
                            let target = a["selector"].as_str()?;
                            let min = a["min"].as_u64().unwrap_or(1);
                            Some(if min > 1 {
                                format!("{target} x{min}")
                            } else {
                                target.to_string()
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

/// Encode a value for safe inclusion in a URL query string.
fn encode_query_value(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(char::from(HEX[(b >> 4) as usize]));
                out.push(char::from(HEX[(b & 0xf) as usize]));
            }
        }
    }
    out
}

const HEX: &[u8; 16] = b"0123456789ABCDEF";

/// Decode percent-encoded URI segment. Only handles ASCII; non-ASCII bytes are passed through.
fn percent_decode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = hex_val(bytes[i + 1]);
            let lo = hex_val(bytes[i + 2]);
            out.push((hi * 16 + lo) as char);
            i += 3;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_response_negotiates_client_version() {
        let params = json!({"protocolVersion": "2024-11-05", "capabilities": {}});
        let resp = crate::mcp::server::handle_initialize(&params, Some(json!(1)));
        assert_eq!(resp["result"]["protocolVersion"], "2024-11-05");
        assert_eq!(resp["result"]["serverInfo"]["name"], "dbward");
        assert_eq!(resp["result"]["capabilities"]["resources"], json!({}));
    }

    #[test]
    fn initialize_response_returns_latest_for_unknown_version() {
        let params = json!({"protocolVersion": "9999-01-01", "capabilities": {}});
        let resp = crate::mcp::server::handle_initialize(&params, Some(json!(1)));
        assert_eq!(resp["result"]["protocolVersion"], "2025-06-18");
    }

    #[test]
    fn initialize_response_supports_2025_03_26() {
        let params = json!({"protocolVersion": "2025-03-26", "capabilities": {}});
        let resp = crate::mcp::server::handle_initialize(&params, Some(json!(1)));
        assert_eq!(resp["result"]["protocolVersion"], "2025-03-26");
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
        assert!(names.contains(&"dbward_wait_request"));
        assert!(names.contains(&"dbward_inspect_schema"));
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
                    "approvers_required": [{"selector": "role:admin", "min": 1}]
                }]
            }),
        );
        assert!(text.contains("Request req_123 status: pending"));
        assert!(text.contains("Step 1 [all]: role:admin"));
    }

    #[test]
    fn tools_count_is_12() {
        let defs = tools_definitions();
        let tools = defs.as_array().unwrap();
        assert_eq!(tools.len(), 12);
    }

    #[test]
    fn old_tool_names_are_removed() {
        let defs = tools_definitions();
        let names: Vec<&str> = defs
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(!names.contains(&"dbward_check_request"));
        assert!(!names.contains(&"dbward_get_result"));
        assert!(!names.contains(&"dbward_list_schemas"));
        assert!(!names.contains(&"dbward_describe_table"));
        assert!(!names.contains(&"dbward_compare_schema"));
    }

    #[test]
    fn wait_request_has_include_result_param() {
        let defs = tools_definitions();
        let tool = defs
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == "dbward_wait_request")
            .unwrap();
        let props = &tool["inputSchema"]["properties"];
        assert!(props.get("include_result").is_some());
        assert!(props.get("timeout").is_some());
        assert!(props.get("request_id").is_some());
    }

    #[test]
    fn inspect_schema_table_is_optional() {
        let defs = tools_definitions();
        let tool = defs
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == "dbward_inspect_schema")
            .unwrap();
        let required = tool["inputSchema"].get("required");
        // table should NOT be required
        if let Some(r) = required {
            let reqs: Vec<&str> = r
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
            assert!(!reqs.contains(&"table"));
        }
    }
}
