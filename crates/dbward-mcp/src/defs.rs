use serde_json::{Value, json};

/// Remote-capable tool definitions (9 tools).
pub fn tools_definitions() -> Value {
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
                    "reason": {"type": "string", "description": "Reason for execution (required by some workflows)", "maxLength": 1024},
                    "_idempotency_key": {"type": "string", "description": "Client-supplied UUID for replay protection (optional)"}
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
                    "environment": {"type": "string", "description": "Environment"},
                    "reason": {"type": "string", "description": "Reason for execution (required by some workflows)", "maxLength": 1024}
                }
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

/// Remote-capable resource definitions.
pub fn resources_definitions() -> Value {
    json!([
        {"uri": "dbward://migrations/status", "name": "Migration Status", "description": "Applied and pending migrations", "mimeType": "application/json"},
        {"uri": "dbward://requests/pending", "name": "Pending Requests", "description": "Requests awaiting approval", "mimeType": "application/json"},
        {"uri": "dbward://audit/recent", "name": "Recent Audit Events", "description": "Last 10 audit events", "mimeType": "application/json"}
    ])
}

/// Remote-capable resource template definitions.
pub fn resource_templates_definitions() -> Value {
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

/// Remote-capable prompt definitions (4 prompts).
pub fn prompts_definitions() -> Value {
    json!([
        {"name": "explain_request", "description": "Explain what a request will do and its impact", "arguments": [{"name": "request_id", "description": "Request ID", "required": true}]},
        {"name": "draft_migration", "description": "Generate migration SQL from a description", "arguments": [{"name": "description", "description": "What the migration should do", "required": true}]},
        {"name": "summarize_audit_trail", "description": "Summarize recent audit events", "arguments": [{"name": "since", "description": "Start date (ISO 8601)", "required": false}, {"name": "database", "description": "Filter by database", "required": false}]},
        {"name": "prepare_approval_comment", "description": "Draft an approval comment for a request", "arguments": [{"name": "request_id", "description": "Request ID to review", "required": true}]}
    ])
}
