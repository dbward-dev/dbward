use std::io::{self, BufRead, Write};

use serde_json::{Value, json};

use dbward_core::{Config, Engine, Role};
use dbward_migrate::Migrator;

pub async fn run_stdio(config: Config) -> Result<(), dbward_core::Error> {
    let mut engine = Engine::new(config.clone()).await?;
    // MCP uses stdout for JSON-RPC, so audit log goes to stderr
    engine.set_audit_logger(dbward_core::AuditLogger::stderr());
    let migrator = Migrator::new(engine.pool().clone(), config.migrations_dir.clone());

    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = line.map_err(dbward_core::Error::Io)?;
        if line.trim().is_empty() {
            continue;
        }

        let request: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let err_resp = json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": {"code": -32700, "message": format!("Parse error: {e}")}
                });
                writeln!(stdout, "{err_resp}").map_err(dbward_core::Error::Io)?;
                stdout.flush().map_err(dbward_core::Error::Io)?;
                continue;
            }
        };

        let id = request.get("id").cloned();
        let method = request["method"].as_str().unwrap_or("");

        // Notifications have no id and expect no response
        if method == "notifications/initialized" {
            continue;
        }

        let response = match method {
            "initialize" => handle_initialize(id.clone()),
            "tools/list" => handle_tools_list(id.clone()),
            "tools/call" => {
                handle_tools_call(id.clone(), &request["params"], &mut engine, &migrator, &config)
                    .await
            }
            _ => json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32601, "message": format!("Method not found: {method}")}
            }),
        };

        writeln!(stdout, "{response}").map_err(dbward_core::Error::Io)?;
        stdout.flush().map_err(dbward_core::Error::Io)?;
    }

    Ok(())
}

fn handle_initialize(id: Option<Value>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "protocolVersion": "2024-11-05",
            "serverInfo": {"name": "dbward", "version": env!("CARGO_PKG_VERSION")},
            "capabilities": {"tools": {}}
        }
    })
}

fn handle_tools_list(id: Option<Value>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {"tools": tools_definitions()}
    })
}

async fn handle_tools_call(
    id: Option<Value>,
    params: &Value,
    engine: &mut Engine,
    migrator: &Migrator,
    config: &Config,
) -> Value {
    let tool_name = params["name"].as_str().unwrap_or("");
    let args = &params["arguments"];

    let result = match tool_name {
        "dbward_migrate_status" => call_migrate_status(migrator).await,
        "dbward_migrate_up" => {
            let count = args["count"].as_u64().map(|n| n as usize);
            call_migrate_up(migrator, count).await
        }
        "dbward_migrate_down" => {
            let count = args["count"].as_u64().map(|n| n as usize);
            call_migrate_down(migrator, count).await
        }
        "dbward_migrate_create" => {
            let name = args["name"].as_str().unwrap_or("unnamed");
            call_migrate_create(migrator, name)
        }
        "dbward_execute_query" => {
            let sql = args["sql"].as_str().unwrap_or("");
            call_execute_query(engine, sql, config.role).await
        }
        "dbward_audit_search" => {
            Ok("Audit search is only available in server mode.".to_string())
        }
        _ => Err(format!("Unknown tool: {tool_name}")),
    };

    match result {
        Ok(text) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "content": [{"type": "text", "text": text}]
            }
        }),
        Err(e) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "content": [{"type": "text", "text": format!("Error: {e}")}],
                "isError": true
            }
        }),
    }
}

async fn call_migrate_status(migrator: &Migrator) -> Result<String, String> {
    let statuses = migrator.status().await.map_err(|e| e.to_string())?;
    if statuses.is_empty() {
        return Ok("No migration files found.".to_string());
    }
    let lines: Vec<String> = statuses
        .iter()
        .map(|s| {
            let mark = if s.applied { "[x]" } else { "[ ]" };
            format!("{mark} {}_{}", s.version, s.name)
        })
        .collect();
    Ok(lines.join("\n"))
}

async fn call_migrate_up(migrator: &Migrator, count: Option<usize>) -> Result<String, String> {
    let result = migrator.up(count).await.map_err(|e| e.to_string())?;
    if result.applied.is_empty() {
        Ok("No pending migrations.".to_string())
    } else {
        Ok(format!(
            "Applied {} migration(s):\n{}",
            result.applied.len(),
            result.applied.join("\n")
        ))
    }
}

async fn call_migrate_down(migrator: &Migrator, count: Option<usize>) -> Result<String, String> {
    let result = migrator.down(count).await.map_err(|e| e.to_string())?;
    if result.rolled_back.is_empty() {
        Ok("Nothing to rollback.".to_string())
    } else {
        Ok(format!(
            "Rolled back:\n{}",
            result.rolled_back.join("\n")
        ))
    }
}

fn call_migrate_create(migrator: &Migrator, name: &str) -> Result<String, String> {
    let path = migrator.create(name).map_err(|e| e.to_string())?;
    Ok(format!("Created: {}", path.display()))
}

async fn call_execute_query(
    engine: &mut Engine,
    sql: &str,
    role: Role,
) -> Result<String, String> {
    if sql.is_empty() {
        return Err("sql parameter is required".to_string());
    }
    let result = engine
        .execute_query("mcp_user", role, sql)
        .await
        .map_err(|e| e.to_string())?;

    if result.rows.is_empty() {
        Ok(format!("Rows affected: {}", result.rows_affected))
    } else {
        serde_json::to_string_pretty(&result.rows).map_err(|e| e.to_string())
    }
}

fn tools_definitions() -> Value {
    json!([
        {
            "name": "dbward_migrate_status",
            "description": "Show migration status (applied/pending)",
            "inputSchema": {"type": "object", "properties": {}}
        },
        {
            "name": "dbward_migrate_up",
            "description": "Apply pending database migrations",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "count": {"type": "integer", "description": "Max migrations to apply"}
                }
            }
        },
        {
            "name": "dbward_migrate_down",
            "description": "Rollback database migrations",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "count": {"type": "integer", "description": "Migrations to rollback", "default": 1}
                }
            }
        },
        {
            "name": "dbward_migrate_create",
            "description": "Create a new migration file",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Migration name (e.g. create_users)"}
                },
                "required": ["name"]
            }
        },
        {
            "name": "dbward_execute_query",
            "description": "Execute a SQL query (SELECT/INSERT/UPDATE/DELETE). DDL is rejected.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "sql": {"type": "string", "description": "SQL statement to execute"}
                },
                "required": ["sql"]
            }
        },
        {
            "name": "dbward_audit_search",
            "description": "Search audit log (server mode only)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "user": {"type": "string", "description": "Filter by user"},
                    "operation": {"type": "string", "description": "Filter by operation"},
                    "limit": {"type": "integer", "description": "Max results", "default": 20}
                }
            }
        }
    ])
}
