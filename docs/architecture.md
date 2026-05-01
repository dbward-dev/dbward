# Architecture

## Crate Dependency Graph

```
dbward-cli (binary)
├── dbward-core      (types, RBAC, audit, config, query execution)
└── dbward-migrate   (migration file I/O + execution)
      └── dbward-core

dbward-server (Pro, not in MVP)
├── dbward-core
└── dbward-migrate
```

## DB Connection Ownership

`dbward-core` owns the PostgreSQL connection pool (`sqlx::PgPool`).
`dbward-migrate` receives a pool reference from the caller.

```
dbward-core::DbConnection
  ├── connect(config) -> PgPool
  ├── execute_query(pool, sql, role) -> QueryResult
  └── (pool is passed to dbward-migrate)

dbward-migrate::Migrator
  └── run(pool, direction, migrations_dir) -> MigrationResult
```

## Data Flows

### 1. CLI: `dbward migrate up`

```
User runs: dbward migrate up

dbward-cli
  │
  ├─ load_config()           → Config from dbward.toml + env vars
  ├─ check_permission()      → Role vs Operation::MigrateUp
  ├─ DbConnection::connect() → PgPool
  ├─ Migrator::up(pool)      → reads migration files
  │   ├─ query schema_migrations table
  │   ├─ determine pending migrations
  │   └─ for each pending:
  │       ├─ BEGIN
  │       ├─ execute SQL
  │       ├─ INSERT INTO schema_migrations
  │       └─ COMMIT
  ├─ AuditLogger::log()      → JSON line to stdout
  └─ print result
```

### 2. MCP: `dbward_migrate_up` tool call

```
AI Agent sends JSON-RPC via stdin:
  {"jsonrpc":"2.0","id":1,"method":"tools/call",
   "params":{"name":"dbward_migrate_up","arguments":{}}}

dbward-cli (MCP mode: `dbward mcp`)
  │
  ├─ read stdin line
  ├─ parse JSON-RPC
  ├─ dispatch to handler based on tool name
  │   └─ (same flow as CLI migrate up)
  ├─ AuditLogger::log()
  └─ write JSON-RPC response to stdout:
     {"jsonrpc":"2.0","id":1,"result":{"content":[
       {"type":"text","text":"Applied 2 migrations: ..."}]}}
```

### 3. CLI: `dbward execute "SELECT * FROM users"`

```
dbward-cli
  │
  ├─ load_config()
  ├─ classify_query(sql)     → QueryType::Select
  ├─ check_permission()      → Role vs Operation::ExecuteQuery
  ├─ (if DDL → reject)
  ├─ (if readonly + DML → reject)
  ├─ DbConnection::connect()
  ├─ execute_query(pool, sql)
  │   ├─ SELECT → return rows as JSON
  │   └─ DML → return affected row count
  ├─ AuditLogger::log()
  └─ print result
```

### 4. MCP: `dbward_execute_query` tool call

```
AI Agent sends:
  {"jsonrpc":"2.0","id":2,"method":"tools/call",
   "params":{"name":"dbward_execute_query",
             "arguments":{"sql":"SELECT * FROM users LIMIT 10"}}}

dbward-cli (MCP mode)
  │
  ├─ (same flow as CLI execute)
  └─ write JSON-RPC response with query results
```

## MCP Protocol (stdio)

Minimal JSON-RPC 2.0 over stdin/stdout. One JSON object per line.

### Initialization

```
→ {"jsonrpc":"2.0","id":0,"method":"initialize",
    "params":{"protocolVersion":"2024-11-05","capabilities":{}}}
← {"jsonrpc":"2.0","id":0,"result":{
    "protocolVersion":"2024-11-05",
    "serverInfo":{"name":"dbward","version":"0.1.0"},
    "capabilities":{"tools":{}}}}
→ {"jsonrpc":"2.0","method":"notifications/initialized"}
```

### Tool Listing

```
→ {"jsonrpc":"2.0","id":1,"method":"tools/list"}
← {"jsonrpc":"2.0","id":1,"result":{"tools":[
    {"name":"dbward_migrate_status","description":"Show migration status",
     "inputSchema":{"type":"object","properties":{}}},
    {"name":"dbward_migrate_up","description":"Run pending migrations",
     "inputSchema":{"type":"object","properties":{
       "count":{"type":"integer","description":"Max migrations to apply"}}}},
    {"name":"dbward_migrate_down","description":"Rollback last migration",
     "inputSchema":{"type":"object","properties":{
       "count":{"type":"integer","description":"Migrations to rollback","default":1}}}},
    {"name":"dbward_migrate_create","description":"Create a new migration file",
     "inputSchema":{"type":"object","properties":{
       "name":{"type":"string","description":"Migration name"}},
      "required":["name"]}},
    {"name":"dbward_execute_query","description":"Execute SQL query",
     "inputSchema":{"type":"object","properties":{
       "sql":{"type":"string","description":"SQL statement"}},
      "required":["sql"]}},
    {"name":"dbward_audit_search","description":"Search audit log",
     "inputSchema":{"type":"object","properties":{
       "user":{"type":"string"},
       "operation":{"type":"string"},
       "limit":{"type":"integer","default":20}}}}
  ]}}
```

## Config Loading

Priority (highest wins):
1. Environment variables: `DBWARD_DATABASE_URL`, `DBWARD_ROLE`, `DBWARD_ENV`
2. `dbward.toml` in current directory (or `--config` flag)
3. Defaults

```toml
# dbward.toml
environment = "development"
role = "developer"
migrations_dir = "db/migrations"

[database]
url = "postgres://localhost:5432/myapp"
```

## Migration File Format

dbmate-compatible for easy migration path:

```
db/migrations/
  20260501120000_create_users.sql
  20260501120100_add_email_index.sql
```

Each file:
```sql
-- migrate:up
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL
);

-- migrate:down
DROP TABLE users;
```

### Schema Tracking

`schema_migrations` table in target DB:

```sql
CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY  -- "20260501120000"
);
```

## Query Classification

Simple prefix-based classification (no full SQL parser in MVP):

```rust
fn classify_query(sql: &str) -> Result<QueryType, Error> {
    let trimmed = sql.trim_start().to_uppercase();
    if trimmed.starts_with("SELECT") || trimmed.starts_with("WITH") {
        Ok(QueryType::Select)
    } else if trimmed.starts_with("INSERT") {
        Ok(QueryType::Insert)
    } else if trimmed.starts_with("UPDATE") {
        Ok(QueryType::Update)
    } else if trimmed.starts_with("DELETE") {
        Ok(QueryType::Delete)
    } else {
        Err(Error::DdlNotAllowed)
    }
}
```

## Module Responsibilities

| Crate | Owns | Does NOT own |
|---|---|---|
| `dbward-core` | Types, RBAC, audit, config, DB pool, query execution, query classification | Migration file I/O |
| `dbward-migrate` | Migration file parsing, schema_migrations table, up/down execution | DB connection creation |
| `dbward-cli` | CLI arg parsing (clap), MCP stdio protocol, user interaction | Business logic |
| `dbward-server` | REST API (axum), MCP HTTP, approval state (SQLite) | (Pro, not MVP) |
