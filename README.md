# dbward

A workflow and approval engine for database operations.

Lightweight CLI + API + MCP. Migrations, RBAC, approval flows, and audit logs — without the weight of a full web application.

## Status

🚧 Early development — not yet usable.

## Architecture

```
CLI mode:    dbward migrate up          (no server needed)
Server mode: dbward server              (approval flows + shared audit log)
```

- **CLI**: Human & CI/CD interface
- **REST API**: Programmatic access (server mode)
- **MCP**: AI agent integration (Kiro, Cursor, Copilot)

## Crates

| Crate | Description |
|---|---|
| `dbward-core` | Workflow engine, RBAC, audit log |
| `dbward-migrate` | Migration execution (PostgreSQL) |
| `dbward-server` | REST API + MCP server |
| `dbward-cli` | CLI interface |

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
