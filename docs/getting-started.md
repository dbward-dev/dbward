---
title: Getting Started
description: Get dbward running in 5 minutes — choose your path
---

# Getting Started

Choose how you want to try dbward:

| Path | Best for | Time | Requirements |
|------|----------|------|--------------|
| [**Connect your database**](quickstart-local.md) | You already have PostgreSQL or MySQL running | 1 min | macOS or Linux |
| [**Try with Docker**](quickstart-docker.md) | You want a self-contained demo with a test database | 5 min | Docker + Docker Compose |

Both paths end with a working approval flow you can test.

---

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Request** | A unit of work (query or migration) submitted for execution |
| **Workflow** | Approval policy that determines whether a request needs human sign-off |
| **Agent** | Process that connects to the database and executes approved requests |
| **Server** | Central coordinator for approval state, audit logs, and request routing |
| **Break-glass** | Emergency bypass mechanism to skip approval in critical situations |

## What's next after getting started

- [Team Setup](deployment/overview.md) — deploy server + agent for your team
- [Workflows Guide](guides/workflows.md) — approval policies and conditions
- [MCP Integration](guides/mcp-integration.md) — use dbward as an MCP server for AI tools
- [Configuration Reference](reference/configuration.md) — all config options
