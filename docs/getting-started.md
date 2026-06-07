---
title: Getting Started
description: Get dbward running in minutes — choose your path
---

# Getting Started

Choose how you want to try dbward:

| Path | Best for | Time |
|------|----------|------|
| [**Connect your database**](quickstart-local.md) | Quick smoke test with your own PostgreSQL/MySQL | 1 min |
| [**Try with Docker**](quickstart-docker.md) | See the full approval workflow (submit → approve → execute) | 2 min |
| [**Setup Guide**](guides/setup-guide.md) | Understand the architecture and deploy to your team | 10 min |

---

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Request** | A unit of work (query or migration) submitted for execution |
| **Workflow** | Approval policy — determines whether a request needs sign-off |
| **Agent** | Process that connects to the database and executes approved requests |
| **Server** | Approval engine + audit log (never touches your database) |
| **Break-glass** | Emergency bypass to skip approval in critical situations |

## Next Steps

1. [Executing Queries](guides/executing-queries.md) — day-to-day workflow
2. [Policies Overview](guides/policies/overview.md) — approval rules and auto-approve
3. [Architecture](architecture.md) — how the components fit together
