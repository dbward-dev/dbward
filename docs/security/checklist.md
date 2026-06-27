---
title: Security Checklist
description: Pre-deployment and operational security checklist
---

# Security Checklist

Use this checklist before deploying dbward to production and for periodic security reviews.

## Pre-Deployment (Must)

- [ ] **TLS enabled** — Server is behind a TLS-terminating reverse proxy or configured with its own certificates
- [ ] **Workflows defined** — Every (database, environment) pair has a matching workflow rule. Unmatched operations are rejected (fail-closed)
- [ ] **Self-approval disabled** — Verify `allow_self_approve = false` in server config
- [ ] **Agent token from environment** — `DBWARD_AGENT_TOKEN` injected via env var or secrets manager, not hardcoded in config files
- [ ] **File permissions set** — `data/` directory is `0700`, `signing.key` is `0600`, owned by dedicated service account
- [ ] **DB users are least-privilege** — Separate users for read-only and DDL operations; no superuser access
- [ ] **Signing key generated** — Ed25519 key exists at `data/signing.key` and is protected
- [ ] **Signing key compromise procedure documented** — Team knows: stop agents → replace key → restart server → wait 5min → restart agents
- [ ] **Agent trust revocation tested** — Team can revoke agent token and stop execution within 5 minutes

## Recommended

- [ ] **OIDC authentication configured** — Eliminates token management; inherits IdP MFA and offboarding
- [ ] **Statement timeout set** — Via `execution_policy` or agent config; prevents runaway queries
- [ ] **Webhook HMAC secret configured** — All webhook receivers verify `X-Dbward-Signature`
- [ ] **Slack signing secret set** — Stored as environment variable, not in committed config
- [ ] **Break-glass restricted** — Only designated roles (e.g., `admin`) can use `--emergency`
- [ ] **Agent capabilities restricted** — Explicit `databases` and `environments` in agent config
- [ ] **Execution policy limits set** — `max_executions` and `execution_window` configured
- [ ] **Core dumps disabled** — On server host where signing key resides in memory
- [ ] **Outbound network restricted** — Agent can only reach server URL + target databases
- [ ] **Trusted proxies configured** — `trusted_proxies` in server.toml matches your reverse proxy CIDRs
- [ ] **sql_review rules configured** — Review [[sql_review]] settings; set destructive rules (drop_table, truncate) to "block" for production environment
- [ ] **auto_approve scoped** — Verify production workflow has no [workflows.auto_approve] section)
- [ ] **S3 result encryption** — If using S3 storage, enable server-side encryption (SSE-S3 or SSE-KMS)

## Operational (Periodic Review)

- [ ] **Token rotation** — API tokens rotated every 90 days; agent tokens rotated on schedule
- [ ] **Audit chain verification** — Daily automated check via `verify_chain()`; alert on failure
- [ ] **Audit export** — Logs exported to external SIEM/storage for independent retention
- [ ] **User cleanup** — Suspended/departed users disabled; unused tokens revoked
- [ ] **Break-glass review** — All break-glass usage reviewed and documented
- [ ] **Backup restore test** — SQLite backup restored and audit chain verified on test instance
- [ ] **OIDC group mapping review** — Group→role mappings match current org structure
- [ ] **Incident drill** — Team can: freeze approvals, revoke agent token, rotate signing key, and disable an agent within 15 minutes
- [ ] **Dependency updates** — `cargo-deny` advisories addressed; runtime dependencies patched
