---
title: Threat Model
description: STRIDE-based threat analysis for dbward
---

# Threat Model

This document provides a STRIDE-based threat analysis of dbward's architecture.

## Assets

| Asset | Location | Sensitivity |
|-------|----------|-------------|
| Database credentials | Agent config/env vars | Critical — full DB access |
| Ed25519 signing key | Server filesystem (`signing.key`) | Critical — token forgery |
| API token hashes | Server SQLite | High — authentication |
| Approval state & workflows | Server SQLite | High — authorization logic |
| Audit log (hash chain) | Server SQLite | High — accountability |
| Query text | Server SQLite (requests table) | Medium — may contain secrets |
| Query results | Agent → result store | Medium — business data |
| OIDC configuration | Server config | Medium — auth infrastructure |

## Actors

| Actor | Trust Level | Capabilities |
|-------|-------------|--------------|
| Authenticated user (CLI/MCP) | Partial — authenticated, role-limited | Create requests, view own results |
| AI agent (MCP client) | Partial — same as user, no special privileges | Propose operations via MCP tools |
| Approver | Partial — authenticated, approve-role | Approve/reject requests |
| dbward-agent | High — holds DB credentials | Execute approved operations |
| Server | High — issues execution tokens | Manage state, verify auth, sign tokens |
| External attacker | None | Network access only |
| Malicious insider | Partial — valid credentials | Abuse legitimate access |

## Trust Boundaries

```
┌─ Boundary 1: Network ──────────────────────────────────────────────┐
│                                                                      │
│  ┌─ Boundary 2: Server Process ─────────────────────────────────┐  │
│  │  Auth middleware, RBAC, workflow engine, token signer          │  │
│  │  SQLite state (audit, approvals, tokens)                      │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌─ Boundary 3: Agent Process ──────────────────────────────────┐  │
│  │  Token verifier, capability checker, DB driver                │  │
│  │  DB credentials (env vars / config)                           │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌─ Boundary 4: External Services ──────────────────────────────┐  │
│  │  Target databases, OIDC IdP, Slack API                        │  │
│  └───────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

## STRIDE Analysis

### Spoofing

| Threat | Risk | Mitigation |
|--------|------|------------|
| Forged API token | High | SHA-256 hash verification, prefix-based lookup, expiry check |
| Spoofed OIDC JWT | High | JWKS-based RS256 signature verification, issuer/audience validation |
| Fake agent registration | High | Agent token required, capability config limits scope |
| Spoofed Slack interaction | Medium | HMAC-SHA256 signature verification (constant-time), timestamp ±5min |

### Tampering

| Threat | Risk | Mitigation |
|--------|------|------------|
| Execution token modification | Critical | Ed25519 signature + SHA-256 content hash binding |
| Audit log manipulation | High | Hash chain — each entry includes hash of previous entry |
| SQLite database file tampering | Medium | PRAGMA foreign_keys, application-level integrity checks |
| Webhook payload tampering | Medium | HMAC-SHA256 signature in X-Dbward-Signature header |

### Repudiation

| Threat | Risk | Mitigation |
|--------|------|------------|
| Denying approval action | High | Hash-chain audit with actor_id, timestamp, matched_selector |
| Denying execution | High | Execution record with agent_id, token, start/end timestamps |
| Denying request creation | Medium | Audit event at creation with requester identity |

**Audit verification model:** Run `verify_chain()` periodically (recommended: daily cron). Each event's hash is recomputed from its fields + previous hash. Any mismatch indicates tampering. Checkpoints can be exported to external storage for independent verification.

### Information Disclosure

| Threat | Risk | Mitigation |
|--------|------|------------|
| DB credential leakage | Critical | Agent-only isolation — creds never sent to server or CLI |
| Query text exposure via webhook | Medium | SQL literals redacted to `?`; parse failure → SHA-256 only |
| API token exposure | Medium | Only SHA-256 hash stored; prefix for lookup only |
| OIDC token in logs | Low | Tokens not logged; only subject_id extracted |

### Denial of Service

| Threat | Risk | Mitigation |
|--------|------|------------|
| JWKS endpoint flooding | Medium | Cache with 1h TTL; refresh only on signature mismatch (not claim errors) |
| Approval queue flooding | Low | Rate limiting at reverse proxy; request size limit 100KB |
| SQLite write contention | Medium | busy_timeout=10s, IMMEDIATE transactions for critical paths |
| Agent starvation | Low | Multiple agents supported; poll interval configurable |

### Elevation of Privilege

| Threat | Risk | Mitigation |
|--------|------|------------|
| Self-approval | High | Configurable prohibition (default: denied); checked in approve path |
| Break-glass abuse | Medium | Requires explicit flag + mandatory reason; audit-logged; role-restricted |
| Role escalation via OIDC groups | Medium | Server-side group→role mapping; no client-side role claims |
| AI proposal laundering | Medium | SQL Review (10 rules); content-bound execution token; human must approve exact SQL |

## AI-Specific Threats

| Threat | Description | Mitigation |
|--------|-------------|------------|
| Prompt injection via schema | Malicious table/column names influence AI proposals | SQL Review catches destructive patterns; human approves final SQL |
| Proposal laundering | AI explanation appears safe but SQL is harmful | Execution token bound to exact SQL text; approver sees actual SQL |
| Multi-step decomposition | Breaking a dangerous operation into individually-safe steps | Workflow can require approval per-request; audit shows full sequence |
| Human over-trust | Approver rubber-stamps AI proposals | Multi-step approval; different approvers per step; risk scoring in context |

## Partial Failure Behavior

| Scenario | Behavior | Recovery |
|----------|----------|----------|
| Server crash during execution | Agent detects heartbeat response failure | Agent marks job failed; on server restart, request can be re-dispatched via resume |
| OIDC IdP unavailable | All OIDC auth fails (fail-closed) | API token auth still works; IdP recovery restores OIDC |
| Agent loses DB connection | Execution fails with error | Result reported as failed; can be retried after resume |
| Signing key unavailable | Token issuance fails | No new executions possible; existing in-flight tokens still valid until expiry |
| Clock drift >5min | Slack signatures rejected; token expiry unreliable | NTP sync required; operations resume after clock correction |

## Known Limitations

| Limitation | Impact | Planned Mitigation |
|------------|--------|-------------------|
| SQLite not encrypted at rest | File access = full state access | Filesystem permissions (0700); encrypted storage planned |
| Single-instance server | No HA; restart = in-memory result loss | Sufficient for <100 concurrent users; HA planned for v0.2+ |
| File-based signing key | No HSM/KMS protection | Rotation via restart; KMS integration planned |
| No SBOM or image signing | Supply chain verification limited | cargo-deny for advisories; image signing planned |
| InMemory result channel | Server restart loses pending results | TTL=10min; clients can re-poll after restart |
