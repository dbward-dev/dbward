# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | ✅ Security fixes  |
| < 0.1   | ❌ Not supported   |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, use GitHub's private vulnerability reporting:

1. Go to [Security → Advisories → Report a vulnerability](https://github.com/dbward-dev/dbward/security/advisories/new)
2. Fill in the details (description, steps to reproduce, impact)
3. Submit — only you and the maintainers can see the report

This keeps the vulnerability private until a fix is available.

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response timeline

- **Acknowledgment**: within 48 hours
- **Initial assessment**: within 7 days
- **Fix or mitigation**: within 30 days for critical issues

### Disclosure policy

- We follow coordinated disclosure (90-day window)
- Credit will be given to reporters unless they prefer anonymity
- We will publish a security advisory on GitHub once a fix is available

## Security Architecture

dbward is designed with the following security principles:

- **Zero-trust client**: CLI/MCP clients never have database credentials
- **Signed execution tokens**: Ed25519 signatures bind approved SQL to specific databases
- **Network isolation**: Server has no DB credentials; Agent connects outbound only
- **Approval enforcement**: No execution without workflow approval (or explicit break-glass)

For details, see the [Architecture section in README](README.md#architecture).

## Known Limitations (v0.1.0)

- SQLite database is not encrypted at rest (file permissions are enforced)
- Result relay is in-memory; server restart loses undelivered results
- Single-node only; no HA or clustering support
- HTTPS is required but must be provided by a reverse proxy (not built-in)
- Break-glass bypasses approval (by design); monitored via webhook + audit log

## Ignored Security Advisories

The following RustSec advisories are acknowledged and ignored in `deny.toml`:

| ID | Crate | Reason |
|----|-------|--------|
| RUSTSEC-2026-0066 | tokio-tar | Dev-dependency only (testcontainers). Not in release binary. |
| RUSTSEC-2026-0112 | tokio-tar | Dev-dependency only (testcontainers). Not in release binary. |
| RUSTSEC-2026-0113 | tar | Dev-dependency only (testcontainers). Not in release binary. |
| RUSTSEC-2023-0071 | rsa | Transitive via rustls. dbward does not use RSA key exchange. |
| RUSTSEC-2025-0134 | rustls-pemfile | Unmaintained. Transitive via reqwest/rustls. No direct usage. |
| RUSTSEC-2026-0145 | astral-tokio-tar | Dev-dependency only (testcontainers). Not in release binary. |
