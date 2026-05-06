# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | ✅ Security fixes  |
| < 0.1   | ❌ Not supported   |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email:

📧 **security@dbward.dev**

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
