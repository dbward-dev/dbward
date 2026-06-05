# Security Architecture Rules

Rules for contributors to prevent authorization bypass and injection vulnerabilities.

## 1. Parameterized queries only

All SQL in `crates/dbward-infra/src/sqlite/` MUST use `?N` parameter binding.
Never embed user-derived values via `format!`. CI lint enforces this.

## 2. Handler → UseCase only

Route handlers in `crates/dbward-server/src/routes/` MUST NOT call repo methods
directly. All data access goes through UseCase structs that contain authorization
checks.

## 3. Authorizer only

Permission checks MUST go through the `Authorizer` trait (`authorize_global` or
`authorize_scoped`). Direct `Permission::` enum comparison in handlers is
forbidden. CI lint enforces this.

## 4. Domain rule ≠ Authz

"Requester can operate on their own request" is a **domain rule**, implemented as
`subject_id == requester_id` checks inside use cases. This is distinct from
authorization (role/permission checks) and is acceptable at the use case layer.
Handler-layer subject_id checks are not allowed.

## 5. ResourceContext for scoped access

When access depends on resource ownership (requests, tokens, users), use
`authorize_scoped` with the appropriate `ResourceContext` variant. Never
short-circuit with `if user.subject_id == owner { skip_authz }` in handlers.

## 6. SSRF validation

Any endpoint accepting user-provided URLs (webhooks, notification policies) MUST
call `SsrfValidator::validate_url()` before storing or dispatching to the URL.
