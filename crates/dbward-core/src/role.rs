use crate::Operation;

/// Built-in permission levels (highest to lowest).
/// Custom role names (e.g. "dba", "team-lead") are treated as Approver level.
pub const ADMIN: &str = "admin";
pub const DEVELOPER: &str = "developer";
pub const READONLY: &str = "readonly";
pub const APPROVER: &str = "approver";

/// All built-in roles in descending rank order.
pub const BUILTIN_ROLES: &[&str] = &[ADMIN, DEVELOPER, READONLY];

/// Numeric rank for permission hierarchy. Higher = more privileged.
pub fn rank(role: &str) -> i8 {
    match role {
        ADMIN => 3,
        DEVELOPER => 2,
        READONLY => 1,
        _ => 0,
    }
}

/// Returns true if `actual` role has at least the privilege level of `required`.
pub fn satisfies(actual: &str, required: &str) -> bool {
    rank(actual) >= rank(required)
}

/// Determine the effective permission level from a list of roles.
/// Returns the highest-ranked built-in role, or "approver" if none match.
pub fn effective_permission(roles: &[String]) -> &'static str {
    for &builtin in BUILTIN_ROLES {
        if roles.iter().any(|r| r == builtin) {
            return builtin;
        }
    }
    APPROVER
}

/// Check if a role is allowed to perform an operation.
pub fn is_operation_allowed(role: &str, operation: &Operation) -> bool {
    match role {
        ADMIN => true,
        DEVELOPER => !matches!(operation, Operation::AuditSearch),
        READONLY => matches!(
            operation,
            Operation::MigrateStatus | Operation::AuditSearch | Operation::ExecuteQuery
        ),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rank_ordering() {
        assert!(rank(ADMIN) > rank(DEVELOPER));
        assert!(rank(DEVELOPER) > rank(READONLY));
        assert!(rank(READONLY) > rank("custom-role"));
    }

    #[test]
    fn satisfies_hierarchy() {
        assert!(satisfies(ADMIN, DEVELOPER));
        assert!(satisfies(ADMIN, READONLY));
        assert!(satisfies(DEVELOPER, READONLY));
        assert!(!satisfies(READONLY, DEVELOPER));
        assert!(!satisfies("dba", READONLY));
    }

    #[test]
    fn effective_permission_picks_highest() {
        assert_eq!(
            effective_permission(&["readonly".into(), "admin".into()]),
            ADMIN
        );
        assert_eq!(effective_permission(&["developer".into()]), DEVELOPER);
        assert_eq!(effective_permission(&["team-lead".into()]), APPROVER);
    }

    #[test]
    fn operation_permissions() {
        assert!(is_operation_allowed(ADMIN, &Operation::AuditSearch));
        assert!(!is_operation_allowed(DEVELOPER, &Operation::AuditSearch));
        assert!(is_operation_allowed(DEVELOPER, &Operation::ExecuteQuery));
        assert!(is_operation_allowed(READONLY, &Operation::ExecuteQuery));
        assert!(!is_operation_allowed(READONLY, &Operation::MigrateUp));
        assert!(!is_operation_allowed("dba", &Operation::ExecuteQuery));
    }
}
