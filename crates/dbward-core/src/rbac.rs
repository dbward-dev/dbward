use crate::{Error, Operation, Role};

/// Check whether `role` is allowed to perform `operation`.
///
/// Matrix:
///   - Admin: all operations
///   - Developer: all except audit_search (read own logs only via CLI)
///   - Readonly: migrate_status, audit_search, execute_query (SELECT only — caller enforces query type)
pub fn check_permission(role: &Role, operation: &Operation) -> Result<(), Error> {
    let allowed = match role {
        Role::Admin => true,
        Role::Developer => !matches!(operation, Operation::AuditSearch),
        Role::Readonly => matches!(
            operation,
            Operation::MigrateStatus | Operation::AuditSearch | Operation::ExecuteQuery
        ),
    };

    if allowed {
        Ok(())
    } else {
        Err(Error::PermissionDenied {
            role: *role,
            operation: *operation,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_can_do_everything() {
        let ops = [
            Operation::MigrateUp,
            Operation::MigrateDown,
            Operation::MigrateStatus,
            Operation::MigrateCreate,
            Operation::ExecuteQuery,
            Operation::AuditSearch,
        ];
        for op in &ops {
            assert!(check_permission(&Role::Admin, op).is_ok(), "admin should be allowed {op}");
        }
    }

    #[test]
    fn developer_cannot_search_audit() {
        assert!(check_permission(&Role::Developer, &Operation::AuditSearch).is_err());
    }

    #[test]
    fn developer_can_migrate_and_execute() {
        assert!(check_permission(&Role::Developer, &Operation::MigrateUp).is_ok());
        assert!(check_permission(&Role::Developer, &Operation::ExecuteQuery).is_ok());
    }

    #[test]
    fn readonly_cannot_mutate() {
        assert!(check_permission(&Role::Readonly, &Operation::MigrateUp).is_err());
        assert!(check_permission(&Role::Readonly, &Operation::MigrateDown).is_err());
        assert!(check_permission(&Role::Readonly, &Operation::MigrateCreate).is_err());
    }

    #[test]
    fn readonly_can_read() {
        assert!(check_permission(&Role::Readonly, &Operation::MigrateStatus).is_ok());
        assert!(check_permission(&Role::Readonly, &Operation::ExecuteQuery).is_ok());
        assert!(check_permission(&Role::Readonly, &Operation::AuditSearch).is_ok());
    }
}
