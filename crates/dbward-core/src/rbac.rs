use crate::{Error, Operation};

/// Check whether `role` (effective permission level) is allowed to perform `operation`.
///
/// Matrix:
///   - "admin": all operations
///   - "developer": all except audit_search
///   - "readonly": migrate_status, audit_search, execute_query (SELECT only — caller enforces query type)
///   - "approver" (custom roles): no operations (they exist only to approve requests)
pub fn check_permission(role: &str, operation: &Operation) -> Result<(), Error> {
    let allowed = match role {
        "admin" => true,
        "developer" => !matches!(operation, Operation::AuditSearch),
        "readonly" => matches!(
            operation,
            Operation::MigrateStatus | Operation::AuditSearch | Operation::ExecuteQuery
        ),
        _ => false,
    };

    if allowed {
        Ok(())
    } else {
        Err(Error::PermissionDenied {
            role: role.to_string(),
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
            assert!(check_permission("admin", op).is_ok(), "admin should be allowed {op}");
        }
    }

    #[test]
    fn developer_cannot_search_audit() {
        assert!(check_permission("developer", &Operation::AuditSearch).is_err());
    }

    #[test]
    fn developer_can_migrate_and_execute() {
        assert!(check_permission("developer", &Operation::MigrateUp).is_ok());
        assert!(check_permission("developer", &Operation::ExecuteQuery).is_ok());
    }

    #[test]
    fn readonly_cannot_mutate() {
        assert!(check_permission("readonly", &Operation::MigrateUp).is_err());
        assert!(check_permission("readonly", &Operation::MigrateDown).is_err());
        assert!(check_permission("readonly", &Operation::MigrateCreate).is_err());
    }

    #[test]
    fn readonly_can_read() {
        assert!(check_permission("readonly", &Operation::MigrateStatus).is_ok());
        assert!(check_permission("readonly", &Operation::ExecuteQuery).is_ok());
        assert!(check_permission("readonly", &Operation::AuditSearch).is_ok());
    }

    #[test]
    fn custom_role_cannot_perform_operations() {
        assert!(check_permission("dba", &Operation::ExecuteQuery).is_err());
        assert!(check_permission("team-lead", &Operation::MigrateUp).is_err());
        assert!(check_permission("dba", &Operation::AuditSearch).is_err());
        assert!(check_permission("approver", &Operation::ExecuteQuery).is_err());
    }
}
