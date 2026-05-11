use serde::{Deserialize, Serialize};
use std::fmt;

/// User role in the system. Hierarchy: admin > developer > readonly. Auditor is independent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Admin,
    Developer,
    Readonly,
    Auditor,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Developer => "developer",
            Self::Readonly => "readonly",
            Self::Auditor => "auditor",
        }
    }

    /// Returns the hierarchy level (higher = more privileged). Auditor is 0 (independent).
    fn level(&self) -> u8 {
        match self {
            Self::Admin => 3,
            Self::Developer => 2,
            Self::Readonly => 1,
            Self::Auditor => 0,
        }
    }

    /// Whether this role satisfies the required role (hierarchy check).
    /// Auditor only satisfies Auditor.
    pub fn satisfies(&self, required: Role) -> bool {
        if required == Role::Auditor {
            return *self == Role::Auditor;
        }
        if *self == Role::Auditor {
            return false;
        }
        self.level() >= required.level()
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Role {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "admin" => Ok(Self::Admin),
            "developer" => Ok(Self::Developer),
            "readonly" => Ok(Self::Readonly),
            "auditor" => Ok(Self::Auditor),
            _ => Err("unknown role"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hierarchy() {
        assert!(Role::Admin.satisfies(Role::Developer));
        assert!(Role::Admin.satisfies(Role::Readonly));
        assert!(Role::Developer.satisfies(Role::Readonly));
        assert!(Role::Developer.satisfies(Role::Developer));
        assert!(!Role::Readonly.satisfies(Role::Developer));
        assert!(!Role::Developer.satisfies(Role::Admin));
    }

    #[test]
    fn auditor_independent() {
        assert!(Role::Auditor.satisfies(Role::Auditor));
        assert!(!Role::Auditor.satisfies(Role::Readonly));
        assert!(!Role::Admin.satisfies(Role::Auditor));
    }

    #[test]
    fn parse() {
        assert_eq!("admin".parse::<Role>().unwrap(), Role::Admin);
        assert!("unknown".parse::<Role>().is_err());
    }
}
