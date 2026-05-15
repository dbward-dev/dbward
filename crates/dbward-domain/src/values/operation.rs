use serde::{Deserialize, Serialize};
use std::fmt;

/// The classified operation type for a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    ExecuteSelect,
    ExecuteDml,
    MigrateUp,
    MigrateDown,
    MigrateStatus,
}

impl Operation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ExecuteSelect => "execute_select",
            Self::ExecuteDml => "execute_dml",
            Self::MigrateUp => "migrate_up",
            Self::MigrateDown => "migrate_down",
            Self::MigrateStatus => "migrate_status",
        }
    }

    pub fn is_read_only(&self) -> bool {
        matches!(self, Self::ExecuteSelect | Self::MigrateStatus)
    }

    pub fn is_mutation(&self) -> bool {
        !self.is_read_only()
    }
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Operation {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "execute_select" => Ok(Self::ExecuteSelect),
            "execute_dml" => Ok(Self::ExecuteDml),
            "execute_query" | "execute" | "query" => Ok(Self::ExecuteSelect),
            "migrate_up" => Ok(Self::MigrateUp),
            "migrate_down" => Ok(Self::MigrateDown),
            "migrate_status" => Ok(Self::MigrateStatus),
            _ => Err(format!(
                "unknown operation '{s}'. Valid operations: execute_select, execute_dml, execute_query, migrate_up, migrate_down, migrate_status"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        for op in [
            Operation::ExecuteSelect,
            Operation::ExecuteDml,
            Operation::MigrateUp,
            Operation::MigrateDown,
            Operation::MigrateStatus,
        ] {
            let s = op.as_str();
            let parsed: Operation = s.parse().unwrap();
            assert_eq!(parsed, op);
        }
    }

    #[test]
    fn read_only() {
        assert!(Operation::ExecuteSelect.is_read_only());
        assert!(Operation::MigrateStatus.is_read_only());
        assert!(!Operation::ExecuteDml.is_read_only());
    }
}
