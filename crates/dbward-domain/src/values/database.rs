use serde::{Deserialize, Serialize};
use std::fmt;

/// Validated database name. 1-63 chars, `^[a-z][a-z0-9_-]*$` or `*` (wildcard).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DatabaseName(String);

impl DatabaseName {
    pub fn new(s: impl Into<String>) -> Result<Self, &'static str> {
        let s = s.into();
        if s == "*" {
            return Ok(Self(s));
        }
        if s.is_empty() || s.len() > 63 {
            return Err("database name must be 1-63 characters");
        }
        let bytes = s.as_bytes();
        if !bytes[0].is_ascii_lowercase() {
            return Err("database name must start with a lowercase letter");
        }
        if !bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-')
        {
            return Err("database name must match [a-z0-9_-]");
        }
        Ok(Self(s))
    }

    pub fn wildcard() -> Self {
        Self("*".to_string())
    }

    pub fn is_wildcard(&self) -> bool {
        self.0 == "*"
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for DatabaseName {
    type Error = &'static str;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl From<DatabaseName> for String {
    fn from(d: DatabaseName) -> Self {
        d.0
    }
}

impl fmt::Display for DatabaseName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_names() {
        assert!(DatabaseName::new("app").is_ok());
        assert!(DatabaseName::new("my-db-1").is_ok());
        assert!(DatabaseName::new("a").is_ok());
        assert!(DatabaseName::new("*").is_ok());
    }

    #[test]
    fn invalid_names() {
        assert!(DatabaseName::new("").is_err());
        assert!(DatabaseName::new("1app").is_err());
        assert!(DatabaseName::new("App").is_err());
        assert!(DatabaseName::new("a b").is_err());
        assert!(DatabaseName::new(&"a".repeat(64)).is_err());
    }

    #[test]
    fn wildcard() {
        let w = DatabaseName::wildcard();
        assert!(w.is_wildcard());
    }
}
