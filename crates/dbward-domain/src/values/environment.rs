use serde::{Deserialize, Serialize};
use std::fmt;

/// Validated environment name. Same rules as DatabaseName: 1-63 chars, `^[a-z][a-z0-9_-]*$` or `*`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Environment(String);

impl Environment {
    pub fn new(s: impl Into<String>) -> Result<Self, &'static str> {
        let s = s.into();
        if s == "*" {
            return Ok(Self(s));
        }
        if s.is_empty() || s.len() > 63 {
            return Err("environment must be 1-63 characters");
        }
        let bytes = s.as_bytes();
        if !bytes[0].is_ascii_lowercase() {
            return Err("environment must start with a lowercase letter");
        }
        if !bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-')
        {
            return Err("environment must match [a-z0-9_-]");
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

impl TryFrom<String> for Environment {
    type Error = &'static str;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(s)
    }
}

impl From<Environment> for String {
    fn from(e: Environment) -> Self {
        e.0
    }
}

impl fmt::Display for Environment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid() {
        assert!(Environment::new("production").is_ok());
        assert!(Environment::new("staging").is_ok());
        assert!(Environment::new("dev-1").is_ok());
        assert!(Environment::new("*").is_ok());
    }

    #[test]
    fn invalid() {
        assert!(Environment::new("").is_err());
        assert!(Environment::new("Production").is_err());
        assert!(Environment::new("1dev").is_err());
    }
}
