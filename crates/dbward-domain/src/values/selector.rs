use serde::{Deserialize, Serialize};
use std::fmt;

/// A selector that matches users by role, group, or specific user ID.
/// Format: `role:<name>`, `group:<name>`, `user:<id>`, `requester`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum Selector {
    Requester,
    Role(String),
    Group(String),
    User(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectorParseError(pub String);

impl fmt::Display for SelectorParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid selector: {}", self.0)
    }
}

impl std::error::Error for SelectorParseError {}

impl Selector {
    pub fn parse(s: &str) -> Result<Self, SelectorParseError> {
        if s == "requester" {
            return Ok(Self::Requester);
        }
        let (prefix, value) = s.split_once(':').ok_or_else(|| {
            SelectorParseError(format!(
                "missing ':' in '{s}'. Expected format: user:<name>, group:<name>, or role:<name>"
            ))
        })?;
        if value.is_empty() {
            return Err(SelectorParseError(format!("empty value in '{s}'")));
        }
        match prefix {
            "role" => Ok(Self::Role(value.to_string())),
            "group" => Ok(Self::Group(value.to_string())),
            "user" => Ok(Self::User(value.to_string())),
            _ => Err(SelectorParseError(format!("unknown prefix '{prefix}'"))),
        }
    }

    /// Check if this selector matches the given user attributes.
    pub fn matches(
        &self,
        role_names: &[String],
        groups: &[String],
        user_id: &str,
        is_requester: bool,
    ) -> bool {
        match self {
            Self::Requester => is_requester,
            Self::Role(r) => role_names.iter().any(|rn| rn == r),
            Self::Group(g) => groups.iter().any(|ug| ug == g),
            Self::User(u) => user_id == u,
        }
    }
}

impl TryFrom<String> for Selector {
    type Error = SelectorParseError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

impl From<Selector> for String {
    fn from(s: Selector) -> Self {
        s.to_string()
    }
}

impl fmt::Display for Selector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Requester => f.write_str("requester"),
            Self::Role(r) => write!(f, "role:{r}"),
            Self::Group(g) => write!(f, "group:{g}"),
            Self::User(u) => write!(f, "user:{u}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid() {
        assert_eq!(
            Selector::parse("role:dba").unwrap(),
            Selector::Role("dba".to_string())
        );
        assert_eq!(
            Selector::parse("group:dba-team").unwrap(),
            Selector::Group("dba-team".to_string())
        );
        assert_eq!(
            Selector::parse("user:alice").unwrap(),
            Selector::User("alice".to_string())
        );
        assert_eq!(Selector::parse("requester").unwrap(), Selector::Requester);
    }

    #[test]
    fn parse_invalid() {
        assert!(Selector::parse("admin").is_err());
        assert!(Selector::parse("role:").is_err());
        assert!(Selector::parse("foo:bar").is_err());
    }

    #[test]
    fn matches_role() {
        let sel = Selector::Role("dba".to_string());
        assert!(sel.matches(&["dba".to_string()], &[], "bob", false));
        assert!(!sel.matches(&["viewer".to_string()], &[], "bob", false));
    }

    #[test]
    fn matches_group() {
        let sel = Selector::Group("dba-team".to_string());
        assert!(sel.matches(&[], &["dba-team".to_string()], "x", false));
        assert!(!sel.matches(&[], &["dev".to_string()], "x", false));
    }

    #[test]
    fn matches_user() {
        let sel = Selector::User("alice".to_string());
        assert!(sel.matches(&[], &[], "alice", false));
        assert!(!sel.matches(&[], &[], "bob", false));
    }

    #[test]
    fn matches_requester() {
        let sel = Selector::Requester;
        assert!(sel.matches(&[], &[], "x", true));
        assert!(!sel.matches(&[], &[], "x", false));
    }
}
