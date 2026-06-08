validated_newtype! {
    /// Validated database name. 1-63 chars, `^[a-z][a-z0-9_-]*$` or `*` (wildcard).
    pub struct DatabaseName;
    max_len = 63,
    error_prefix = "database name",
    error_pattern = "[a-z0-9_-]"
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
        assert!(DatabaseName::new("a".repeat(64)).is_err());
    }

    #[test]
    fn wildcard() {
        let w = DatabaseName::wildcard();
        assert!(w.is_wildcard());
    }
}
