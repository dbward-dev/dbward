validated_newtype! {
    /// Validated environment name. Same rules as DatabaseName.
    pub struct Environment;
    max_len = 63,
    error_prefix = "environment",
    error_pattern = "[a-z0-9_-]"
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
