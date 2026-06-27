use crate::services::sql_reviewer::ReviewRules;
use crate::values::{DatabaseName, Environment};

#[derive(Debug, Clone)]
pub struct SqlReviewPolicy {
    pub id: String,
    pub database: DatabaseName,
    pub environment: Environment,
    pub rules: ReviewRules,
    /// "config" | "builtin"
    pub source: String,
}

impl Default for SqlReviewPolicy {
    fn default() -> Self {
        Self {
            id: "builtin-default".into(),
            database: DatabaseName::wildcard(),
            environment: Environment::wildcard(),
            rules: ReviewRules::default(),
            source: "builtin".into(),
        }
    }
}
