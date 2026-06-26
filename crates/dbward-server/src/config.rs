// Re-export all config types from dbward-config.
pub use dbward_config::ConfigError;
pub use dbward_config::ServerConfig;
pub use dbward_config::server::*;

// ---------------------------------------------------------------------------
// Domain conversion extensions (server-only, depends on dbward-domain)
// ---------------------------------------------------------------------------

use dbward_domain::services::sql_reviewer::{ReviewRules, RuleAction};

pub trait SqlReviewExt {
    fn to_review_rules(&self) -> Result<ReviewRules, String>;
}

impl SqlReviewExt for SqlReviewConfig {
    fn to_review_rules(&self) -> Result<ReviewRules, String> {
        fn parse_action(s: &str, field: &str) -> Result<RuleAction, String> {
            match s {
                "block" => Ok(RuleAction::Block),
                "warn" => Ok(RuleAction::Warn),
                "off" => Ok(RuleAction::Off),
                other => Err(format!(
                    "sql_review.{field}: invalid action '{other}' (expected block/warn/off)"
                )),
            }
        }
        Ok(ReviewRules {
            no_where_delete: parse_action(&self.no_where_delete, "no_where_delete")?,
            no_where_update: parse_action(&self.no_where_update, "no_where_update")?,
            drop_table: parse_action(&self.drop_table, "drop_table")?,
            drop_column: parse_action(&self.drop_column, "drop_column")?,
            not_null_without_default: parse_action(
                &self.not_null_without_default,
                "not_null_without_default",
            )?,
            create_index_not_concurrently: parse_action(
                &self.create_index_not_concurrently,
                "create_index_not_concurrently",
            )?,
            alter_column_type: parse_action(&self.alter_column_type, "alter_column_type")?,
            truncate: parse_action(&self.truncate, "truncate")?,
            mixed_ddl_dml: parse_action(&self.mixed_ddl_dml, "mixed_ddl_dml")?,
            large_in_list: parse_action(&self.large_in_list, "large_in_list")?,
        })
    }
}
