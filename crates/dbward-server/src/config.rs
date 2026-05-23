// Re-export all config types from dbward-config.
pub use dbward_config::ConfigError;
pub use dbward_config::ServerConfig;
pub use dbward_config::server::*;

// ---------------------------------------------------------------------------
// Domain conversion extensions (server-only, depends on dbward-domain)
// ---------------------------------------------------------------------------

use dbward_domain::services::sql_reviewer::{ReviewRules, RuleAction};
use dbward_domain::services::workflow_matcher::AutoApproveEntry;
use dbward_domain::values::{DatabaseName, Environment};

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

pub trait AutoApproveExt {
    fn to_entry(&self) -> Result<AutoApproveEntry, String>;
}

impl AutoApproveExt for AutoApproveConfig {
    fn to_entry(&self) -> Result<AutoApproveEntry, String> {
        use dbward_domain::services::risk_scorer::RiskLevel;

        let database = DatabaseName::new(&self.database)
            .map_err(|e| format!("auto_approve: invalid database '{}': {e}", self.database))?;
        let environment = Environment::new(&self.environment).map_err(|e| {
            format!(
                "auto_approve: invalid environment '{}': {e}",
                self.environment
            )
        })?;
        let max_risk_level = match self.risk.as_str() {
            "none" => None,
            "low" => Some(RiskLevel::Low),
            "medium" => Some(RiskLevel::Medium),
            "high" => Some(RiskLevel::High),
            other => {
                return Err(format!(
                    "auto_approve: invalid risk '{}' (expected none/low/medium/high)",
                    other
                ));
            }
        };
        Ok(AutoApproveEntry {
            database,
            environment,
            max_risk_level,
            allow_safe_ddl: self.allow_safe_ddl,
            allow_read_only: self.allow_read_only,
            max_estimated_rows: self.max_estimated_rows,
        })
    }
}
