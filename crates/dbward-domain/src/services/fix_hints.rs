//! Generates actionable fix hints from review findings and risk assessment.
//! Pure function — no side effects, no I/O.

use super::risk_scorer::RiskLevel;
use super::sql_reviewer::{Finding, RuleId};

/// Generate human-readable fix hints for AI consumers.
/// Each hint is a short instruction describing how to fix or mitigate the issue.
pub fn generate(findings: &[Finding], risk_level: RiskLevel) -> Vec<String> {
    let mut hints: Vec<String> = findings.iter().map(|f| hint_for_rule(f.rule)).collect();

    // Risk-based hints (only if not already covered by rule hints)
    match risk_level {
        RiskLevel::Critical | RiskLevel::High => {
            hints.push(
                "For production writes, include --reason with expected impact".to_string(),
            );
        }
        RiskLevel::Unknown => {
            hints.push(
                "Schema information is unavailable; verify table existence before submitting"
                    .to_string(),
            );
        }
        _ => {}
    }

    hints.dedup();
    hints
}

fn hint_for_rule(rule: RuleId) -> String {
    match rule {
        RuleId::NoWhereDelete => {
            "Add a WHERE clause to limit the rows affected by DELETE".to_string()
        }
        RuleId::NoWhereUpdate => {
            "Add a WHERE clause using an indexed column to limit the rows affected by UPDATE"
                .to_string()
        }
        RuleId::DropTable => {
            "Confirm table removal is intentional; consider renaming instead of dropping"
                .to_string()
        }
        RuleId::DropColumn => {
            "Verify no application code references this column before dropping".to_string()
        }
        RuleId::NotNullWithoutDefault => {
            "Add a DEFAULT value or make the column nullable to avoid blocking writes".to_string()
        }
        RuleId::CreateIndexNotConcurrently => {
            "Use CREATE INDEX CONCURRENTLY to avoid locking the table during index creation"
                .to_string()
        }
        RuleId::AlterColumnType => {
            "Prefer adding a new column + migrating data over altering the type in-place"
                .to_string()
        }
        RuleId::Truncate => {
            "Consider using DELETE with a WHERE clause for selective removal instead of TRUNCATE"
                .to_string()
        }
        RuleId::MixedDdlDml => {
            "Split DDL and DML into separate statements to avoid implicit commits".to_string()
        }
        RuleId::LargeInList => {
            "Replace large IN list with a JOIN against a temporary table or use a subquery"
                .to_string()
        }
        RuleId::ParseFailure => {
            "Fix SQL syntax errors; the statement could not be parsed".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::sql_reviewer::RuleAction;

    fn finding(rule: RuleId) -> Finding {
        Finding {
            rule,
            action: RuleAction::Block,
            message: String::new(),
            statement_index: 0,
        }
    }

    #[test]
    fn all_rules_produce_hints() {
        let rules = [
            RuleId::NoWhereDelete,
            RuleId::NoWhereUpdate,
            RuleId::DropTable,
            RuleId::DropColumn,
            RuleId::NotNullWithoutDefault,
            RuleId::CreateIndexNotConcurrently,
            RuleId::AlterColumnType,
            RuleId::Truncate,
            RuleId::MixedDdlDml,
            RuleId::LargeInList,
            RuleId::ParseFailure,
        ];
        for rule in rules {
            let hint = hint_for_rule(rule);
            assert!(!hint.is_empty(), "empty hint for {:?}", rule);
        }
    }

    #[test]
    fn generate_includes_risk_hint_for_critical() {
        let findings = vec![finding(RuleId::NoWhereUpdate)];
        let hints = generate(&findings, RiskLevel::Critical);
        assert!(hints.len() >= 2);
        assert!(hints.iter().any(|h| h.contains("--reason")));
    }

    #[test]
    fn generate_includes_risk_hint_for_unknown() {
        let hints = generate(&[], RiskLevel::Unknown);
        assert!(hints.iter().any(|h| h.contains("Schema information")));
    }

    #[test]
    fn generate_empty_for_low_risk_no_findings() {
        let hints = generate(&[], RiskLevel::Low);
        assert!(hints.is_empty());
    }

    #[test]
    fn generate_deduplicates() {
        let findings = vec![
            finding(RuleId::NoWhereUpdate),
            finding(RuleId::NoWhereUpdate),
        ];
        let hints = generate(&findings, RiskLevel::Low);
        // dedup only removes consecutive duplicates, but same rule → same hint → consecutive
        let unique: std::collections::HashSet<_> = hints.iter().collect();
        assert_eq!(hints.len(), unique.len());
    }
}
