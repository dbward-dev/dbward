use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyConfig {
    #[serde(default = "default_action")]
    pub default: String,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyRule {
    #[serde(default)]
    pub environments: Vec<String>,
    #[serde(default)]
    pub operations: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    pub action: String,
}

fn default_action() -> String {
    "require_approval".into()
}

impl Default for PolicyConfig {
    fn default() -> Self {
        // Matches the previous hardcoded behavior
        Self {
            default: "require_approval".into(),
            rules: vec![
                PolicyRule {
                    environments: vec![],
                    operations: vec!["migrate_status".into(), "audit_search".into()],
                    roles: vec![],
                    action: "auto_approve".into(),
                },
                PolicyRule {
                    environments: vec!["production".into()],
                    operations: vec![],
                    roles: vec![],
                    action: "require_approval".into(),
                },
                PolicyRule {
                    environments: vec![],
                    operations: vec![],
                    roles: vec![],
                    action: "auto_approve".into(),
                },
            ],
        }
    }
}

impl PolicyConfig {
    /// Evaluate policy for a request. Returns "auto_approve" or "require_approval".
    pub fn evaluate(&self, environment: &str, operation: &str, role: &str) -> &str {
        for rule in &self.rules {
            if self.rule_matches(rule, environment, operation, role) {
                return &rule.action;
            }
        }
        &self.default
    }

    fn rule_matches(
        &self,
        rule: &PolicyRule,
        environment: &str,
        operation: &str,
        role: &str,
    ) -> bool {
        let env_ok =
            rule.environments.is_empty() || rule.environments.iter().any(|e| e == environment);
        let op_ok = rule.operations.is_empty() || rule.operations.iter().any(|o| o == operation);
        let role_ok = rule.roles.is_empty() || rule.roles.iter().any(|r| r == role);
        env_ok && op_ok && role_ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_matches_hardcoded_behavior() {
        let p = PolicyConfig::default();
        // production + mutating → require_approval
        assert_eq!(
            p.evaluate("production", "execute_query", "developer"),
            "require_approval"
        );
        assert_eq!(
            p.evaluate("production", "migrate_up", "developer"),
            "require_approval"
        );
        // production + read-only → auto_approve
        assert_eq!(
            p.evaluate("production", "migrate_status", "developer"),
            "auto_approve"
        );
        assert_eq!(
            p.evaluate("production", "audit_search", "admin"),
            "auto_approve"
        );
        // non-production → auto_approve
        assert_eq!(
            p.evaluate("staging", "execute_query", "developer"),
            "auto_approve"
        );
        assert_eq!(
            p.evaluate("development", "migrate_up", "admin"),
            "auto_approve"
        );
    }

    #[test]
    fn custom_policy_staging_requires_approval() {
        let p = PolicyConfig {
            default: "require_approval".into(),
            rules: vec![PolicyRule {
                environments: vec!["development".into()],
                operations: vec![],
                roles: vec![],
                action: "auto_approve".into(),
            }],
        };
        assert_eq!(
            p.evaluate("development", "execute_query", "developer"),
            "auto_approve"
        );
        assert_eq!(
            p.evaluate("staging", "execute_query", "developer"),
            "require_approval"
        );
        assert_eq!(
            p.evaluate("production", "execute_query", "developer"),
            "require_approval"
        );
    }

    #[test]
    fn role_scoped_rule() {
        let p = PolicyConfig {
            default: "require_approval".into(),
            rules: vec![PolicyRule {
                environments: vec!["staging".into()],
                operations: vec![],
                roles: vec!["admin".into()],
                action: "auto_approve".into(),
            }],
        };
        assert_eq!(
            p.evaluate("staging", "execute_query", "admin"),
            "auto_approve"
        );
        assert_eq!(
            p.evaluate("staging", "execute_query", "developer"),
            "require_approval"
        );
    }

    #[test]
    fn first_match_wins() {
        let p = PolicyConfig {
            default: "require_approval".into(),
            rules: vec![
                PolicyRule {
                    environments: vec!["production".into()],
                    operations: vec!["migrate_status".into()],
                    roles: vec![],
                    action: "auto_approve".into(),
                },
                PolicyRule {
                    environments: vec!["production".into()],
                    operations: vec![],
                    roles: vec![],
                    action: "require_approval".into(),
                },
            ],
        };
        assert_eq!(
            p.evaluate("production", "migrate_status", "developer"),
            "auto_approve"
        );
        assert_eq!(
            p.evaluate("production", "execute_query", "developer"),
            "require_approval"
        );
    }

    #[test]
    fn deserialize_from_toml() {
        let toml = r#"
            default = "auto_approve"

            [[rules]]
            environments = ["production"]
            action = "require_approval"
        "#;
        let p: PolicyConfig = toml::from_str(toml).unwrap();
        assert_eq!(
            p.evaluate("production", "execute_query", "developer"),
            "require_approval"
        );
        assert_eq!(
            p.evaluate("staging", "execute_query", "developer"),
            "auto_approve"
        );
    }
}
