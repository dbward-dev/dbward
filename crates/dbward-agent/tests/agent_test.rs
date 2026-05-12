use dbward_agent::AgentConfig;

#[test]
fn config_parse_valid() {
    let toml = r#"
[server]
url = "https://server.example.com"
agent_token = "my-secret-token"

[databases.app.production]
url = "postgres://localhost:5432/app"

[databases.app.staging]
url = "postgres://localhost:5432/app_staging"
"#;
    let config = AgentConfig::from_toml(toml).unwrap();
    assert_eq!(config.server.url, "https://server.example.com");
    assert_eq!(config.max_concurrent_tasks(), 2);
    assert_eq!(config.poll_interval_ms(), 1000);
    assert!(config.databases.contains_key("app"));
}

#[test]
fn config_env_var_expansion() {
    unsafe { std::env::set_var("DBWARD_TEST_TOKEN", "expanded-token") };
    let toml = r#"
[server]
url = "http://localhost:8080"
agent_token = "${DBWARD_TEST_TOKEN}"

[databases.db.dev]
url = "postgres://localhost/test"
"#;
    let config = AgentConfig::from_toml(toml).unwrap();
    assert_eq!(config.server.agent_token, "expanded-token");
    unsafe { std::env::remove_var("DBWARD_TEST_TOKEN") };
}

#[test]
fn config_validation_bad_scheme() {
    let toml = r#"
[server]
url = "ftp://bad-scheme"
agent_token = "tok"

[databases.db.dev]
url = "postgres://localhost/x"
"#;
    let err = AgentConfig::from_toml(toml).unwrap_err();
    assert!(err.to_string().contains("http"));
}

#[test]
fn config_validation_no_databases() {
    let toml = r#"
[server]
url = "http://localhost:8080"
agent_token = "tok"

[databases]
"#;
    let err = AgentConfig::from_toml(toml).unwrap_err();
    assert!(err.to_string().contains("database"));
}
