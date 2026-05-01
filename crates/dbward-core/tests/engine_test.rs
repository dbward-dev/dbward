use std::sync::Arc;

use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;

use dbward_core::{Config, DatabaseConfig, Engine, Environment, Role};
use dbward_core::driver;

async fn setup() -> (testcontainers::ContainerAsync<Postgres>, Arc<dyn driver::DatabaseDriver>, Config) {
    let container = Postgres::default().start().await.unwrap();
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");

    let drv = driver::connect(&url).await.unwrap();
    let config = Config {
        database: DatabaseConfig { url },
        environment: Environment::Development,
        role: Role::Admin,
        migrations_dir: "db/migrations".into(),
        server: None,
    };

    (container, drv, config)
}

#[tokio::test]
async fn execute_select() {
    let (_container, drv, config) = setup().await;
    let mut engine = Engine::from_driver(drv, config);

    let result = engine
        .execute_query("test_user", Role::Admin, "SELECT 1 AS num, 'hello' AS msg")
        .await
        .unwrap();

    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0]["num"], 1);
    assert_eq!(result.rows[0]["msg"], "hello");
}

#[tokio::test]
async fn execute_dml() {
    let (_container, drv, config) = setup().await;
    // Create table via driver directly
    drv.execute("CREATE TABLE test_dml (id SERIAL, val TEXT)").await.unwrap();

    let mut engine = Engine::from_driver(drv, config);
    let result = engine
        .execute_query(
            "test_user",
            Role::Developer,
            "INSERT INTO test_dml (val) VALUES ('a'), ('b')",
        )
        .await
        .unwrap();

    assert_eq!(result.rows_affected, 2);
}

#[tokio::test]
async fn readonly_cannot_dml() {
    let (_container, drv, config) = setup().await;
    let mut engine = Engine::from_driver(drv, config);

    let err = engine
        .execute_query("readonly_user", Role::Readonly, "DELETE FROM nonexistent")
        .await;

    assert!(err.is_err());
}

#[tokio::test]
async fn ddl_rejected() {
    let (_container, drv, config) = setup().await;
    let mut engine = Engine::from_driver(drv, config);

    let err = engine
        .execute_query("admin", Role::Admin, "CREATE TABLE bad (id INT)")
        .await;

    assert!(err.is_err());
    assert!(err.unwrap_err().to_string().contains("DDL"));
}
