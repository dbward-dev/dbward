use std::sync::Arc;

use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;

use dbward_core::driver;
use dbward_core::{Engine, Environment};

async fn setup() -> (
    testcontainers::ContainerAsync<Postgres>,
    Arc<dyn driver::DatabaseDriver>,
    String,
) {
    let container = Postgres::default().start().await.unwrap();
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");

    let drv = driver::connect(&url).await.unwrap();

    (container, drv, "test".to_string())
}

#[tokio::test]
#[ignore]
async fn execute_select() {
    let (_container, drv, db_name) = setup().await;
    let mut engine = Engine::from_driver(drv, &db_name, Environment::Development);

    let result = engine
        .execute_query("test_user", "admin", "SELECT 1 AS num, 'hello' AS msg")
        .await
        .unwrap();

    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0]["num"], 1);
    assert_eq!(result.rows[0]["msg"], "hello");
}

#[tokio::test]
#[ignore]
async fn execute_dml() {
    let (_container, drv, db_name) = setup().await;
    // Create table via driver directly
    drv.execute("CREATE TABLE test_dml (id SERIAL, val TEXT)")
        .await
        .unwrap();

    let mut engine = Engine::from_driver(drv, &db_name, Environment::Development);
    let result = engine
        .execute_query(
            "test_user",
            "developer",
            "INSERT INTO test_dml (val) VALUES ('a'), ('b')",
        )
        .await
        .unwrap();

    assert_eq!(result.rows_affected, 2);
}

#[tokio::test]
#[ignore]
async fn readonly_cannot_dml() {
    let (_container, drv, db_name) = setup().await;
    let mut engine = Engine::from_driver(drv, &db_name, Environment::Development);

    let err = engine
        .execute_query("readonly_user", "readonly", "DELETE FROM nonexistent")
        .await;

    assert!(err.is_err());
}

#[tokio::test]
#[ignore]
async fn ddl_rejected() {
    let (_container, drv, db_name) = setup().await;
    let mut engine = Engine::from_driver(drv, &db_name, Environment::Development);

    let err = engine
        .execute_query("admin", "admin", "CREATE TABLE bad (id INT)")
        .await;

    assert!(err.is_err());
    assert!(err.unwrap_err().to_string().contains("DDL"));
}

#[tokio::test]
#[ignore]
async fn pg_type_mapping_timestamptz() {
    let (_container, drv, _) = setup().await;
    let rows = drv
        .query("SELECT '2024-01-15 10:30:00+00'::timestamptz AS ts")
        .await
        .unwrap();
    assert!(rows[0]["ts"].is_string());
    let ts = rows[0]["ts"].as_str().unwrap();
    assert!(ts.contains("2024-01-15"));
}

#[tokio::test]
#[ignore]
async fn pg_type_mapping_uuid() {
    let (_container, drv, _) = setup().await;
    let rows = drv
        .query("SELECT 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11'::uuid AS id")
        .await
        .unwrap();
    assert_eq!(
        rows[0]["id"].as_str().unwrap(),
        "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
    );
}

#[tokio::test]
#[ignore]
async fn pg_type_mapping_jsonb() {
    let (_container, drv, _) = setup().await;
    let rows = drv
        .query(r#"SELECT '{"key": "value"}'::jsonb AS data"#)
        .await
        .unwrap();
    assert_eq!(rows[0]["data"]["key"], "value");
}

#[tokio::test]
#[ignore]
async fn pg_type_mapping_date() {
    let (_container, drv, _) = setup().await;
    let rows = drv.query("SELECT '2024-06-15'::date AS d").await.unwrap();
    assert!(rows[0]["d"].as_str().unwrap().contains("2024-06-15"));
}

#[tokio::test]
#[ignore]
async fn pg_type_mapping_numeric_as_string() {
    let (_container, drv, _) = setup().await;
    let rows = drv.query("SELECT 123.456::numeric AS n").await.unwrap();
    // NUMERIC falls through to String fallback
    assert!(rows[0]["n"].is_string());
}

#[tokio::test]
async fn connect_rejects_unsupported_scheme() {
    let err = driver::connect("sqlite:///tmp/test.db").await;
    assert!(err.is_err());
}
