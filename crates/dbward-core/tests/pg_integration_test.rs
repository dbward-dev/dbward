//! PostgreSQL integration tests: type mapping, result limits, multi-statement, error handling.
//! All tests require Docker and are marked #[ignore].

use std::sync::Arc;

use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;

use dbward_core::driver::{self, DEFAULT_MAX_RESULT_ROWS, DatabaseDriver};

async fn setup() -> (
    testcontainers::ContainerAsync<Postgres>,
    Arc<dyn DatabaseDriver>,
) {
    let container = Postgres::default().start().await.unwrap();
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
    let drv = driver::connect(&url).await.unwrap();
    (container, drv)
}

// ─── Result size limits ───

#[tokio::test]
#[ignore]
async fn result_rows_capped_at_max() {
    let (_c, drv) = setup().await;
    let output = drv
        .query(&format!(
            "SELECT generate_series(1, {}) AS n",
            DEFAULT_MAX_RESULT_ROWS + 5000
        ))
        .await
        .unwrap();
    assert_eq!(output.rows.len(), DEFAULT_MAX_RESULT_ROWS);
    assert!(output.truncated);
    assert!(output.truncation_reason.unwrap().contains("row limit"));
}

#[tokio::test]
#[ignore]
async fn empty_result_returns_empty_array() {
    let (_c, drv) = setup().await;
    let rows = drv.query("SELECT 1 WHERE false").await.unwrap().rows;
    assert!(rows.is_empty());
}

// ─── Additional type mapping ───

#[tokio::test]
#[ignore]
async fn pg_null_values() {
    let (_c, drv) = setup().await;
    let rows = drv
        .query("SELECT NULL::int AS n, NULL::text AS t")
        .await
        .unwrap()
        .rows;
    assert!(rows[0]["n"].is_null());
    assert!(rows[0]["t"].is_null());
}

#[tokio::test]
#[ignore]
async fn pg_array_type_as_string() {
    let (_c, drv) = setup().await;
    let rows = drv
        .query("SELECT ARRAY[1,2,3]::int[] AS arr")
        .await
        .unwrap()
        .rows;
    // Arrays fall through to String fallback
    assert!(rows[0]["arr"].is_string());
}

#[tokio::test]
#[ignore]
async fn pg_boolean_type() {
    let (_c, drv) = setup().await;
    let rows = drv
        .query("SELECT true AS t, false AS f")
        .await
        .unwrap()
        .rows;
    assert_eq!(rows[0]["t"], true);
    assert_eq!(rows[0]["f"], false);
}

#[tokio::test]
#[ignore]
async fn pg_inet_type_as_string() {
    let (_c, drv) = setup().await;
    let rows = drv
        .query("SELECT '192.168.1.1'::inet AS ip")
        .await
        .unwrap()
        .rows;
    assert!(rows[0]["ip"].is_string());
    assert!(rows[0]["ip"].as_str().unwrap().contains("192.168.1.1"));
}

// ─── Error handling ───

#[tokio::test]
#[ignore]
async fn syntax_error_returns_db_error() {
    let (_c, drv) = setup().await;
    let result = drv.query("SELECT FROM").await;
    assert!(result.is_err());
}

#[tokio::test]
#[ignore]
async fn nonexistent_table_returns_error() {
    let (_c, drv) = setup().await;
    let result = drv.query("SELECT * FROM no_such_table_xyz").await;
    assert!(result.is_err());
}

// ─── Unicode ───

#[tokio::test]
#[ignore]
async fn unicode_data_roundtrip() {
    let (_c, drv) = setup().await;
    drv.execute("CREATE TABLE unicode_test (val TEXT)")
        .await
        .unwrap();
    drv.execute("INSERT INTO unicode_test VALUES ('日本語テスト 🎉')")
        .await
        .unwrap();
    let rows = drv
        .query("SELECT val FROM unicode_test")
        .await
        .unwrap()
        .rows;
    assert_eq!(rows[0]["val"].as_str().unwrap(), "日本語テスト 🎉");
}

// ─── Multi-statement (via execute) ───

#[tokio::test]
#[ignore]
async fn multi_statement_execute() {
    let (_c, drv) = setup().await;
    drv.execute("CREATE TABLE multi_test (id SERIAL, val TEXT)")
        .await
        .unwrap();
    let affected = drv
        .execute(
            "INSERT INTO multi_test (val) VALUES ('a'); INSERT INTO multi_test (val) VALUES ('b')",
        )
        .await
        .unwrap();
    // rows_affected may be 1 (last statement) or 2 depending on driver behavior
    assert!(affected >= 1);
    let rows = drv
        .query("SELECT COUNT(*)::int AS cnt FROM multi_test")
        .await
        .unwrap()
        .rows;
    assert_eq!(rows[0]["cnt"], 2);
}
