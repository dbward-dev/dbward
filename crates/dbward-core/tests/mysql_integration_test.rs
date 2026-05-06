//! MySQL integration tests: basic operations, type mapping, migrations.
//! All tests require Docker and are marked #[ignore].

use std::sync::Arc;

use testcontainers::runners::AsyncRunner;
use testcontainers_modules::mysql::Mysql;

use dbward_core::driver::{self, DatabaseDriver};

async fn setup() -> (
    testcontainers::ContainerAsync<Mysql>,
    Arc<dyn DatabaseDriver>,
) {
    let container = Mysql::default().start().await.unwrap();
    let port = container.get_host_port_ipv4(3306).await.unwrap();
    let url = format!("mysql://root@127.0.0.1:{port}/mysql");
    let drv = driver::connect(&url).await.unwrap();
    (container, drv)
}

// ─── Basic operations ───

#[tokio::test]
#[ignore]
async fn mysql_select() {
    let (_c, drv) = setup().await;
    let rows = drv.query("SELECT 1 AS num, 'hello' AS msg").await.unwrap().rows;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["num"], 1);
    assert_eq!(rows[0]["msg"], "hello");
}

#[tokio::test]
#[ignore]
async fn mysql_dml() {
    let (_c, drv) = setup().await;
    drv.execute("CREATE TABLE test_dml (id INT AUTO_INCREMENT PRIMARY KEY, val VARCHAR(255))")
        .await
        .unwrap();
    let affected = drv
        .execute("INSERT INTO test_dml (val) VALUES ('a'), ('b')")
        .await
        .unwrap();
    assert_eq!(affected, 2);
}

// ─── Type mapping ───

#[tokio::test]
#[ignore]
async fn mysql_int_types() {
    let (_c, drv) = setup().await;
    let rows = drv
        .query("SELECT CAST(1 AS SIGNED) AS i, CAST(9999999999 AS SIGNED) AS big")
        .await
        .unwrap().rows;
    assert!(rows[0]["i"].is_number());
    assert!(rows[0]["big"].is_number());
}

#[tokio::test]
#[ignore]
async fn mysql_float_types() {
    let (_c, drv) = setup().await;
    let rows = drv
        .query("SELECT CAST(3.14 AS DOUBLE) AS d")
        .await
        .unwrap().rows;
    assert!(rows[0]["d"].is_number());
}

#[tokio::test]
#[ignore]
async fn mysql_null_values() {
    let (_c, drv) = setup().await;
    let rows = drv
        .query("SELECT NULL AS n")
        .await
        .unwrap().rows;
    assert!(rows[0]["n"].is_null());
}

#[tokio::test]
#[ignore]
async fn mysql_datetime_as_string() {
    let (_c, drv) = setup().await;
    let rows = drv
        .query("SELECT NOW() AS ts, CURDATE() AS d")
        .await
        .unwrap().rows;
    assert!(rows[0]["ts"].is_string());
    assert!(rows[0]["d"].is_string());
}

// ─── Migrations ───

#[tokio::test]
#[ignore]
async fn mysql_migrations_up_and_status() {
    let (_c, drv) = setup().await;
    use dbward_migrate::Migrator;
    use std::path::PathBuf;

    // Create a temp migration dir with MySQL-compatible SQL
    let dir = tempfile::tempdir().unwrap();
    let mig_path = dir.path().join("20260101000000_create_test.sql");
    std::fs::write(
        &mig_path,
        "-- migrate:up\nCREATE TABLE test_mig (id INT PRIMARY KEY);\n\n-- migrate:down\nDROP TABLE test_mig;\n",
    ).unwrap();

    let migrator = Migrator::new(drv.clone(), dir.path().to_path_buf());
    let status = migrator.status().await.unwrap();
    assert_eq!(status.len(), 1);
    assert!(!status[0].applied);

    let result = migrator.up(None).await.unwrap();
    assert_eq!(result.applied.len(), 1);

    let status = migrator.status().await.unwrap();
    assert!(status[0].applied);

    // Verify table exists
    let rows = drv.query("SELECT COUNT(*) AS cnt FROM test_mig").await.unwrap().rows;
    assert_eq!(rows[0]["cnt"], 0);
}
