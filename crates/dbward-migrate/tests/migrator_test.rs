use std::path::PathBuf;

use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;

use dbward_core::driver;
use dbward_migrate::Migrator;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/migrations")
}

async fn setup() -> (
    testcontainers::ContainerAsync<Postgres>,
    std::sync::Arc<dyn driver::DatabaseDriver>,
) {
    let container = Postgres::default().start().await.unwrap();
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
    let drv = driver::connect(&url).await.unwrap();
    (container, drv)
}

#[tokio::test]
#[ignore]
async fn migrate_up_and_status() {
    let (_container, drv) = setup().await;
    let migrator = Migrator::new(drv.clone(), fixtures_dir());

    let status = migrator.status().await.unwrap();
    assert_eq!(status.len(), 2);
    assert!(!status[0].applied);
    assert!(!status[1].applied);

    let result = migrator.up(None).await.unwrap();
    assert_eq!(result.applied.len(), 2);

    let status = migrator.status().await.unwrap();
    assert!(status[0].applied);
    assert!(status[1].applied);

    // Verify table exists via driver
    let rows = drv
        .query("SELECT COUNT(*)::int AS cnt FROM users")
        .await
        .unwrap().rows;
    assert_eq!(rows[0]["cnt"], 0);
}

#[tokio::test]
#[ignore]
async fn migrate_up_with_count() {
    let (_container, drv) = setup().await;
    let migrator = Migrator::new(drv, fixtures_dir());

    let result = migrator.up(Some(1)).await.unwrap();
    assert_eq!(result.applied.len(), 1);
    assert!(result.applied[0].contains("create_users"));

    let status = migrator.status().await.unwrap();
    assert!(status[0].applied);
    assert!(!status[1].applied);
}

#[tokio::test]
#[ignore]
async fn migrate_down() {
    let (_container, drv) = setup().await;
    let migrator = Migrator::new(drv, fixtures_dir());

    migrator.up(None).await.unwrap();

    let result = migrator.down(Some(1)).await.unwrap();
    assert_eq!(result.rolled_back.len(), 1);
    assert!(result.rolled_back[0].contains("add_email_index"));

    let status = migrator.status().await.unwrap();
    assert!(status[0].applied);
    assert!(!status[1].applied);
}

#[tokio::test]
#[ignore]
async fn migrate_idempotent() {
    let (_container, drv) = setup().await;
    let migrator = Migrator::new(drv, fixtures_dir());

    migrator.up(None).await.unwrap();
    let result = migrator.up(None).await.unwrap();
    assert_eq!(result.applied.len(), 0);
}
