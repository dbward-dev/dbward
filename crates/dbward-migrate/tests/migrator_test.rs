use std::path::PathBuf;

use sqlx::PgPool;
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;

use dbward_migrate::Migrator;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/migrations")
}

async fn setup() -> (testcontainers::ContainerAsync<Postgres>, PgPool) {
    let container = Postgres::default().start().await.unwrap();
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
    let pool = PgPool::connect(&url).await.unwrap();
    (container, pool)
}

#[tokio::test]
async fn migrate_up_and_status() {
    let (_container, pool) = setup().await;
    let migrator = Migrator::new(pool.clone(), fixtures_dir());

    // Status before migration
    let status = migrator.status().await.unwrap();
    assert_eq!(status.len(), 2);
    assert!(!status[0].applied);
    assert!(!status[1].applied);

    // Migrate up
    let result = migrator.up(None).await.unwrap();
    assert_eq!(result.applied.len(), 2);

    // Status after migration
    let status = migrator.status().await.unwrap();
    assert!(status[0].applied);
    assert!(status[1].applied);

    // Verify table exists
    let rows: Vec<(i32,)> = sqlx::query_as("SELECT COUNT(*)::int FROM users")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(rows[0].0, 0);
}

#[tokio::test]
async fn migrate_up_with_count() {
    let (_container, pool) = setup().await;
    let migrator = Migrator::new(pool, fixtures_dir());

    let result = migrator.up(Some(1)).await.unwrap();
    assert_eq!(result.applied.len(), 1);
    assert!(result.applied[0].contains("create_users"));

    let status = migrator.status().await.unwrap();
    assert!(status[0].applied);
    assert!(!status[1].applied);
}

#[tokio::test]
async fn migrate_down() {
    let (_container, pool) = setup().await;
    let migrator = Migrator::new(pool, fixtures_dir());

    migrator.up(None).await.unwrap();

    let result = migrator.down(Some(1)).await.unwrap();
    assert_eq!(result.rolled_back.len(), 1);
    assert!(result.rolled_back[0].contains("add_email_index"));

    let status = migrator.status().await.unwrap();
    assert!(status[0].applied);
    assert!(!status[1].applied);
}

#[tokio::test]
async fn migrate_idempotent() {
    let (_container, pool) = setup().await;
    let migrator = Migrator::new(pool, fixtures_dir());

    migrator.up(None).await.unwrap();
    let result = migrator.up(None).await.unwrap();
    assert_eq!(result.applied.len(), 0);
}
