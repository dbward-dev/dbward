use serde_json::Value;

use super::super::server::ElicitHandle;
use super::request::submit_and_wait;

pub(super) async fn handle_migrate_status(
    client: &crate::server_client::ServerClient,
    args: &Value,
    env: &str,
    db_name: &str,
    elicit: &ElicitHandle,
    client_supports_elicitation: bool,
) -> Result<String, String> {
    let db = args["database"].as_str().unwrap_or(db_name);
    submit_and_wait(
        client,
        "migrate_status",
        env,
        db,
        "",
        None,
        elicit,
        client_supports_elicitation,
    )
    .await
}

pub(super) async fn handle_migrate_up(
    client: &crate::server_client::ServerClient,
    args: &Value,
    env: &str,
    db_name: &str,
    migrations_dir: &std::path::Path,
    elicit: &ElicitHandle,
    client_supports_elicitation: bool,
) -> Result<String, String> {
    let count = args["count"].as_u64().map(|n| n as usize);
    let db = args["database"].as_str().unwrap_or(db_name);
    match dbward_migrate::build_migrate_up_detail(migrations_dir, &[]) {
        Ok(mut d) => {
            if d.migrations.is_empty() {
                if !migrations_dir.exists() {
                    Err(format!(
                        "migrations directory not found: {}",
                        migrations_dir.display()
                    ))
                } else {
                    let has_sql = std::fs::read_dir(migrations_dir)
                        .ok()
                        .map(|entries| {
                            entries
                                .filter_map(|e| e.ok())
                                .any(|e| e.path().extension().is_some_and(|ext| ext == "sql"))
                        })
                        .unwrap_or(false);
                    if has_sql {
                        Err(format!(
                            "found .sql files in {} but none matched the expected format. \
                             Expected: <timestamp>_<name>.sql with '-- migrate:up' marker.",
                            migrations_dir.display()
                        ))
                    } else {
                        Ok("No pending migrations found.".into())
                    }
                }
            } else {
                d.max_count = count.filter(|&c| c > 0);
                match d.to_detail_string() {
                    Ok(detail) => {
                        submit_and_wait(
                            client,
                            "migrate_up",
                            env,
                            db,
                            &detail,
                            args["reason"].as_str(),
                            elicit,
                            client_supports_elicitation,
                        )
                        .await
                    }
                    Err(e) => Err(e.to_string()),
                }
            }
        }
        Err(e) => Err(e.to_string()),
    }
}

pub(super) async fn handle_migrate_down(
    client: &crate::server_client::ServerClient,
    args: &Value,
    env: &str,
    db_name: &str,
    migrations_dir: &std::path::Path,
    elicit: &ElicitHandle,
    client_supports_elicitation: bool,
) -> Result<String, String> {
    let count = args["count"].as_u64().map(|n| n as usize);
    let db = args["database"].as_str().unwrap_or(db_name);
    match dbward_migrate::list_down_versions(migrations_dir) {
        Ok(all_down) => {
            if all_down.is_empty() {
                Ok("No migrations with down SQL found.".into())
            } else {
                match dbward_migrate::build_migrate_down_detail(migrations_dir, &all_down) {
                    Ok(mut d) => {
                        d.max_count = Some(count.unwrap_or(1));
                        match d.to_detail_string() {
                            Ok(detail) => {
                                submit_and_wait(
                                    client,
                                    "migrate_down",
                                    env,
                                    db,
                                    &detail,
                                    args["reason"].as_str(),
                                    elicit,
                                    client_supports_elicitation,
                                )
                                .await
                            }
                            Err(e) => Err(e.to_string()),
                        }
                    }
                    Err(e) => Err(e.to_string()),
                }
            }
        }
        Err(e) => Err(e.to_string()),
    }
}

pub(super) fn handle_migrate_create(
    args: &Value,
    migrations_dir: &std::path::Path,
) -> Result<String, String> {
    let name = args["name"].as_str().unwrap_or("unnamed");
    let migrator = dbward_migrate::LocalMigrator::new(migrations_dir.to_path_buf());
    match migrator.create(name) {
        Ok(path) => Ok(format!("Created: {}", path.display())),
        Err(e) => Err(e.to_string()),
    }
}
