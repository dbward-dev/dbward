use std::path::Path;

use serde::Serialize;

use crate::error::MigrateError;

/// A parsed migration file (dbmate-compatible format).
#[derive(Debug, Clone, Serialize)]
pub struct Migration {
    pub version: String,
    pub name: String,
    pub up_sql: String,
    pub down_sql: Option<String>,
}

/// Parse migration files from a directory.
/// Expected filename: `YYYYMMDDHHMMSS_name.sql`
/// Expected content markers: `-- migrate:up` and `-- migrate:down`
pub fn parse_migrations_dir(dir: &Path) -> Result<Vec<Migration>, MigrateError> {
    let mut migrations = Vec::new();

    if !dir.exists() {
        return Ok(migrations);
    }

    let mut entries: Vec<_> = std::fs::read_dir(dir)?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "sql"))
        .collect();

    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let filename = entry.file_name().to_string_lossy().to_string();
        let content = std::fs::read_to_string(entry.path())?;

        if let Some(migration) = parse_migration_file(&filename, &content) {
            migrations.push(migration);
        }
    }

    Ok(migrations)
}

fn parse_migration_file(filename: &str, content: &str) -> Option<Migration> {
    let stem = filename.strip_suffix(".sql")?;
    let (version, name) = stem.split_once('_')?;

    let up_marker = "-- migrate:up";
    let down_marker = "-- migrate:down";

    let up_start = content.find(up_marker)? + up_marker.len();

    let (up_sql, down_sql) = if let Some(down_pos) = content.find(down_marker) {
        let up = content[up_start..down_pos].trim().to_string();
        let down = content[down_pos + down_marker.len()..].trim().to_string();
        (up, if down.is_empty() { None } else { Some(down) })
    } else {
        (content[up_start..].trim().to_string(), None)
    };

    Some(Migration {
        version: version.to_string(),
        name: name.to_string(),
        up_sql,
        down_sql,
    })
}

/// Create a new migration file with the given name.
pub fn create_migration_file(dir: &Path, name: &str) -> Result<std::path::PathBuf, MigrateError> {
    std::fs::create_dir_all(dir)?;

    let timestamp = chrono::Utc::now().format("%Y%m%d%H%M%S");
    let filename = format!("{timestamp}_{name}.sql");
    let path = dir.join(&filename);

    let content = "-- migrate:up\n\n-- migrate:down\n";
    std::fs::write(&path, content)?;

    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_migration_file() {
        let content = "-- migrate:up\nCREATE TABLE users (id SERIAL);\n\n-- migrate:down\nDROP TABLE users;\n";
        let m = parse_migration_file("20260501120000_create_users.sql", content).unwrap();
        assert_eq!(m.version, "20260501120000");
        assert_eq!(m.name, "create_users");
        assert_eq!(m.up_sql, "CREATE TABLE users (id SERIAL);");
        assert_eq!(m.down_sql.as_deref(), Some("DROP TABLE users;"));
    }

    #[test]
    fn parses_up_only() {
        let content = "-- migrate:up\nCREATE TABLE t (id INT);\n";
        let m = parse_migration_file("20260501120000_init.sql", content).unwrap();
        assert_eq!(m.up_sql, "CREATE TABLE t (id INT);");
        assert!(m.down_sql.is_none());
    }

    #[test]
    fn rejects_invalid_filename() {
        assert!(parse_migration_file("bad.sql", "-- migrate:up\n").is_none());
    }

    #[test]
    fn rejects_missing_marker() {
        assert!(parse_migration_file("20260501_x.sql", "SELECT 1;").is_none());
    }

    #[test]
    fn parse_migrations_dir_skips_invalid_files() {
        let dir = std::env::temp_dir().join(format!(
            "dbward-parser-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        // Valid file
        std::fs::write(
            dir.join("20260501120000_valid.sql"),
            "-- migrate:up\nSELECT 1;\n",
        )
        .unwrap();
        // Invalid: no marker
        std::fs::write(dir.join("20260502120000_no_marker.sql"), "SELECT 2;\n").unwrap();
        // Invalid: bad filename
        std::fs::write(dir.join("bad.sql"), "-- migrate:up\nSELECT 3;\n").unwrap();
        // Non-sql file (ignored)
        std::fs::write(dir.join("README.md"), "hello").unwrap();

        let migrations = parse_migrations_dir(&dir).unwrap();
        assert_eq!(migrations.len(), 1);
        assert_eq!(migrations[0].version, "20260501120000");

        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn parse_migrations_dir_nonexistent_returns_empty() {
        let dir = std::path::Path::new("/tmp/dbward-nonexistent-dir-xyz");
        let migrations = parse_migrations_dir(dir).unwrap();
        assert!(migrations.is_empty());
    }
}
