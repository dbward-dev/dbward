use std::collections::HashSet;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::MigrateError;

/// v2 migration detail: version list + SQL content as JSON.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MigrationDetail {
    pub format: String,
    pub direction: String,
    pub versions: Vec<String>,
    pub migrations: Vec<MigrationEntry>,
    pub dir_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_count: Option<usize>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MigrationEntry {
    pub version: String,
    pub sql: String,
    #[serde(default = "default_true")]
    pub transactional: bool,
}

fn default_true() -> bool {
    true
}

impl MigrationDetail {
    pub fn to_detail_string(&self) -> Result<String, MigrateError> {
        serde_json::to_string(self)
            .map_err(|e| MigrateError::Config(format!("serialize detail: {e}")))
    }

    pub fn parse(detail: &str) -> Result<Self, MigrateError> {
        serde_json::from_str(detail)
            .map_err(|e| MigrateError::Config(format!("invalid migration detail JSON: {e}")))
    }
}

/// Build a v2 migration detail for `migrate up`.
/// Reads pending migration files from `dir` and includes their SQL content.
pub fn build_migrate_up_detail(
    dir: &Path,
    applied_versions: &[String],
) -> Result<MigrationDetail, MigrateError> {
    let all_migrations = crate::parser::parse_migrations_dir(dir)?;
    let applied_set: HashSet<&str> = applied_versions.iter().map(|s| s.as_str()).collect();
    let pending: Vec<_> = all_migrations
        .into_iter()
        .filter(|m| !applied_set.contains(m.version.as_str()))
        .collect();

    let migrations: Vec<MigrationEntry> = pending
        .iter()
        .map(|m| MigrationEntry {
            version: m.version.clone(),
            sql: m.up_sql.clone(),
            transactional: m.up_transactional,
        })
        .collect();

    let versions = migrations.iter().map(|m| m.version.clone()).collect();

    Ok(MigrationDetail {
        format: "v2".into(),
        direction: "up".into(),
        versions,
        migrations,
        dir_sha256: hash_migrations_dir(dir)?,
        max_count: None,
    })
}

/// Build a v2 migration detail for `migrate down`.
pub fn build_migrate_down_detail(
    dir: &Path,
    versions_to_revert: &[String],
) -> Result<MigrationDetail, MigrateError> {
    let all_migrations = crate::parser::parse_migrations_dir(dir)?;
    let migrations: Vec<MigrationEntry> = versions_to_revert
        .iter()
        .map(|version| {
            let m = all_migrations
                .iter()
                .find(|m| m.version == *version)
                .ok_or_else(|| {
                    MigrateError::Config(format!("no migration file for version '{version}'"))
                })?;
            let sql = m.down_sql.as_ref().ok_or_else(|| {
                MigrateError::Config(format!(
                    "no down migration SQL for version '{version}' (missing -- migrate:down marker)"
                ))
            })?;
            Ok(MigrationEntry {
                version: version.clone(),
                sql: sql.clone(),
                transactional: m.down_transactional,
            })
        })
        .collect::<Result<Vec<_>, MigrateError>>()?;

    let versions = migrations.iter().map(|m| m.version.clone()).collect();

    Ok(MigrationDetail {
        format: "v2".into(),
        direction: "down".into(),
        versions,
        migrations,
        dir_sha256: hash_migrations_dir(dir)?,
        max_count: None,
    })
}

/// List all available down migration versions (sorted).
pub fn list_down_versions(dir: &Path) -> Result<Vec<String>, MigrateError> {
    let migrations = crate::parser::parse_migrations_dir(dir)?;
    Ok(migrations
        .into_iter()
        .filter(|m| m.down_sql.is_some())
        .map(|m| m.version)
        .collect())
}

/// Canonicalize: re-read files and rebuild detail to verify integrity.
/// Used by agent to verify the detail matches current file state.
pub fn canonicalize_migration_detail(detail: &str) -> Result<String, MigrateError> {
    // v2 detail is self-contained (SQL is in the JSON). Just re-serialize canonically.
    let parsed = MigrationDetail::parse(detail)?;
    parsed.to_detail_string()
}

fn hash_migrations_dir(dir: &Path) -> Result<String, MigrateError> {
    let mut entries = Vec::new();

    if dir.exists() {
        for entry in std::fs::read_dir(dir)
            .map_err(MigrateError::Io)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(MigrateError::Io)?
        {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "sql") {
                entries.push((entry.file_name().to_string_lossy().to_string(), path));
            }
        }
    }

    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut manifest_hasher = Sha256::new();
    for (filename, path) in entries {
        let content = std::fs::read(&path).map_err(MigrateError::Io)?;
        let file_hash = sha256_hex(&content);
        manifest_hasher.update(filename.as_bytes());
        manifest_hasher.update([0]);
        manifest_hasher.update(file_hash.as_bytes());
        manifest_hasher.update(*b"\n");
    }

    Ok(format!("{:x}", manifest_hasher.finalize()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

// Keep legacy support for parsing old v1 format (used only in tests/transition)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationApprovalDetail {
    pub count: usize,
    pub dir_hash: String,
}

impl MigrationApprovalDetail {
    pub fn parse(detail: &str) -> Result<Self, MigrateError> {
        let mut count = None;
        let mut dir_hash = None;

        for part in detail.split(';') {
            if part == "v1" {
                continue;
            }
            if let Some(value) = part.strip_prefix("count=") {
                count = Some(value.parse::<usize>().map_err(|e| {
                    MigrateError::Config(format!("invalid migration approval detail count: {e}"))
                })?);
                continue;
            }
            if let Some(value) = part.strip_prefix("dir_sha256=") {
                dir_hash = Some(value.to_string());
                continue;
            }
        }

        match (count, dir_hash) {
            (Some(count), Some(dir_hash)) if !dir_hash.is_empty() => Ok(Self { count, dir_hash }),
            _ => Err(MigrateError::Config(
                "invalid migration approval detail format".into(),
            )),
        }
    }

    pub fn format(&self) -> String {
        format!("v1;count={};dir_sha256={}", self.count, self.dir_hash)
    }
}

pub fn build_migration_approval_detail(dir: &Path, count: usize) -> Result<String, MigrateError> {
    Ok(MigrationApprovalDetail {
        count,
        dir_hash: hash_migrations_dir(dir)?,
    }
    .format())
}

pub fn canonicalize_migration_approval_detail(
    dir: &Path,
    detail: &str,
) -> Result<String, MigrateError> {
    // Try v2 JSON first
    if detail.starts_with('{') {
        return canonicalize_migration_detail(detail);
    }
    // Legacy v1
    let parsed = MigrationApprovalDetail::parse(detail)?;
    build_migration_approval_detail(dir, parsed.count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let unique = format!(
            "dbward-migrate-approval-{name}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn builds_v2_migrate_up_detail() {
        let dir = temp_dir("v2up");
        std::fs::write(
            dir.join("20260501120000_create_users.sql"),
            "-- migrate:up\nCREATE TABLE users (id INT);\n\n-- migrate:down\nDROP TABLE users;\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("20260502120000_add_email.sql"),
            "-- migrate:up\nALTER TABLE users ADD email TEXT;\n\n-- migrate:down\nALTER TABLE users DROP COLUMN email;\n",
        )
        .unwrap();

        let detail = build_migrate_up_detail(&dir, &[]).unwrap();
        assert_eq!(detail.versions, vec!["20260501120000", "20260502120000"]);
        assert_eq!(detail.migrations.len(), 2);
        assert_eq!(detail.migrations[0].sql, "CREATE TABLE users (id INT);");
        assert_eq!(detail.direction, "up");

        // With one already applied
        let detail2 = build_migrate_up_detail(&dir, &["20260501120000".into()]).unwrap();
        assert_eq!(detail2.versions, vec!["20260502120000"]);

        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn builds_v2_migrate_down_detail() {
        let dir = temp_dir("v2down");
        std::fs::write(
            dir.join("20260501120000_create_users.sql"),
            "-- migrate:up\nCREATE TABLE users (id INT);\n\n-- migrate:down\nDROP TABLE users;\n",
        )
        .unwrap();

        let detail = build_migrate_down_detail(&dir, &["20260501120000".into()]).unwrap();
        assert_eq!(detail.versions, vec!["20260501120000"]);
        assert_eq!(detail.migrations[0].sql, "DROP TABLE users;");
        assert_eq!(detail.direction, "down");

        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn down_detail_errors_when_no_down_sql() {
        let dir = temp_dir("v2down-nodown");
        std::fs::write(
            dir.join("20260501120000_init.sql"),
            "-- migrate:up\nCREATE TABLE t (id INT);\n",
        )
        .unwrap();

        let err = build_migrate_down_detail(&dir, &["20260501120000".into()]).unwrap_err();
        assert!(err.to_string().contains("no down migration SQL"));

        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn list_down_versions_single_file() {
        let dir = temp_dir("v2downlist");
        std::fs::write(
            dir.join("20260501120000_create_users.sql"),
            "-- migrate:up\nCREATE TABLE users (id INT);\n\n-- migrate:down\nDROP TABLE users;\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("20260502120000_no_down.sql"),
            "-- migrate:up\nINSERT INTO t VALUES (1);\n",
        )
        .unwrap();

        let versions = list_down_versions(&dir).unwrap();
        assert_eq!(versions, vec!["20260501120000"]);

        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn canonicalize_v2_is_stable() {
        let dir = temp_dir("canon");
        std::fs::write(
            dir.join("20260501120000_init.sql"),
            "-- migrate:up\nSELECT 1;\n",
        )
        .unwrap();

        let detail = build_migrate_up_detail(&dir, &[]).unwrap();
        let json = detail.to_detail_string().unwrap();
        let canonical = canonicalize_migration_detail(&json).unwrap();
        assert_eq!(json, canonical);

        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn legacy_v1_still_parses() {
        let dir = temp_dir("legacy");
        std::fs::write(dir.join("001.sql"), "SELECT 1;").unwrap();

        let detail = build_migration_approval_detail(&dir, 2).unwrap();
        let parsed = MigrationApprovalDetail::parse(&detail).unwrap();
        assert_eq!(parsed.count, 2);

        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn empty_dir_returns_empty_detail() {
        let dir = temp_dir("empty");
        let detail = build_migrate_up_detail(&dir, &[]).unwrap();
        assert!(detail.versions.is_empty());
        assert!(detail.migrations.is_empty());
        std::fs::remove_dir_all(dir).ok();
    }
}
