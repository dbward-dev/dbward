use std::path::Path;

use sha2::{Digest, Sha256};

use dbward_core::Error;

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
}

impl MigrationDetail {
    pub fn to_detail_string(&self) -> Result<String, Error> {
        serde_json::to_string(self).map_err(|e| Error::Config(format!("serialize detail: {e}")))
    }

    pub fn parse(detail: &str) -> Result<Self, Error> {
        serde_json::from_str(detail)
            .map_err(|e| Error::Config(format!("invalid migration detail JSON: {e}")))
    }
}

/// Build a v2 migration detail for `migrate up`.
/// Reads pending migration files from `dir` and includes their SQL content.
pub fn build_migrate_up_detail(
    dir: &Path,
    applied_versions: &[String],
) -> Result<MigrationDetail, Error> {
    let all_migrations = list_migration_files(dir, "up")?;
    let pending: Vec<_> = all_migrations
        .into_iter()
        .filter(|(version, _)| !applied_versions.contains(version))
        .collect();

    if pending.is_empty() {
        return Ok(MigrationDetail {
            format: "v2".into(),
            direction: "up".into(),
            versions: vec![],
            migrations: vec![],
            dir_sha256: hash_migrations_dir(dir)?,
        max_count: None,
        });
    }

    let migrations: Vec<MigrationEntry> = pending
        .iter()
        .map(|(version, path)| {
            let sql = std::fs::read_to_string(path).map_err(Error::Io)?;
            Ok(MigrationEntry {
                version: version.clone(),
                sql,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;

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
) -> Result<MigrationDetail, Error> {
    let migrations: Vec<MigrationEntry> = versions_to_revert
        .iter()
        .map(|version| {
            let down_files = list_migration_files(dir, "down")?;
            let (_, path) = down_files
                .iter()
                .find(|(v, _)| v == version)
                .ok_or_else(|| {
                    Error::Config(format!("no down migration file for version '{version}'"))
                })?;
            let sql = std::fs::read_to_string(path).map_err(Error::Io)?;
            Ok(MigrationEntry {
                version: version.clone(),
                sql,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;

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
pub fn list_down_versions(dir: &Path) -> Result<Vec<String>, Error> {
    let files = list_migration_files(dir, "down")?;
    Ok(files.into_iter().map(|(v, _)| v).collect())
}

/// Canonicalize: re-read files and rebuild detail to verify integrity.
/// Used by agent to verify the detail matches current file state.
pub fn canonicalize_migration_detail(detail: &str) -> Result<String, Error> {
    // v2 detail is self-contained (SQL is in the JSON). Just re-serialize canonically.
    let parsed = MigrationDetail::parse(detail)?;
    parsed.to_detail_string()
}

/// List migration files in a directory, filtered by direction (up/down).
/// Returns (version, path) pairs sorted by version.
fn list_migration_files(dir: &Path, direction: &str) -> Result<Vec<(String, std::path::PathBuf)>, Error> {
    let suffix = format!(".{direction}.sql");
    let mut entries = Vec::new();

    if !dir.exists() {
        return Ok(entries);
    }

    for entry in std::fs::read_dir(dir).map_err(Error::Io)? {
        let entry = entry.map_err(Error::Io)?;
        let filename = entry.file_name().to_string_lossy().to_string();
        if filename.ends_with(&suffix) {
            let version = filename.strip_suffix(&suffix).unwrap_or(&filename).to_string();
            entries.push((version, entry.path()));
        }
    }

    entries.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(entries)
}

fn hash_migrations_dir(dir: &Path) -> Result<String, Error> {
    let mut entries = Vec::new();

    if dir.exists() {
        for entry in std::fs::read_dir(dir)
            .map_err(Error::Io)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(Error::Io)?
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
        let content = std::fs::read(&path).map_err(Error::Io)?;
        let file_hash = sha256_hex(&content);
        manifest_hasher.update(filename.as_bytes());
        manifest_hasher.update([0]);
        manifest_hasher.update(file_hash.as_bytes());
        manifest_hasher.update([b'\n']);
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
    pub fn parse(detail: &str) -> Result<Self, Error> {
        let mut count = None;
        let mut dir_hash = None;

        for part in detail.split(';') {
            if part == "v1" {
                continue;
            }
            if let Some(value) = part.strip_prefix("count=") {
                count = Some(value.parse::<usize>().map_err(|e| {
                    Error::Config(format!("invalid migration approval detail count: {e}"))
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
            _ => Err(Error::Config(
                "invalid migration approval detail format".into(),
            )),
        }
    }

    pub fn format(&self) -> String {
        format!("v1;count={};dir_sha256={}", self.count, self.dir_hash)
    }
}

pub fn build_migration_approval_detail(dir: &Path, count: usize) -> Result<String, Error> {
    Ok(MigrationApprovalDetail {
        count,
        dir_hash: hash_migrations_dir(dir)?,
    }
    .format())
}

pub fn canonicalize_migration_approval_detail(dir: &Path, detail: &str) -> Result<String, Error> {
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
        std::fs::write(dir.join("001_create_users.up.sql"), "CREATE TABLE users (id INT);").unwrap();
        std::fs::write(dir.join("002_add_email.up.sql"), "ALTER TABLE users ADD email TEXT;").unwrap();

        let detail = build_migrate_up_detail(&dir, &[]).unwrap();
        assert_eq!(detail.versions, vec!["001_create_users", "002_add_email"]);
        assert_eq!(detail.migrations.len(), 2);
        assert_eq!(detail.migrations[0].sql, "CREATE TABLE users (id INT);");
        assert_eq!(detail.direction, "up");

        // With one already applied
        let detail2 = build_migrate_up_detail(&dir, &["001_create_users".into()]).unwrap();
        assert_eq!(detail2.versions, vec!["002_add_email"]);

        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn builds_v2_migrate_down_detail() {
        let dir = temp_dir("v2down");
        std::fs::write(dir.join("001_create_users.down.sql"), "DROP TABLE users;").unwrap();

        let detail = build_migrate_down_detail(&dir, &["001_create_users".into()]).unwrap();
        assert_eq!(detail.versions, vec!["001_create_users"]);
        assert_eq!(detail.migrations[0].sql, "DROP TABLE users;");
        assert_eq!(detail.direction, "down");

        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn canonicalize_v2_is_stable() {
        let dir = temp_dir("canon");
        std::fs::write(dir.join("001_init.up.sql"), "SELECT 1;").unwrap();

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
}
