use std::path::Path;

use sha2::{Digest, Sha256};

use dbward_core::Error;

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
    let parsed = MigrationApprovalDetail::parse(detail)?;
    build_migration_approval_detail(dir, parsed.count)
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
    fn builds_and_parses_detail() {
        let dir = temp_dir("builds");
        std::fs::write(dir.join("20260501120000_create_users.sql"), "-- migrate:up\nSELECT 1;\n")
            .unwrap();

        let detail = build_migration_approval_detail(&dir, 0).unwrap();
        let parsed = MigrationApprovalDetail::parse(&detail).unwrap();

        assert_eq!(parsed.count, 0);
        assert_eq!(detail, parsed.format());

        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn canonicalize_reflects_file_changes() {
        let dir = temp_dir("changes");
        let path = dir.join("20260501120000_create_users.sql");
        std::fs::write(&path, "-- migrate:up\nSELECT 1;\n").unwrap();

        let approved = build_migration_approval_detail(&dir, 2).unwrap();
        std::fs::write(&path, "-- migrate:up\nSELECT 2;\n").unwrap();

        let current = canonicalize_migration_approval_detail(&dir, &approved).unwrap();
        assert_ne!(approved, current);

        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn parse_rejects_invalid_detail() {
        let err = MigrationApprovalDetail::parse("count:0").unwrap_err();
        assert!(err.to_string().contains("invalid migration approval detail format"));
    }
}
