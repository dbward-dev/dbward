use std::fs;
use std::io;
use std::path::PathBuf;

pub struct ProbeGuard {
    liveness_path: PathBuf,
    readiness_path: PathBuf,
}

impl ProbeGuard {
    /// Create liveness probe only. Call `set_ready()` once startup completes.
    pub fn create_liveness(liveness: &str, readiness: &str) -> io::Result<Self> {
        let liveness_path = PathBuf::from(liveness);
        let readiness_path = PathBuf::from(readiness);
        fs::write(&liveness_path, "")?;
        Ok(Self {
            liveness_path,
            readiness_path,
        })
    }

    pub fn set_ready(&self) {
        if let Err(e) = fs::write(&self.readiness_path, "") {
            tracing::warn!(path = %self.readiness_path.display(), %e, "failed to create readiness probe");
        }
    }

    pub fn remove_readiness(&self) {
        let _ = fs::remove_file(&self.readiness_path);
    }

    pub fn restore_readiness(&self) {
        if let Err(e) = fs::write(&self.readiness_path, "") {
            tracing::warn!(path = %self.readiness_path.display(), %e, "failed to restore readiness probe");
        }
    }
}

impl Drop for ProbeGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.liveness_path);
        let _ = fs::remove_file(&self.readiness_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn probe_guard_liveness_only() {
        let live = "/tmp/dbward-test-f1-alive";
        let ready = "/tmp/dbward-test-f1-ready";
        {
            let guard = ProbeGuard::create_liveness(live, ready).unwrap();
            assert!(Path::new(live).exists());
            assert!(!Path::new(ready).exists());
            guard.set_ready();
            assert!(Path::new(ready).exists());
            guard.remove_readiness();
            assert!(!Path::new(ready).exists());
            guard.restore_readiness();
            assert!(Path::new(ready).exists());
        }
        assert!(!Path::new(live).exists());
        assert!(!Path::new(ready).exists());
    }
}
