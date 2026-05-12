use std::fs;
use std::io;
use std::path::PathBuf;

pub struct ProbeGuard {
    liveness_path: PathBuf,
    readiness_path: PathBuf,
}

impl ProbeGuard {
    pub fn create(liveness: &str, readiness: &str) -> io::Result<Self> {
        let liveness_path = PathBuf::from(liveness);
        let readiness_path = PathBuf::from(readiness);
        fs::write(&liveness_path, "")?;
        fs::write(&readiness_path, "")?;
        Ok(Self {
            liveness_path,
            readiness_path,
        })
    }

    pub fn remove_readiness(&self) {
        let _ = fs::remove_file(&self.readiness_path);
    }

    pub fn restore_readiness(&self) {
        let _ = fs::write(&self.readiness_path, "");
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
    fn probe_guard_lifecycle() {
        let live = "/tmp/dbward-test-alive";
        let ready = "/tmp/dbward-test-ready";
        {
            let guard = ProbeGuard::create(live, ready).unwrap();
            assert!(Path::new(live).exists());
            assert!(Path::new(ready).exists());
            guard.remove_readiness();
            assert!(!Path::new(ready).exists());
            assert!(Path::new(live).exists());
        }
        // Drop removes liveness
        assert!(!Path::new(live).exists());
    }
}
