use std::io::{self, Write};

use crate::{AuditEntry, Error};

/// MVP audit logger — writes JSON lines to stdout.
/// Persistent storage (SQLite) is a Pro feature.
pub struct AuditLogger {
    writer: Box<dyn Write + Send>,
}

impl AuditLogger {
    pub fn stdout() -> Self {
        Self {
            writer: Box::new(io::stdout()),
        }
    }

    /// Use stderr — required for MCP mode where stdout is the JSON-RPC channel.
    pub fn stderr() -> Self {
        Self {
            writer: Box::new(io::stderr()),
        }
    }

    #[cfg(test)]
    fn from_writer(writer: impl Write + Send + 'static) -> Self {
        Self {
            writer: Box::new(writer),
        }
    }

    pub fn log(&mut self, entry: &AuditEntry) -> Result<(), Error> {
        let json = serde_json::to_string(entry)?;
        writeln!(self.writer, "{json}")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Environment, Operation, Role};

    #[test]
    fn logs_json_line_to_writer() {
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let writer = ArcWriter(buf.clone());
        let mut logger = AuditLogger::from_writer(writer);

        let entry = AuditEntry::new(
            "alice",
            Role::Developer,
            Operation::MigrateUp,
            Environment::Staging,
            "20260501_create_users.sql",
        );
        logger.log(&entry).unwrap();

        let output = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(parsed["operation"], "migrate_up");
        assert_eq!(parsed["user"], "alice");
        assert!(output.ends_with('\n'));
    }

    /// Helper to share a Vec<u8> behind Arc<Mutex<_>> for testing.
    #[derive(Clone)]
    struct ArcWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl Write for ArcWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0.lock().unwrap().flush()
        }
    }
}
