use crate::sqlite::DbConn;
use dbward_app::ports::ConfigGenerationRepo;

pub struct SqliteConfigGenerationRepo {
    conn: DbConn,
}

impl SqliteConfigGenerationRepo {
    pub fn new(conn: DbConn) -> Self {
        Self { conn }
    }
}

impl ConfigGenerationRepo for SqliteConfigGenerationRepo {
    fn record_generation(&self, digest: &str, summary_json: &str) {
        let conn = self.conn.lock();
        let _ = conn.execute(
            "INSERT INTO config_generations (config_digest, synced_at, summary_json) VALUES (?1, ?2, ?3)",
            rusqlite::params![digest, chrono::Utc::now().to_rfc3339(), summary_json],
        );
    }
}
