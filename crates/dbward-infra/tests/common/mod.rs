#![allow(dead_code)]
//! Shared helpers for infra integration tests.

use chrono::Utc;
use dbward_infra::sqlite::{self, DbConn};

pub fn setup() -> DbConn {
    sqlite::open_memory().unwrap()
}

pub fn register_db(conn: &DbConn) {
    conn.lock()
        .unwrap()
        .execute(
            "INSERT INTO databases (id, name, environment, created_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                "app:production",
                "app",
                "production",
                Utc::now().to_rfc3339()
            ],
        )
        .unwrap();
}
