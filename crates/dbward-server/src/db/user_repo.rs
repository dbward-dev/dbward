use rusqlite::Connection;

pub struct UserRow {
    pub subject_type: String,
    pub subject_id: String,
    pub role: String,
    pub disabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

pub fn get_user(
    conn: &Connection,
    subject_type: &str,
    subject_id: &str,
) -> Result<Option<UserRow>, rusqlite::Error> {
    conn.query_row(
        "SELECT subject_type, subject_id, role, disabled, created_at, updated_at FROM users WHERE subject_type = ?1 AND subject_id = ?2",
        rusqlite::params![subject_type, subject_id],
        |row| {
            Ok(UserRow {
                subject_type: row.get(0)?,
                subject_id: row.get(1)?,
                role: row.get(2)?,
                disabled: row.get::<_, i64>(3)? != 0,
                created_at: row.get(4)?,
                updated_at: row.get(5)?,
            })
        },
    )
    .optional()
}

pub fn upsert_user(
    conn: &Connection,
    subject_type: &str,
    subject_id: &str,
    role: &str,
) -> Result<(), rusqlite::Error> {
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO users (subject_type, subject_id, role, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?4)
         ON CONFLICT (subject_type, subject_id) DO NOTHING",
        rusqlite::params![subject_type, subject_id, role, now],
    )?;
    Ok(())
}

pub fn update_role(
    conn: &Connection,
    subject_type: &str,
    subject_id: &str,
    new_role: &str,
) -> Result<Option<String>, rusqlite::Error> {
    let now = chrono::Utc::now().to_rfc3339();
    let old_role: Option<String> = conn
        .query_row(
            "SELECT role FROM users WHERE subject_type = ?1 AND subject_id = ?2",
            rusqlite::params![subject_type, subject_id],
            |row| row.get(0),
        )
        .optional()?;

    if old_role.is_some() {
        conn.execute(
            "UPDATE users SET role = ?1, updated_at = ?2 WHERE subject_type = ?3 AND subject_id = ?4",
            rusqlite::params![new_role, now, subject_type, subject_id],
        )?;
    }
    Ok(old_role)
}

pub fn disable_user(
    conn: &Connection,
    subject_type: &str,
    subject_id: &str,
) -> Result<bool, rusqlite::Error> {
    let now = chrono::Utc::now().to_rfc3339();
    let updated = conn.execute(
        "UPDATE users SET disabled = 1, updated_at = ?1 WHERE subject_type = ?2 AND subject_id = ?3 AND disabled = 0",
        rusqlite::params![now, subject_type, subject_id],
    )?;
    Ok(updated > 0)
}

pub fn cancel_user_requests(
    conn: &Connection,
    subject_id: &str,
) -> Result<usize, rusqlite::Error> {
    let now = chrono::Utc::now().to_rfc3339();
    let count = conn.execute(
        "UPDATE requests SET status = 'cancelled', updated_at = ?1 WHERE created_by = ?2 AND status IN ('pending', 'approved', 'dispatched')",
        rusqlite::params![now, subject_id],
    )?;
    Ok(count)
}

pub fn is_user_disabled(
    conn: &Connection,
    subject_type: &str,
    subject_id: &str,
) -> Result<bool, rusqlite::Error> {
    conn.query_row(
        "SELECT disabled FROM users WHERE subject_type = ?1 AND subject_id = ?2",
        rusqlite::params![subject_type, subject_id],
        |row| row.get::<_, i64>(0).map(|v| v != 0),
    )
    .optional()
    .map(|opt| opt.unwrap_or(false))
}

pub fn list_users(conn: &Connection) -> Result<Vec<UserRow>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT subject_type, subject_id, role, disabled, created_at, updated_at FROM users ORDER BY created_at",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok(UserRow {
                subject_type: row.get(0)?,
                subject_id: row.get(1)?,
                role: row.get(2)?,
                disabled: row.get::<_, i64>(3)? != 0,
                created_at: row.get(4)?,
                updated_at: row.get(5)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

use rusqlite::OptionalExtension;
