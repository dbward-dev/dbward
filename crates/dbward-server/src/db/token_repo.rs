use rusqlite::Connection;

pub(crate) struct TokenRow {
    pub(crate) id: String,
    pub(crate) subject_id: String,
    pub(crate) role: String,
    pub(crate) subject_type: String,
}

pub(crate) fn insert_token(
    conn: &Connection,
    id: &str,
    subject_type: &str,
    subject_id: &str,
    token_hash: &str,
    token_prefix: &str,
    role: &str,
    now: &str,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT INTO tokens (id, subject_type, subject_id, token_hash, token_prefix, role, status, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![id, subject_type, subject_id, token_hash, token_prefix, role, "active", now],
    )?;
    Ok(())
}

pub(crate) fn revoke_token(
    conn: &Connection,
    token_id: &str,
    now: &str,
) -> Result<bool, rusqlite::Error> {
    let updated = conn.execute(
        "UPDATE tokens SET status = 'revoked', revoked_at = ?1 WHERE id = ?2",
        rusqlite::params![now, token_id],
    )?;
    Ok(updated > 0)
}

pub(crate) fn lookup_active_token(
    conn: &Connection,
    prefix: &str,
    hash: &str,
) -> Result<Option<TokenRow>, rusqlite::Error> {
    match conn.query_row(
        "SELECT id, subject_id, role, subject_type FROM tokens WHERE token_prefix = ?1 AND token_hash = ?2 AND status = 'active'",
        rusqlite::params![prefix, hash],
        |row| Ok(TokenRow {
            id: row.get(0)?,
            subject_id: row.get(1)?,
            role: row.get(2)?,
            subject_type: row.get(3)?,
        }),
    ) {
        Ok(row) => Ok(Some(row)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}
