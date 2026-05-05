use rusqlite::Connection;

pub(crate) struct TokenRow {
    pub(crate) id: String,
    pub(crate) subject_id: String,
    pub(crate) role: String,
    pub(crate) subject_type: String,
    pub(crate) groups: Vec<String>,
}

#[allow(clippy::too_many_arguments)]
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

pub(crate) fn insert_token_groups(
    conn: &Connection,
    token_id: &str,
    groups: &[String],
) -> Result<(), rusqlite::Error> {
    for group in groups {
        conn.execute(
            "INSERT INTO token_groups (token_id, group_name) VALUES (?1, ?2)",
            rusqlite::params![token_id, group],
        )?;
    }
    Ok(())
}

pub(crate) fn lookup_active_token(
    conn: &Connection,
    prefix: &str,
    hash: &str,
) -> Result<Option<TokenRow>, rusqlite::Error> {
    match conn.query_row(
        "SELECT id, subject_id, role, subject_type FROM tokens WHERE token_prefix = ?1 AND token_hash = ?2 AND status = 'active'",
        rusqlite::params![prefix, hash],
        |row| Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        )),
    ) {
        Ok((id, subject_id, role, subject_type)) => {
            let groups = {
                let mut stmt =
                    conn.prepare("SELECT group_name FROM token_groups WHERE token_id = ?1")?;
                stmt.query_map([&id], |row| row.get(0))?
                    .collect::<Result<Vec<String>, _>>()?
            };
            Ok(Some(TokenRow {
                id,
                subject_id,
                role,
                subject_type,
                groups,
            }))
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}
