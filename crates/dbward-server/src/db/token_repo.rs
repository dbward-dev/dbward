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
    name: Option<&str>,
    now: &str,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "INSERT INTO tokens (id, subject_type, subject_id, token_hash, token_prefix, role, name, status, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        rusqlite::params![id, subject_type, subject_id, token_hash, token_prefix, role, name, "active", now],
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

pub(crate) fn lookup_token_status(
    conn: &Connection,
    prefix: &str,
    hash: &str,
) -> Result<Option<String>, rusqlite::Error> {
    match conn.query_row(
        "SELECT status FROM tokens WHERE token_prefix = ?1 AND token_hash = ?2",
        rusqlite::params![prefix, hash],
        |row| row.get::<_, String>(0),
    ) {
        Ok(status) => Ok(Some(status)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

pub(crate) struct TokenListRow {
    pub(crate) id: String,
    pub(crate) prefix: String,
    pub(crate) subject_id: String,
    pub(crate) subject_type: String,
    pub(crate) role: String,
    pub(crate) name: Option<String>,
    pub(crate) status: String,
    pub(crate) groups: Vec<String>,
    pub(crate) created_at: String,
    pub(crate) revoked_at: Option<String>,
}

pub(crate) fn list_tokens(conn: &Connection) -> Result<Vec<TokenListRow>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT id, token_prefix, subject_id, subject_type, role, name, status, created_at, revoked_at FROM tokens ORDER BY created_at DESC",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, Option<String>>(8)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let mut result = Vec::with_capacity(rows.len());
    for (id, prefix, subject_id, subject_type, role, name, status, created_at, revoked_at) in rows {
        let mut grp_stmt = conn.prepare("SELECT group_name FROM token_groups WHERE token_id = ?1")?;
        let groups = grp_stmt
            .query_map([&id], |row| row.get(0))?
            .collect::<Result<Vec<String>, _>>()?;
        result.push(TokenListRow {
            id,
            prefix,
            subject_id,
            subject_type,
            role,
            name,
            status,
            groups,
            created_at,
            revoked_at,
        });
    }
    Ok(result)
}

pub(crate) fn count_active_tokens(conn: &Connection) -> Result<i64, rusqlite::Error> {
    conn.query_row("SELECT COUNT(*) FROM tokens WHERE status = 'active'", [], |row| row.get(0))
}
