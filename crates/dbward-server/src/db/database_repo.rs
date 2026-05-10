use rusqlite::{params, Connection};

use crate::server_config::DatabaseDef;

/// Validate database/environment name: lowercase alphanumeric + hyphen + underscore, starts with letter.
fn validate_name(name: &str, field: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 63 {
        return Err(format!("{field} must be 1-63 characters, got: '{name}'"));
    }
    if !name.starts_with(|c: char| c.is_ascii_lowercase()) {
        return Err(format!("{field} must start with a lowercase letter, got: '{name}'"));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err(format!(
            "{field} must contain only lowercase letters, digits, hyphens, underscores, got: '{name}'"
        ));
    }
    Ok(())
}

/// Sync database definitions from config into SQLite.
/// Config is the source of truth; this replaces all existing entries.
pub fn register_databases(
    conn: &Connection,
    defs: &[DatabaseDef],
) -> Result<(), String> {
    for def in defs {
        validate_name(&def.name, "database name")?;
        for env in &def.environments {
            validate_name(env, "environment name")?;
        }
    }

    let tx = conn
        .unchecked_transaction()
        .map_err(|e| format!("failed to begin transaction: {e}"))?;

    tx.execute("DELETE FROM databases", [])
        .map_err(|e| format!("failed to clear databases: {e}"))?;

    let mut stmt = tx
        .prepare("INSERT OR IGNORE INTO databases (name, environment) VALUES (?1, ?2)")
        .map_err(|e| format!("failed to prepare insert: {e}"))?;

    for def in defs {
        for env in &def.environments {
            stmt.execute(params![&def.name, env])
                .map_err(|e| format!("failed to register database '{}' env '{}': {e}", def.name, env))?;
        }
    }
    drop(stmt);

    tx.commit()
        .map_err(|e| format!("failed to commit database registration: {e}"))?;
    Ok(())
}

/// Check if a (database, environment) pair is registered.
pub fn database_exists(conn: &Connection, name: &str, environment: &str) -> bool {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM databases WHERE name = ?1 AND environment = ?2)",
        params![name, environment],
        |row| row.get(0),
    )
    .unwrap_or(false)
}

/// List all registered databases grouped by name.
pub fn list_databases(conn: &Connection) -> Result<Vec<(String, Vec<String>)>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT name, environment FROM databases ORDER BY name, environment",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;

    let mut result: Vec<(String, Vec<String>)> = Vec::new();
    for row in rows {
        let (name, env) = row?;
        if let Some(last) = result.last_mut() {
            if last.0 == name {
                last.1.push(env);
                continue;
            }
        }
        result.push((name, vec![env]));
    }
    Ok(result)
}
