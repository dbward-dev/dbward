use rusqlite::Connection;

/// Insert a policy change audit record (used by policy CRUD handlers).
pub fn insert_policy_change(
    conn: &Connection,
    user: &str,
    op_type: &str,
    policy_type: &str,
    policy_id: &str,
) -> Result<(), rusqlite::Error> {
    let (db, env) = policy_id.split_once(':').unwrap_or((policy_id, ""));
    let audit_id = uuid::Uuid::new_v4().to_string();
    let detail_json = serde_json::json!({"type": policy_type, "id": policy_id}).to_string();
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO audit_log (id, request_id, actor_id, operation, environment, database_name, detail, status, created_at) VALUES (?1, NULL, ?2, ?3, ?4, ?5, ?6, 'policy_change', ?7)",
        rusqlite::params![audit_id, user, op_type, env, db, detail_json, now],
    )?;
    Ok(())
}
