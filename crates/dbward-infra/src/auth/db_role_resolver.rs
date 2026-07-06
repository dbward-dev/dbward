use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use dashmap::DashMap;
use parking_lot::Mutex;
use rusqlite::Connection;

use dbward_app::error::AuthError;
use dbward_app::ports::RoleResolver;
use dbward_domain::auth::{Permission, ResolvedRole, SubjectType};
use dbward_domain::values::{DatabaseName, Environment};

const CACHE_TTL_SECS: u64 = 5;

struct CachedEntry {
    roles: Vec<ResolvedRole>,
    #[allow(dead_code)] // Used in Step 5.6 when auth middleware reads groups
    groups: Vec<String>,
    cached_at: Instant,
}

/// DB-backed role resolver with per-subject DashMap cache.
/// Replaces ConfigRoleResolver — reads roles from users.roles_json + group_members.
pub struct DbRoleResolver {
    conn: Mutex<Connection>,
    cache: DashMap<String, CachedEntry>,
    /// Config-defined group→roles mapping. Swapped atomically on config reload.
    group_roles: ArcSwap<HashMap<String, Vec<String>>>,
    /// Built-in + custom role definitions (name → ResolvedRole).
    roles: HashMap<String, ResolvedRole>,
    default_role: Option<String>,
    policy_repo: Option<Arc<dyn dbward_app::ports::PolicyRepo>>,
}

impl DbRoleResolver {
    pub fn new(
        db_path: &str,
        group_roles: HashMap<String, Vec<String>>,
        role_definitions: Vec<dbward_domain::auth::RoleDefinition>,
        default_role: Option<String>,
        policy_repo: Option<Arc<dyn dbward_app::ports::PolicyRepo>>,
    ) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open_with_flags(
            db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.execute_batch("PRAGMA busy_timeout = 5000;")?;

        let mut roles = HashMap::new();
        for (name, resolved) in builtin_roles() {
            roles.insert(name, resolved);
        }
        for def in role_definitions {
            let resolved = ResolvedRole {
                name: def.name.clone(),
                permissions: def.permissions.into_iter().collect(),
                databases: def.databases,
                environments: def.environments,
            };
            roles.insert(def.name, resolved);
        }

        Ok(Self {
            conn: Mutex::new(conn),
            cache: DashMap::new(),
            group_roles: ArcSwap::new(Arc::new(group_roles)),
            roles,
            default_role,
            policy_repo,
        })
    }

    /// For testing: create from an existing connection (in-memory DB).
    #[cfg(test)]
    pub fn from_connection(
        conn: Connection,
        group_roles: HashMap<String, Vec<String>>,
        default_role: Option<String>,
    ) -> Self {
        let mut roles = HashMap::new();
        for (name, resolved) in builtin_roles() {
            roles.insert(name, resolved);
        }
        Self {
            conn: Mutex::new(conn),
            cache: DashMap::new(),
            group_roles: ArcSwap::new(Arc::new(group_roles)),
            roles,
            default_role,
            policy_repo: None,
        }
    }

    /// Invalidate cache for a specific user (call after user update).
    pub fn invalidate(&self, subject_id: &str) {
        self.cache.remove(subject_id);
    }

    /// Invalidate all cached entries (call on config reload).
    pub fn invalidate_all(&self) {
        self.cache.clear();
    }

    /// Update group→roles mapping from config (call on config reload).
    pub fn update_group_roles(&self, new_group_roles: HashMap<String, Vec<String>>) {
        self.group_roles.store(Arc::new(new_group_roles));
        self.cache.clear();
    }

    fn resolve_from_db(
        &self,
        subject_id: &str,
        oidc_groups: &[String],
    ) -> Result<(Vec<String>, Vec<String>), AuthError> {
        let conn = self.conn.lock();

        // 1. Get direct roles from users.roles_json
        let direct_roles: Vec<String> = conn
            .query_row(
                "SELECT roles_json FROM users WHERE id = ?1 AND lifecycle_state = 'active'",
                rusqlite::params![subject_id],
                |row| row.get::<_, String>(0),
            )
            .map(|json| serde_json::from_str::<Vec<String>>(&json).unwrap_or_default())
            .unwrap_or_default();

        // 2. Get local group memberships
        let mut stmt = conn
            .prepare("SELECT group_name FROM group_members WHERE user_id = ?1")
            .map_err(|e| AuthError::Internal(format!("resolve: group_members query: {e}")))?;
        let local_groups: Vec<String> = stmt
            .query_map(rusqlite::params![subject_id], |row| row.get(0))
            .map_err(|e| AuthError::Internal(format!("resolve: group_members read: {e}")))?
            .filter_map(|r| r.ok())
            .collect();

        // 3. effective_groups = local_groups ∪ oidc_groups
        let mut effective_groups: Vec<String> = local_groups;
        for g in oidc_groups {
            if !effective_groups.contains(g) {
                effective_groups.push(g.clone());
            }
        }

        // 4. Collect group-derived role names from config
        let group_roles_map = self.group_roles.load();
        let mut all_role_names: HashSet<String> = direct_roles.into_iter().collect();
        for group in &effective_groups {
            if let Some(roles) = group_roles_map.get(group) {
                for r in roles {
                    all_role_names.insert(r.clone());
                }
            }
        }

        // 5. Default role fallback
        if all_role_names.is_empty()
            && let Some(ref default) = self.default_role
        {
            all_role_names.insert(default.clone());
        }

        Ok((all_role_names.into_iter().collect(), effective_groups))
    }

    fn resolve_role_names_to_objects(
        &self,
        role_names: &[String],
    ) -> Result<Vec<ResolvedRole>, AuthError> {
        let mut resolved = Vec::new();
        let mut unresolved = Vec::new();

        for name in role_names {
            if let Some(r) = self.roles.get(name) {
                resolved.push(r.clone());
            } else {
                unresolved.push(name.clone());
            }
        }

        // Fallback to PolicyRepo for DB-stored custom roles
        if !unresolved.is_empty()
            && let Some(ref repo) = self.policy_repo
            && let Ok(defs) = repo.get_roles_by_names(&unresolved)
        {
            for def in defs {
                resolved.push(ResolvedRole {
                    name: def.name.clone(),
                    permissions: def.permissions.into_iter().collect(),
                    databases: def.databases,
                    environments: def.environments,
                });
            }
        }

        Ok(resolved)
    }
}

impl RoleResolver for DbRoleResolver {
    fn resolve(
        &self,
        subject_id: &str,
        subject_type: SubjectType,
        groups: &[String],
    ) -> Result<Vec<ResolvedRole>, AuthError> {
        // Agents always get agent-default only
        if subject_type == SubjectType::Agent {
            return Ok(vec![self
                .roles
                .get("agent-default")
                .cloned()
                .ok_or_else(|| AuthError::Internal("agent-default role not found".into()))?]);
        }

        // Check cache (TTL-based lazy eviction)
        // Skip cache when OIDC groups are provided — they vary per request
        if groups.is_empty()
            && let Some(entry) = self.cache.get(subject_id)
            && entry.cached_at.elapsed().as_secs() < CACHE_TTL_SECS
        {
            return self.resolve_role_names_to_objects(
                &entry
                    .roles
                    .iter()
                    .map(|r| r.name.clone())
                    .collect::<Vec<_>>(),
            );
        }

        // Cache miss: query DB
        let (role_names, effective_groups) = self.resolve_from_db(subject_id, groups)?;
        let resolved = self.resolve_role_names_to_objects(&role_names)?;

        // Only cache when no OIDC groups were provided (stable result)
        if groups.is_empty() {
            self.cache.insert(
                subject_id.to_string(),
                CachedEntry {
                    roles: resolved.clone(),
                    groups: effective_groups,
                    cached_at: Instant::now(),
                },
            );
        }

        Ok(resolved)
    }

    fn invalidate_cache(&self, subject_id: &str) {
        self.cache.remove(subject_id);
    }

    fn subjects_for_role(&self, role: &str) -> Vec<String> {
        let conn = self.conn.lock();
        let mut subjects: HashSet<String> = HashSet::new();

        // Direct role holders
        if let Ok(mut stmt) =
            conn.prepare("SELECT id FROM users WHERE roles_json LIKE ?1 AND lifecycle_state = 'active' AND status = 'active'")
            && let Ok(rows) = stmt.query_map(rusqlite::params![format!("%\"{role}\"%")], |row| row.get(0))
        {
            for r in rows.flatten() {
                subjects.insert(r);
            }
        }

        // Group-derived role holders
        let group_roles_map = self.group_roles.load();
        for (group, roles) in group_roles_map.iter() {
            if roles.iter().any(|r| r == role)
                && let Ok(mut stmt) =
                    conn.prepare("SELECT gm.user_id FROM group_members gm JOIN users u ON u.id = gm.user_id WHERE gm.group_name = ?1 AND u.lifecycle_state = 'active' AND u.status = 'active'")
                && let Ok(rows) = stmt.query_map(rusqlite::params![group], |row| row.get(0))
            {
                for r in rows.flatten() {
                    subjects.insert(r);
                }
            }
        }

        subjects.into_iter().collect()
    }

    fn subjects_for_selector(&self, selector: &str) -> Vec<String> {
        if let Some(role) = selector.strip_prefix("role:") {
            self.subjects_for_role(role)
        } else if let Some(group) = selector.strip_prefix("group:") {
            let conn = self.conn.lock();
            let mut result = Vec::new();
            if let Ok(mut stmt) =
                conn.prepare("SELECT user_id FROM group_members WHERE group_name = ?1")
                && let Ok(rows) = stmt.query_map(rusqlite::params![group], |row| row.get(0))
            {
                for r in rows.flatten() {
                    result.push(r);
                }
            }
            result
        } else if let Some(user) = selector.strip_prefix("user:") {
            vec![user.to_string()]
        } else {
            vec![]
        }
    }

    fn config_groups_for(&self, subject_id: &str) -> Option<&Vec<String>> {
        // Cannot return borrow from DB-backed resolver.
        // Callers should use the groups from resolve() result instead.
        // This method will be removed when auth middleware is updated (Step 5.6).
        let _ = subject_id;
        None
    }

    fn roles_for_group(&self, group_name: &str) -> Vec<String> {
        self.group_roles
            .load()
            .get(group_name)
            .cloned()
            .unwrap_or_default()
    }
}

fn builtin_roles() -> Vec<(String, ResolvedRole)> {
    let wildcard_db = DatabaseName::new("*").unwrap();
    let wildcard_env = Environment::new("*").unwrap();
    vec![
        (
            "admin".to_string(),
            ResolvedRole {
                name: "admin".to_string(),
                permissions: [Permission::All].into_iter().collect(),
                databases: vec![wildcard_db.clone()],
                environments: vec![wildcard_env.clone()],
            },
        ),
        (
            "developer".to_string(),
            ResolvedRole {
                name: "developer".to_string(),
                permissions: [
                    Permission::RequestExecute,
                    Permission::RequestQuery,
                    Permission::RequestView,
                    Permission::RequestCancel,
                    Permission::RequestResume,
                    Permission::ResultView,
                    Permission::WorkflowRead,
                    Permission::TokenRevokeOwn,
                ]
                .into_iter()
                .collect(),
                databases: vec![wildcard_db.clone()],
                environments: vec![wildcard_env.clone()],
            },
        ),
        (
            "readonly".to_string(),
            ResolvedRole {
                name: "readonly".to_string(),
                permissions: [
                    Permission::RequestQuery,
                    Permission::RequestView,
                    Permission::ResultView,
                    Permission::WorkflowRead,
                ]
                .into_iter()
                .collect(),
                databases: vec![wildcard_db.clone()],
                environments: vec![wildcard_env.clone()],
            },
        ),
        (
            "agent-default".to_string(),
            ResolvedRole {
                name: "agent-default".to_string(),
                permissions: [Permission::AgentOperate].into_iter().collect(),
                databases: vec![wildcard_db],
                environments: vec![wildcard_env],
            },
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::initialize;

    fn setup_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        initialize(&conn).unwrap();
        conn
    }

    fn insert_user(conn: &Connection, id: &str, roles: &[&str]) {
        let roles_json = serde_json::to_string(&roles).unwrap();
        let now = "2024-01-01T00:00:00Z";
        conn.execute(
            "INSERT INTO users (id, roles_json, status, source, lifecycle_state, created_at, updated_at) VALUES (?1, ?2, 'active', 'api', 'active', ?3, ?3)",
            rusqlite::params![id, roles_json, now],
        ).unwrap();
    }

    fn insert_group(conn: &Connection, name: &str) {
        conn.execute(
            "INSERT INTO groups (name, created_at) VALUES (?1, '2024-01-01T00:00:00Z')",
            rusqlite::params![name],
        )
        .unwrap();
    }

    fn add_member(conn: &Connection, group: &str, user: &str) {
        conn.execute(
            "INSERT INTO group_members (group_name, user_id, added_at) VALUES (?1, ?2, '2024-01-01T00:00:00Z')",
            rusqlite::params![group, user],
        ).unwrap();
    }

    #[test]
    fn resolve_direct_roles() {
        let conn = setup_db();
        insert_user(&conn, "alice", &["admin"]);

        let resolver = DbRoleResolver::from_connection(conn, HashMap::new(), None);
        let roles = resolver.resolve("alice", SubjectType::User, &[]).unwrap();
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].name, "admin");
    }

    #[test]
    fn resolve_group_roles() {
        let conn = setup_db();
        insert_user(&conn, "bob", &[]);
        insert_group(&conn, "backend-team");
        add_member(&conn, "backend-team", "bob");

        let group_roles = HashMap::from([("backend-team".to_string(), vec!["developer".to_string()])]);
        let resolver = DbRoleResolver::from_connection(conn, group_roles, None);
        let roles = resolver.resolve("bob", SubjectType::User, &[]).unwrap();
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].name, "developer");
    }

    #[test]
    fn resolve_union_direct_and_group() {
        let conn = setup_db();
        insert_user(&conn, "carol", &["readonly"]);
        insert_group(&conn, "dba-team");
        add_member(&conn, "dba-team", "carol");

        let group_roles = HashMap::from([("dba-team".to_string(), vec!["developer".to_string()])]);
        let resolver = DbRoleResolver::from_connection(conn, group_roles, None);
        let roles = resolver.resolve("carol", SubjectType::User, &[]).unwrap();
        let names: HashSet<_> = roles.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains("readonly"));
        assert!(names.contains("developer"));
    }

    #[test]
    fn resolve_default_role() {
        let conn = setup_db();
        insert_user(&conn, "newbie", &[]);

        let resolver =
            DbRoleResolver::from_connection(conn, HashMap::new(), Some("readonly".to_string()));
        let roles = resolver.resolve("newbie", SubjectType::User, &[]).unwrap();
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].name, "readonly");
    }

    #[test]
    fn resolve_agent() {
        let conn = setup_db();
        insert_user(&conn, "agent-1", &["admin"]);

        let resolver = DbRoleResolver::from_connection(conn, HashMap::new(), None);
        let roles = resolver
            .resolve("agent-1", SubjectType::Agent, &[])
            .unwrap();
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].name, "agent-default");
    }

    #[test]
    fn resolve_oidc_groups() {
        let conn = setup_db();
        insert_user(&conn, "dave", &[]);

        let group_roles =
            HashMap::from([("engineering".to_string(), vec!["developer".to_string()])]);
        let resolver = DbRoleResolver::from_connection(conn, group_roles, None);
        let roles = resolver
            .resolve("dave", SubjectType::User, &["engineering".to_string()])
            .unwrap();
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].name, "developer");
    }

    #[test]
    fn cache_invalidation() {
        let conn = setup_db();
        insert_user(&conn, "eve", &["developer"]);

        let resolver = DbRoleResolver::from_connection(conn, HashMap::new(), None);

        // First resolve populates cache
        let roles = resolver.resolve("eve", SubjectType::User, &[]).unwrap();
        assert_eq!(roles[0].name, "developer");

        // Invalidate
        resolver.invalidate("eve");
        assert!(!resolver.cache.contains_key("eve"));
    }

    #[test]
    fn subjects_for_role_direct() {
        let conn = setup_db();
        insert_user(&conn, "alice", &["admin"]);
        insert_user(&conn, "bob", &["developer"]);

        let resolver = DbRoleResolver::from_connection(conn, HashMap::new(), None);
        let subjects = resolver.subjects_for_role("admin");
        assert_eq!(subjects, vec!["alice"]);
    }

    #[test]
    fn subjects_for_selector_group() {
        let conn = setup_db();
        insert_user(&conn, "alice", &[]);
        insert_group(&conn, "team");
        add_member(&conn, "team", "alice");

        let resolver = DbRoleResolver::from_connection(conn, HashMap::new(), None);
        let subjects = resolver.subjects_for_selector("group:team");
        assert_eq!(subjects, vec!["alice"]);
    }
}
