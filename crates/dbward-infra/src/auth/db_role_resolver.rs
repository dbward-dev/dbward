use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use dashmap::DashMap;
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

#[derive(Debug)]
struct BusyTimeoutCustomizer;

impl r2d2::CustomizeConnection<Connection, rusqlite::Error> for BusyTimeoutCustomizer {
    fn on_acquire(&self, conn: &mut Connection) -> Result<(), rusqlite::Error> {
        conn.execute_batch("PRAGMA busy_timeout = 5000;")?;
        Ok(())
    }
}

/// Immutable snapshot of config-derived resolver state.
/// Swapped atomically on config reload — guarantees cross-field consistency.
struct ResolverSnapshot {
    group_roles: HashMap<String, Vec<String>>,
    roles: HashMap<String, ResolvedRole>,
    default_role: Option<String>,
}

/// DB-backed role resolver with per-subject DashMap cache.
/// Replaces ConfigRoleResolver — reads roles from users.roles_json + group_members.
pub struct DbRoleResolver {
    pool: r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>,
    cache: DashMap<String, CachedEntry>,
    /// Atomic snapshot of all config-derived state.
    snapshot: ArcSwap<ResolverSnapshot>,
    policy_repo: Option<Arc<dyn dbward_app::ports::PolicyRepo>>,
}

impl DbRoleResolver {
    pub fn new(
        db_path: &str,
        group_roles: HashMap<String, Vec<String>>,
        role_definitions: Vec<dbward_domain::auth::RoleDefinition>,
        default_role: Option<String>,
        policy_repo: Option<Arc<dyn dbward_app::ports::PolicyRepo>>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let manager = r2d2_sqlite::SqliteConnectionManager::file(db_path).with_flags(
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        );
        let pool = r2d2::Pool::builder()
            .max_size(4)
            .connection_customizer(Box::new(BusyTimeoutCustomizer))
            .build(manager)?;

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
            pool,
            cache: DashMap::new(),
            snapshot: ArcSwap::new(Arc::new(ResolverSnapshot {
                group_roles,
                roles,
                default_role,
            })),
            policy_repo,
        })
    }

    /// For testing: create from an existing connection (in-memory DB).
    /// The provided connection is used to initialize a shared in-memory pool via backup.
    #[cfg(test)]
    pub fn from_connection(
        conn: Connection,
        group_roles: HashMap<String, Vec<String>>,
        default_role: Option<String>,
    ) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        // Each test gets a unique shared in-memory DB so they don't interfere
        let uri = format!("file:test_resolver_{id}?mode=memory&cache=shared");

        let manager = r2d2_sqlite::SqliteConnectionManager::file(&uri);
        let pool = r2d2::Pool::builder()
            .max_size(1)
            .build(manager)
            .expect("failed to build test pool");

        // Copy schema and data from the provided connection into the pool's DB
        {
            let mut pooled = pool.get().expect("failed to get pooled conn");
            let backup =
                rusqlite::backup::Backup::new(&conn, &mut pooled).expect("failed to init backup");
            backup
                .run_to_completion(100, std::time::Duration::ZERO, None)
                .expect("failed to run backup");
        }

        let mut roles = HashMap::new();
        for (name, resolved) in builtin_roles() {
            roles.insert(name, resolved);
        }
        Self {
            pool,
            cache: DashMap::new(),
            snapshot: ArcSwap::new(Arc::new(ResolverSnapshot {
                group_roles,
                roles,
                default_role,
            })),
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
        let current = self.snapshot.load();
        self.snapshot.store(Arc::new(ResolverSnapshot {
            group_roles: new_group_roles,
            roles: current.roles.clone(),
            default_role: current.default_role.clone(),
        }));
        self.cache.clear();
    }

    /// Atomically update all config-derived state in a single snapshot swap.
    pub fn reload_config(
        &self,
        new_group_roles: HashMap<String, Vec<String>>,
        role_definitions: Vec<dbward_domain::auth::RoleDefinition>,
        new_default_role: Option<String>,
    ) {
        let mut new_roles = HashMap::new();
        for (name, resolved) in builtin_roles() {
            new_roles.insert(name, resolved);
        }
        for def in role_definitions {
            let resolved = ResolvedRole {
                name: def.name.clone(),
                permissions: def.permissions.into_iter().collect(),
                databases: def.databases,
                environments: def.environments,
            };
            new_roles.insert(def.name, resolved);
        }
        self.snapshot.store(Arc::new(ResolverSnapshot {
            group_roles: new_group_roles,
            roles: new_roles,
            default_role: new_default_role,
        }));
        self.cache.clear();
    }

    fn resolve_from_db_with_snapshot(
        &self,
        snap: &ResolverSnapshot,
        subject_id: &str,
        oidc_groups: &[String],
    ) -> Result<(Vec<String>, Vec<String>), AuthError> {
        let conn = self
            .pool
            .get()
            .map_err(|e| AuthError::Internal(format!("pool: {e}")))?;

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
        let mut all_role_names: HashSet<String> = direct_roles.into_iter().collect();
        for group in &effective_groups {
            if let Some(roles) = snap.group_roles.get(group) {
                for r in roles {
                    all_role_names.insert(r.clone());
                }
            }
        }

        // 5. Default role fallback
        if all_role_names.is_empty()
            && let Some(ref d) = snap.default_role
        {
            all_role_names.insert(d.clone());
        }

        Ok((all_role_names.into_iter().collect(), effective_groups))
    }

    fn resolve_role_names_with_snapshot(
        &self,
        snap: &ResolverSnapshot,
        role_names: &[String],
    ) -> Result<Vec<ResolvedRole>, AuthError> {
        let mut resolved = Vec::new();
        let mut unresolved = Vec::new();

        for name in role_names {
            if let Some(r) = snap.roles.get(name) {
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
        // Load config snapshot once for the entire resolve flow (consistency guarantee)
        let snap = self.snapshot.load();

        // Agents always get agent-default only
        if subject_type == SubjectType::Agent {
            return Ok(vec![snap.roles.get("agent-default").cloned().ok_or_else(
                || AuthError::Internal("agent-default role not found".into()),
            )?]);
        }

        // Check cache (TTL-based lazy eviction)
        // Skip cache when OIDC groups are provided — they vary per request
        if groups.is_empty()
            && let Some(entry) = self.cache.get(subject_id)
            && entry.cached_at.elapsed().as_secs() < CACHE_TTL_SECS
        {
            return self.resolve_role_names_with_snapshot(
                &snap,
                &entry
                    .roles
                    .iter()
                    .map(|r| r.name.clone())
                    .collect::<Vec<_>>(),
            );
        }

        // Cache miss: query DB
        let (role_names, effective_groups) = self.resolve_from_db_with_snapshot(&snap, subject_id, groups)?;
        let resolved = self.resolve_role_names_with_snapshot(&snap, &role_names)?;

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
        let conn = match self.pool.get() {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };
        let mut subjects: HashSet<String> = HashSet::new();

        // Direct role holders
        if let Ok(mut stmt) =
            conn.prepare("SELECT DISTINCT u.id FROM users u, json_each(u.roles_json) je WHERE je.value = ?1 AND u.lifecycle_state = 'active' AND u.status = 'active'")
            && let Ok(rows) = stmt.query_map(rusqlite::params![role], |row| row.get(0))
        {
            for r in rows.flatten() {
                subjects.insert(r);
            }
        }

        // Group-derived role holders
        let snap = self.snapshot.load();
        for (group, roles) in snap.group_roles.iter() {
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
            let conn = match self.pool.get() {
                Ok(c) => c,
                Err(_) => return Vec::new(),
            };
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
        self.snapshot
            .load()
            .group_roles
            .get(group_name)
            .cloned()
            .unwrap_or_default()
    }

    fn groups_granting_role(&self, role: &str) -> Vec<String> {
        self.snapshot
            .load()
            .group_roles
            .iter()
            .filter(|(_, roles)| roles.contains(&role.to_string()))
            .map(|(name, _)| name.clone())
            .collect()
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
                    Permission::UserRead,
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

        let group_roles =
            HashMap::from([("backend-team".to_string(), vec!["developer".to_string()])]);
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
