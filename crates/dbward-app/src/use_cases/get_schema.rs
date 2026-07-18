use std::sync::Arc;

use serde::Serialize;
use serde_json::Value;

use dbward_domain::auth::{AuthUser, Permission, ResourceContext};
use dbward_domain::values::{DatabaseName, Environment};

use crate::error::AppError;
use crate::ports::{Authorizer, DatabaseRegistry, SchemaRepo};

const ENV_PRIORITY: &[&str] = &["production", "staging", "development"];

pub struct GetSchema {
    pub database_registry: Arc<dyn DatabaseRegistry>,
    pub schema_repo: Arc<dyn SchemaRepo>,
    pub authorizer: Arc<dyn Authorizer>,
}

pub struct GetSchemaInput {
    pub database: String,
    pub environment: Option<String>,
    pub table: Option<String>,
    pub summary: bool,
}

#[derive(Debug, Serialize)]
pub struct SchemaOutput {
    pub database: String,
    pub environment: String,
    pub dialect: String,
    pub status: String,
    pub collected_at: String,
    #[serde(flatten)]
    pub body: SchemaBody,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum SchemaBody {
    SingleTable { table: Value },
    TableList { tables: Vec<Value> },
}

impl GetSchema {
    pub fn execute(
        &self,
        input: GetSchemaInput,
        user: &AuthUser,
    ) -> Result<SchemaOutput, AppError> {
        let all_pairs = self.database_registry.list_active()?;
        let envs_for_db: Vec<&str> = all_pairs
            .iter()
            .filter(|(d, _)| d.as_str() == input.database)
            .map(|(_, e)| e.as_str())
            .collect();

        if envs_for_db.is_empty() {
            return Err(AppError::NotFound("database not registered".into()));
        }

        let candidates = self.resolve_candidates(&envs_for_db, input.environment.as_deref())?;
        let (resolved_env, record) =
            self.find_authorized_snapshot(&input.database, &candidates, user)?;

        let snapshot_json = record.snapshot_json.as_deref().unwrap_or("{}");
        let snapshot: Value = serde_json::from_str(snapshot_json)
            .map_err(|e| AppError::Internal(format!("corrupt snapshot JSON: {e}")))?;
        let tables = snapshot["tables"]
            .as_array()
            .ok_or_else(|| AppError::Internal("snapshot missing tables array".into()))?
            .clone();

        let body = if let Some(ref table_filter) = input.table {
            self.filter_table(&tables, table_filter)?
        } else if input.summary {
            SchemaBody::TableList {
                tables: tables.iter().map(summarize_table).collect(),
            }
        } else {
            SchemaBody::TableList { tables }
        };

        Ok(SchemaOutput {
            database: input.database,
            environment: resolved_env,
            dialect: record.dialect,
            status: record.status,
            collected_at: record.collected_at,
            body,
        })
    }

    fn resolve_candidates<'a>(
        &self,
        envs_for_db: &[&'a str],
        env_override: Option<&'a str>,
    ) -> Result<Vec<&'a str>, AppError> {
        if let Some(env) = env_override {
            if envs_for_db.contains(&env) {
                return Ok(vec![env]);
            }
            return Err(AppError::NotFound(format!(
                "environment '{env}' not registered for this database"
            )));
        }

        let mut candidates: Vec<&str> = Vec::new();
        for &p in ENV_PRIORITY {
            if envs_for_db.contains(&p) {
                candidates.push(p);
            }
        }
        let mut remaining: Vec<&str> = envs_for_db
            .iter()
            .copied()
            .filter(|e| !candidates.contains(e))
            .collect();
        remaining.sort_unstable();
        candidates.extend(remaining);
        Ok(candidates)
    }

    fn find_authorized_snapshot(
        &self,
        db: &str,
        candidates: &[&str],
        user: &AuthUser,
    ) -> Result<(String, crate::ports::SchemaSnapshotRecord), AppError> {
        let mut any_ready = false;
        for env in candidates {
            let snapshot = self.schema_repo.get_snapshot(db, env)?;
            if let Some(s) = snapshot.filter(|s| s.status == "ready") {
                any_ready = true;
                let db_name =
                    DatabaseName::new(db).map_err(|e| AppError::Internal(e.to_string()))?;
                let env_val =
                    Environment::new(*env).map_err(|e| AppError::Internal(e.to_string()))?;
                if self
                    .authorizer
                    .authorize_scoped(
                        user,
                        Permission::RequestView,
                        &db_name,
                        &env_val,
                        &ResourceContext::Global,
                    )
                    .is_ok()
                {
                    return Ok((env.to_string(), s));
                }
            }
        }
        if any_ready {
            Err(AppError::Forbidden(crate::error::AuthzError::Forbidden {
                permission: Permission::RequestView,
                reason: "no authorized environment".into(),
            }))
        } else {
            Err(AppError::NotFound(
                "schema not yet collected. Start an agent for this database.".into(),
            ))
        }
    }

    fn filter_table(&self, tables: &[Value], filter: &str) -> Result<SchemaBody, AppError> {
        let (schema_filter, name_filter) = if let Some((s, t)) = filter.split_once('.') {
            (Some(s), t)
        } else {
            (None, filter)
        };

        let matches: Vec<&Value> = tables
            .iter()
            .filter(|t| {
                let name = t["name"].as_str().unwrap_or("");
                let schema = t["schema_name"].as_str().unwrap_or("");
                match schema_filter {
                    Some(sf) => name == name_filter && schema == sf,
                    None => name == name_filter,
                }
            })
            .collect();

        match matches.len() {
            0 => Err(AppError::NotFound(format!(
                "table '{filter}' not found in snapshot"
            ))),
            1 => Ok(SchemaBody::SingleTable {
                table: matches[0].clone(),
            }),
            _ => {
                let schemas: Vec<&str> = matches
                    .iter()
                    .filter_map(|t| t["schema_name"].as_str())
                    .collect();
                Err(AppError::NotFound(format!(
                    "multiple tables named '{name_filter}' found in schemas: {}. Specify as schema.table",
                    schemas.join(", ")
                )))
            }
        }
    }
}

fn summarize_table(t: &Value) -> Value {
    serde_json::json!({
        "name": t["name"],
        "schema_name": t["schema_name"],
        "estimated_rows": t["estimated_rows"],
        "column_count": t["columns"].as_array().map(|a| a.len()).unwrap_or(0),
        "constraint_count": t["constraints"].as_array().map(|a| a.len()).unwrap_or(0),
        "index_count": t["indexes"].as_array().map(|a| a.len()).unwrap_or(0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AuthzError;
    use crate::ports::SchemaSnapshotRecord;
    use dbward_domain::auth::SubjectType;
    use std::sync::Mutex;

    struct FakeRegistry {
        pairs: Vec<(DatabaseName, Environment)>,
    }
    impl DatabaseRegistry for FakeRegistry {
        fn register(&self, _: &DatabaseName, _: &Environment) -> Result<(), AppError> {
            Ok(())
        }
        fn exists_active(&self, _: &DatabaseName, _: &Environment) -> Result<bool, AppError> {
            Ok(true)
        }
        fn list_active(&self) -> Result<Vec<(DatabaseName, Environment)>, AppError> {
            Ok(self.pairs.clone())
        }
    }

    struct FakeSchemaRepo {
        snapshot: Mutex<Option<SchemaSnapshotRecord>>,
    }
    impl SchemaRepo for FakeSchemaRepo {
        fn upsert_snapshot(&self, _: &SchemaSnapshotRecord) -> Result<(), AppError> {
            Ok(())
        }
        fn get_snapshot(&self, _: &str, _: &str) -> Result<Option<SchemaSnapshotRecord>, AppError> {
            Ok(self.snapshot.lock().unwrap().clone())
        }
        fn get_dialect(&self, _: &str, _: &str) -> Result<Option<String>, AppError> {
            Ok(None)
        }
        fn get_tables_for(
            &self,
            _: &str,
            _: &str,
            _: &[dbward_domain::services::table_extractor::TableRef],
        ) -> Result<Option<String>, AppError> {
            Ok(None)
        }
    }

    struct AllowAuth;
    impl Authorizer for AllowAuth {
        fn authorize_scoped(
            &self,
            _: &AuthUser,
            _: Permission,
            _: &DatabaseName,
            _: &Environment,
            _: &ResourceContext,
        ) -> Result<(), AuthzError> {
            Ok(())
        }
        fn authorize_global(&self, _: &AuthUser, _: Permission) -> Result<(), AuthzError> {
            Ok(())
        }
        fn authorize_approval(
            &self,
            _: &AuthUser,
            _: &DatabaseName,
            _: &Environment,
            _: &ResourceContext,
        ) -> Result<(), AuthzError> {
            Ok(())
        }
    }

    struct DenyAuth;
    impl Authorizer for DenyAuth {
        fn authorize_scoped(
            &self,
            _: &AuthUser,
            _: Permission,
            _: &DatabaseName,
            _: &Environment,
            _: &ResourceContext,
        ) -> Result<(), AuthzError> {
            Err(AuthzError::Forbidden {
                permission: Permission::RequestView,
                reason: "denied".into(),
            })
        }
        fn authorize_global(&self, _: &AuthUser, _: Permission) -> Result<(), AuthzError> {
            Err(AuthzError::Forbidden {
                permission: Permission::RequestView,
                reason: "denied".into(),
            })
        }
        fn authorize_approval(
            &self,
            _: &AuthUser,
            _: &DatabaseName,
            _: &Environment,
            _: &ResourceContext,
        ) -> Result<(), AuthzError> {
            Err(AuthzError::Forbidden {
                permission: Permission::RequestView,
                reason: "denied".into(),
            })
        }
    }

    fn user() -> AuthUser {
        AuthUser {
            subject_id: "u1".into(),
            subject_type: SubjectType::User,
            groups: vec![],
            roles: vec![],
            token_id: None,
        }
    }

    fn snapshot_record() -> SchemaSnapshotRecord {
        SchemaSnapshotRecord {
            database_name: "app".into(),
            environment: "production".into(),
            status: "ready".into(),
            snapshot_json: Some(
                r#"{"tables":[{"name":"users","schema_name":"public","estimated_rows":100,"columns":[{"name":"id"}],"constraints":[],"indexes":[]}]}"#.into(),
            ),
            error_message: None,
            dialect: "postgresql".into(),
            collected_at: "2026-01-01T00:00:00Z".into(),
            agent_id: "agent-1".into(),
        }
    }

    #[test]
    fn db_not_found() {
        let uc = GetSchema {
            database_registry: Arc::new(FakeRegistry { pairs: vec![] }),
            schema_repo: Arc::new(FakeSchemaRepo {
                snapshot: Mutex::new(None),
            }),
            authorizer: Arc::new(AllowAuth),
        };
        let err = uc
            .execute(
                GetSchemaInput {
                    database: "nope".into(),
                    environment: None,
                    table: None,
                    summary: true,
                },
                &user(),
            )
            .unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)));
    }

    #[test]
    fn summary_mode() {
        let uc = GetSchema {
            database_registry: Arc::new(FakeRegistry {
                pairs: vec![(
                    DatabaseName::new("app").unwrap(),
                    Environment::new("production").unwrap(),
                )],
            }),
            schema_repo: Arc::new(FakeSchemaRepo {
                snapshot: Mutex::new(Some(snapshot_record())),
            }),
            authorizer: Arc::new(AllowAuth),
        };
        let out = uc
            .execute(
                GetSchemaInput {
                    database: "app".into(),
                    environment: None,
                    table: None,
                    summary: true,
                },
                &user(),
            )
            .unwrap();
        assert_eq!(out.environment, "production");
        match out.body {
            SchemaBody::TableList { ref tables } => {
                assert_eq!(tables.len(), 1);
                assert_eq!(tables[0]["name"], "users");
                assert_eq!(tables[0]["column_count"], 1);
            }
            _ => panic!("expected TableList"),
        }
    }

    #[test]
    fn single_table_filter() {
        let uc = GetSchema {
            database_registry: Arc::new(FakeRegistry {
                pairs: vec![(
                    DatabaseName::new("app").unwrap(),
                    Environment::new("production").unwrap(),
                )],
            }),
            schema_repo: Arc::new(FakeSchemaRepo {
                snapshot: Mutex::new(Some(snapshot_record())),
            }),
            authorizer: Arc::new(AllowAuth),
        };
        let out = uc
            .execute(
                GetSchemaInput {
                    database: "app".into(),
                    environment: None,
                    table: Some("users".into()),
                    summary: false,
                },
                &user(),
            )
            .unwrap();
        match out.body {
            SchemaBody::SingleTable { ref table } => {
                assert_eq!(table["name"], "users");
            }
            _ => panic!("expected SingleTable"),
        }
    }

    #[test]
    fn forbidden_returns_error() {
        let uc = GetSchema {
            database_registry: Arc::new(FakeRegistry {
                pairs: vec![(
                    DatabaseName::new("app").unwrap(),
                    Environment::new("production").unwrap(),
                )],
            }),
            schema_repo: Arc::new(FakeSchemaRepo {
                snapshot: Mutex::new(Some(snapshot_record())),
            }),
            authorizer: Arc::new(DenyAuth),
        };
        let err = uc
            .execute(
                GetSchemaInput {
                    database: "app".into(),
                    environment: None,
                    table: None,
                    summary: true,
                },
                &user(),
            )
            .unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)));
    }
}
