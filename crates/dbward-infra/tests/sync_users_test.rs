mod common;
use common::*;

use chrono::Utc;
use dbward_app::ports::*;
use dbward_domain::entities::*;
use dbward_infra::sqlite::*;

#[test]
fn list_stale_config_ids_excludes_non_config_users() {
    let conn = setup();
    let user_repo = SqliteUserRepo::new(conn.clone());
    let now = Utc::now();

    let config_user = User {
        id: "config-alice".into(),
        display_name: None,
        email: None,
        groups: vec![],
        roles: vec![],
        status: UserStatus::Active,
        last_seen_at: None,
        created_at: now,
        updated_at: now,
    };
    let token_user = User {
        id: "token-bob".into(),
        display_name: None,
        email: None,
        groups: vec![],
        roles: vec![],
        status: UserStatus::Active,
        last_seen_at: None,
        created_at: now,
        updated_at: now,
    };

    user_repo.upsert(&config_user).unwrap();
    user_repo.set_source("config-alice", "config").unwrap();
    user_repo.upsert(&token_user).unwrap();

    // Only config-managed users appear as stale
    let stale = user_repo.list_stale_config_ids(&[]).unwrap();
    assert_eq!(stale, vec!["config-alice".to_string()]);

    // If active set includes config-alice, stale is empty
    let stale = user_repo
        .list_stale_config_ids(&["config-alice".into()])
        .unwrap();
    assert!(stale.is_empty());
}
