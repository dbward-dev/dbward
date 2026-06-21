use crate::auth::AuthUser;
use crate::policies::workflow::ApproverGroup;

/// Determines whether a user can approve a given workflow step.
/// Shared by Authorizer (single request check) and list filter (pending_for_me).
pub fn is_approvable_by(
    user: &AuthUser,
    approvers: &[ApproverGroup],
    requester_id: &str,
    previous_approver_ids: &[String],
    allow_self_approve: bool,
    allow_same_approver_across_steps: bool,
) -> bool {
    // Self-approve check
    if !allow_self_approve && user.subject_id == requester_id {
        return false;
    }

    let role_names: Vec<String> = user.roles.iter().map(|r| r.name.clone()).collect();
    is_approvable_by_attrs_inner(
        &user.subject_id,
        &role_names,
        &user.groups,
        approvers,
        previous_approver_ids,
        allow_same_approver_across_steps,
    )
}

/// Attribute-based version for use inside TX closures where &AuthUser is not available.
#[allow(clippy::too_many_arguments)]
pub fn is_approvable_by_attrs(
    user_id: &str,
    role_names: &[String],
    groups: &[String],
    approvers: &[ApproverGroup],
    requester_id: &str,
    previous_approver_ids: &[String],
    allow_self_approve: bool,
    allow_same_approver_across_steps: bool,
) -> bool {
    // Self-approve check
    if !allow_self_approve && user_id == requester_id {
        return false;
    }

    is_approvable_by_attrs_inner(
        user_id,
        role_names,
        groups,
        approvers,
        previous_approver_ids,
        allow_same_approver_across_steps,
    )
}

fn is_approvable_by_attrs_inner(
    user_id: &str,
    role_names: &[String],
    groups: &[String],
    approvers: &[ApproverGroup],
    previous_approver_ids: &[String],
    allow_same_approver_across_steps: bool,
) -> bool {
    // Cross-step distinct actors check
    if !allow_same_approver_across_steps && previous_approver_ids.contains(&user_id.to_string()) {
        return false;
    }

    // Check if user matches any approver group's selector
    approvers
        .iter()
        .any(|ag| ag.selector.matches(role_names, groups, user_id, false))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthUser, Permission, ResolvedRole, SubjectType};
    use crate::values::Selector;
    use std::collections::HashSet;

    fn make_user(id: &str, roles: &[&str], groups: &[&str]) -> AuthUser {
        AuthUser {
            subject_id: id.to_string(),
            subject_type: SubjectType::User,
            roles: roles
                .iter()
                .map(|name| ResolvedRole {
                    name: name.to_string(),
                    permissions: HashSet::new(),
                    databases: vec![],
                    environments: vec![],
                })
                .collect(),
            groups: groups.iter().map(|s| s.to_string()).collect(),
            token_id: None,
        }
    }

    fn make_admin(id: &str) -> AuthUser {
        AuthUser {
            subject_id: id.to_string(),
            subject_type: SubjectType::User,
            roles: vec![ResolvedRole {
                name: "admin".to_string(),
                permissions: [Permission::All].into_iter().collect(),
                databases: vec![],
                environments: vec![],
            }],
            groups: vec![],
            token_id: None,
        }
    }

    fn approver_role(role: &str) -> ApproverGroup {
        ApproverGroup {
            selector: Selector::Role(role.to_string()),
            min: 1,
        }
    }

    fn approver_group(group: &str) -> ApproverGroup {
        ApproverGroup {
            selector: Selector::Group(group.to_string()),
            min: 1,
        }
    }

    fn approver_user(user: &str) -> ApproverGroup {
        ApproverGroup {
            selector: Selector::User(user.to_string()),
            min: 1,
        }
    }

    #[test]
    fn matches_by_role() {
        let user = make_user("alice", &["dba"], &[]);
        assert!(is_approvable_by(
            &user,
            &[approver_role("dba")],
            "bob",
            &[],
            true,
            true
        ));
    }

    #[test]
    fn matches_by_group() {
        let user = make_user("alice", &[], &["dba-team"]);
        assert!(is_approvable_by(
            &user,
            &[approver_group("dba-team")],
            "bob",
            &[],
            true,
            true
        ));
    }

    #[test]
    fn matches_by_user() {
        let user = make_user("alice", &[], &[]);
        assert!(is_approvable_by(
            &user,
            &[approver_user("alice")],
            "bob",
            &[],
            true,
            true
        ));
    }

    #[test]
    fn no_match() {
        let user = make_user("alice", &["viewer"], &["frontend"]);
        assert!(!is_approvable_by(
            &user,
            &[approver_role("dba")],
            "bob",
            &[],
            true,
            true
        ));
    }

    #[test]
    fn self_approve_blocked() {
        let user = make_user("alice", &["dba"], &[]);
        assert!(!is_approvable_by(
            &user,
            &[approver_role("dba")],
            "alice",
            &[],
            false,
            true
        ));
    }

    #[test]
    fn self_approve_allowed() {
        let user = make_user("alice", &["dba"], &[]);
        assert!(is_approvable_by(
            &user,
            &[approver_role("dba")],
            "alice",
            &[],
            true,
            true
        ));
    }

    #[test]
    fn cross_step_blocked() {
        let user = make_user("alice", &["dba"], &[]);
        let prev = vec!["alice".to_string()];
        assert!(!is_approvable_by(
            &user,
            &[approver_role("dba")],
            "bob",
            &prev,
            true,
            false
        ));
    }

    #[test]
    fn cross_step_allowed() {
        let user = make_user("alice", &["dba"], &[]);
        let prev = vec!["alice".to_string()];
        assert!(is_approvable_by(
            &user,
            &[approver_role("dba")],
            "bob",
            &prev,
            true,
            true
        ));
    }

    #[test]
    fn admin_does_not_bypass_approver_matching() {
        let admin = make_admin("admin-user");
        assert!(!is_approvable_by(
            &admin,
            &[approver_role("dba")],
            "bob",
            &[],
            true,
            true
        ));
    }

    #[test]
    fn admin_does_not_bypass_cross_step() {
        let admin = make_admin("admin-user");
        let prev = vec!["admin-user".to_string()];
        assert!(!is_approvable_by(
            &admin,
            &[approver_role("dba")],
            "bob",
            &prev,
            true,
            false
        ));
    }

    #[test]
    fn admin_still_blocked_by_self_approve() {
        let admin = make_admin("admin-user");
        assert!(!is_approvable_by(
            &admin,
            &[approver_role("dba")],
            "admin-user",
            &[],
            false,
            true
        ));
    }
}
