//! Adversarial tests for execution token security.
use chrono::{Duration, Utc};
use dbward_core::token::{ExecutionToken, hash_detail, token_message, verify_token};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

fn gen_keypair() -> (SigningKey, VerifyingKey) {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let vk = sk.verifying_key();
    (sk, vk)
}

fn issue(sk: &SigningKey, req_id: &str, op: &str, env: &str, db: &str, detail: &str) -> ExecutionToken {
    let detail_hash = hash_detail(detail);
    let expires_at = (Utc::now() + Duration::hours(1)).to_rfc3339();
    let msg = token_message(req_id, op, env, db, &detail_hash, &expires_at);
    let sig = sk.sign(msg.as_bytes());
    ExecutionToken {
        request_id: req_id.to_string(),
        operation: op.to_string(),
        environment: env.to_string(),
        database: db.to_string(),
        detail_hash,
        issued_at: Utc::now().to_rfc3339(),
        expires_at,
        signature: hex::encode(sig.to_bytes()),
    }
}

// === Signature forgery ===

#[test]
fn wrong_key_rejected() {
    let (sk, _vk) = gen_keypair();
    let (_sk2, vk2) = gen_keypair();
    let token = issue(&sk, "r1", "execute_query", "prod", "app", "SELECT 1");
    assert!(verify_token(&token, &vk2, "execute_query", "prod", "app", "SELECT 1").is_err());
}

#[test]
fn tampered_request_id_rejected() {
    let (sk, vk) = gen_keypair();
    let mut token = issue(&sk, "r1", "execute_query", "prod", "app", "SELECT 1");
    token.request_id = "r2".to_string();
    assert!(verify_token(&token, &vk, "execute_query", "prod", "app", "SELECT 1").is_err());
}

#[test]
fn tampered_detail_hash_rejected() {
    let (sk, vk) = gen_keypair();
    let mut token = issue(&sk, "r1", "execute_query", "prod", "app", "SELECT 1");
    token.detail_hash = hash_detail("DELETE FROM users");
    assert!(verify_token(&token, &vk, "execute_query", "prod", "app", "SELECT 1").is_err());
}

#[test]
fn different_detail_at_verify_rejected() {
    let (sk, vk) = gen_keypair();
    let token = issue(&sk, "r1", "execute_query", "prod", "app", "SELECT 1");
    // Agent tries to execute different SQL
    assert!(verify_token(&token, &vk, "execute_query", "prod", "app", "DELETE FROM users").is_err());
}

#[test]
fn environment_swap_rejected() {
    let (sk, vk) = gen_keypair();
    let token = issue(&sk, "r1", "execute_query", "staging", "app", "SELECT 1");
    assert!(verify_token(&token, &vk, "execute_query", "production", "app", "SELECT 1").is_err());
}

#[test]
fn database_swap_rejected() {
    let (sk, vk) = gen_keypair();
    let token = issue(&sk, "r1", "execute_query", "prod", "app", "SELECT 1");
    assert!(verify_token(&token, &vk, "execute_query", "prod", "billing", "SELECT 1").is_err());
}

// === Expiry ===

#[test]
fn expired_token_rejected() {
    let (sk, vk) = gen_keypair();
    let detail_hash = hash_detail("SELECT 1");
    let expires_at = (Utc::now() - Duration::hours(1)).to_rfc3339();
    let msg = token_message("r1", "execute_query", "prod", "app", &detail_hash, &expires_at);
    let sig = sk.sign(msg.as_bytes());
    let token = ExecutionToken {
        request_id: "r1".to_string(),
        operation: "execute_query".to_string(),
        environment: "prod".to_string(),
        database: "app".to_string(),
        detail_hash,
        issued_at: (Utc::now() - Duration::hours(2)).to_rfc3339(),
        expires_at,
        signature: hex::encode(sig.to_bytes()),
    };
    assert!(verify_token(&token, &vk, "execute_query", "prod", "app", "SELECT 1").is_err());
}

// === Signature manipulation ===

#[test]
fn zero_signature_rejected() {
    let (sk, vk) = gen_keypair();
    let mut token = issue(&sk, "r1", "execute_query", "prod", "app", "SELECT 1");
    token.signature = "00".repeat(64);
    assert!(verify_token(&token, &vk, "execute_query", "prod", "app", "SELECT 1").is_err());
}

#[test]
fn truncated_signature_rejected() {
    let (sk, vk) = gen_keypair();
    let mut token = issue(&sk, "r1", "execute_query", "prod", "app", "SELECT 1");
    token.signature = token.signature[..32].to_string();
    assert!(verify_token(&token, &vk, "execute_query", "prod", "app", "SELECT 1").is_err());
}

#[test]
fn invalid_hex_signature_rejected() {
    let (sk, vk) = gen_keypair();
    let mut token = issue(&sk, "r1", "execute_query", "prod", "app", "SELECT 1");
    token.signature = "not_hex_at_all".to_string();
    assert!(verify_token(&token, &vk, "execute_query", "prod", "app", "SELECT 1").is_err());
}

// === Operation escalation ===

#[test]
fn operation_escalation_rejected() {
    let (sk, vk) = gen_keypair();
    // Token issued for execute_query, agent tries to use for migrate_up
    let token = issue(&sk, "r1", "execute_query", "prod", "app", "SELECT 1");
    assert!(verify_token(&token, &vk, "migrate_up", "prod", "app", "SELECT 1").is_err());
}
