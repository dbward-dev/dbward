use chrono::Utc;
use ed25519_dalek::{Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionToken {
    pub request_id: String,
    pub operation: String,
    pub environment: String,
    pub database: String,
    pub detail_hash: String,
    pub issued_at: String,
    pub expires_at: String,
    pub signature: String,
}

pub fn hash_detail(detail: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(detail.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn token_message(
    request_id: &str,
    operation: &str,
    environment: &str,
    database: &str,
    detail_hash: &str,
    expires_at: &str,
) -> String {
    format!("{request_id}|{operation}|{environment}|{database}|{detail_hash}|{expires_at}")
}

/// Verify an execution token using the server's public key.
pub fn verify_token(
    token: &ExecutionToken,
    public_key: &VerifyingKey,
    expected_operation: &str,
    expected_environment: &str,
    expected_database: &str,
    expected_detail: &str,
) -> Result<(), Error> {
    // Check expiry
    let expires = chrono::DateTime::parse_from_rfc3339(&token.expires_at)
        .map_err(|e| Error::Token(format!("invalid expires_at: {e}")))?;
    if Utc::now() > expires {
        return Err(Error::Token("execution token expired".into()));
    }

    if token.operation != expected_operation {
        return Err(Error::Token(format!(
            "operation mismatch: token={}, expected={}",
            token.operation, expected_operation
        )));
    }
    if token.environment != expected_environment {
        return Err(Error::Token(format!(
            "environment mismatch: token={}, expected={}",
            token.environment, expected_environment
        )));
    }
    if token.database != expected_database {
        return Err(Error::Token(format!(
            "database mismatch: token={}, expected={}",
            token.database, expected_database
        )));
    }

    let expected_hash = hash_detail(expected_detail);
    if token.detail_hash != expected_hash {
        return Err(Error::Token(
            "detail_hash mismatch: approved content differs from execution content".into(),
        ));
    }

    let message = token_message(
        &token.request_id,
        &token.operation,
        &token.environment,
        &token.database,
        &token.detail_hash,
        &token.expires_at,
    );
    let sig_bytes = hex::decode(&token.signature)
        .map_err(|e| Error::Token(format!("invalid signature: {e}")))?;
    let signature = ed25519_dalek::Signature::from_bytes(
        &sig_bytes
            .try_into()
            .map_err(|_| Error::Token("invalid signature length".into()))?,
    );
    public_key
        .verify(message.as_bytes(), &signature)
        .map_err(|_| Error::Token("invalid signature".into()))?;

    Ok(())
}

/// Load a public key from a file (32-byte raw Ed25519 public key).
pub fn load_public_key(path: &std::path::Path) -> Result<VerifyingKey, Error> {
    let bytes = std::fs::read(path).map_err(Error::Io)?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::Token("invalid public key file".into()))?;
    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| Error::Token(format!("invalid public key: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use ed25519_dalek::{Signer, SigningKey};

    fn make_token(
        signing_key: &SigningKey,
        op: &str,
        env: &str,
        detail: &str,
        expires_at: chrono::DateTime<Utc>,
    ) -> ExecutionToken {
        let detail_hash = hash_detail(detail);
        let expires_str = expires_at.to_rfc3339();
        let msg = token_message("req-1", op, env, "default", &detail_hash, &expires_str);
        let sig = signing_key.sign(msg.as_bytes());
        ExecutionToken {
            request_id: "req-1".into(),
            operation: op.into(),
            environment: env.into(),
            database: "default".into(),
            detail_hash,
            issued_at: Utc::now().to_rfc3339(),
            expires_at: expires_str,
            signature: hex::encode(sig.to_bytes()),
        }
    }

    fn keypair() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    #[test]
    fn valid_token_passes() {
        let (sk, vk) = keypair();
        let token = make_token(
            &sk,
            "execute",
            "production",
            "SELECT 1",
            Utc::now() + Duration::hours(1),
        );
        assert!(verify_token(&token, &vk, "execute", "production", "default", "SELECT 1").is_ok());
    }

    #[test]
    fn expired_token_rejected() {
        let (sk, vk) = keypair();
        let token = make_token(
            &sk,
            "execute",
            "production",
            "SELECT 1",
            Utc::now() - Duration::seconds(1),
        );
        let err =
            verify_token(&token, &vk, "execute", "production", "default", "SELECT 1").unwrap_err();
        assert!(err.to_string().contains("expired"));
    }

    #[test]
    fn operation_mismatch_rejected() {
        let (sk, vk) = keypair();
        let token = make_token(
            &sk,
            "execute",
            "production",
            "SELECT 1",
            Utc::now() + Duration::hours(1),
        );
        let err =
            verify_token(&token, &vk, "migrate", "production", "default", "SELECT 1").unwrap_err();
        assert!(err.to_string().contains("operation mismatch"));
    }

    #[test]
    fn environment_mismatch_rejected() {
        let (sk, vk) = keypair();
        let token = make_token(
            &sk,
            "execute",
            "production",
            "SELECT 1",
            Utc::now() + Duration::hours(1),
        );
        let err =
            verify_token(&token, &vk, "execute", "staging", "default", "SELECT 1").unwrap_err();
        assert!(err.to_string().contains("environment mismatch"));
    }

    #[test]
    fn detail_mismatch_rejected() {
        let (sk, vk) = keypair();
        let token = make_token(
            &sk,
            "execute",
            "production",
            "SELECT 1",
            Utc::now() + Duration::hours(1),
        );
        let err = verify_token(
            &token,
            &vk,
            "execute",
            "production",
            "default",
            "DROP TABLE users",
        )
        .unwrap_err();
        assert!(err.to_string().contains("detail_hash mismatch"));
    }

    #[test]
    fn tampered_signature_rejected() {
        let (sk, vk) = keypair();
        let mut token = make_token(
            &sk,
            "execute",
            "production",
            "SELECT 1",
            Utc::now() + Duration::hours(1),
        );
        // Flip a byte in the signature
        let mut sig_bytes = hex::decode(&token.signature).unwrap();
        sig_bytes[0] ^= 0xff;
        token.signature = hex::encode(sig_bytes);
        let err =
            verify_token(&token, &vk, "execute", "production", "default", "SELECT 1").unwrap_err();
        assert!(err.to_string().contains("invalid signature"));
    }

    #[test]
    fn wrong_key_rejected() {
        let (sk, _) = keypair();
        let (_, other_vk) = keypair();
        let token = make_token(
            &sk,
            "execute",
            "production",
            "SELECT 1",
            Utc::now() + Duration::hours(1),
        );
        let err = verify_token(
            &token,
            &other_vk,
            "execute",
            "production",
            "default",
            "SELECT 1",
        )
        .unwrap_err();
        assert!(err.to_string().contains("invalid signature"));
    }

    #[test]
    fn load_public_key_from_file() {
        let (_, vk) = keypair();
        let dir = std::env::temp_dir().join("dbward-test-token");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.pub");
        std::fs::write(&path, vk.to_bytes()).unwrap();
        let loaded = load_public_key(&path).unwrap();
        assert_eq!(loaded.to_bytes(), vk.to_bytes());
        std::fs::remove_dir_all(&dir).ok();
    }
}
