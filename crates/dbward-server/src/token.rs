use std::path::Path;

use chrono::{Duration, Utc};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionToken {
    pub request_id: String,
    pub operation: String,
    pub environment: String,
    pub detail_hash: String,
    pub issued_at: String,
    pub expires_at: String,
    pub signature: String,
}

pub struct TokenSigner {
    signing_key: SigningKey,
}

impl TokenSigner {
    /// Load or generate Ed25519 keypair.
    pub fn load_or_generate(data_dir: &Path) -> Result<Self, String> {
        let key_path = data_dir.join("signing.key");
        let pub_path = data_dir.join("signing.pub");

        let signing_key = if key_path.exists() {
            let bytes = std::fs::read(&key_path).map_err(|e| e.to_string())?;
            let key_bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| "invalid signing key file".to_string())?;
            SigningKey::from_bytes(&key_bytes)
        } else {
            std::fs::create_dir_all(data_dir).map_err(|e| e.to_string())?;
            let mut rng = rand::rngs::OsRng {};
            let key = SigningKey::generate(&mut rng);
            std::fs::write(&key_path, key.to_bytes()).map_err(|e| e.to_string())?;
            std::fs::write(&pub_path, key.verifying_key().to_bytes())
                .map_err(|e| e.to_string())?;
            eprintln!("Generated signing keypair: {}", pub_path.display());
            key
        };

        Ok(Self { signing_key })
    }

    #[cfg(test)]
    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng {};
        Self {
            signing_key: SigningKey::generate(&mut rng),
        }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn issue(
        &self,
        request_id: &str,
        operation: &str,
        environment: &str,
        detail: &str,
    ) -> ExecutionToken {
        let detail_hash = hash_detail(detail);
        let issued_at = Utc::now().to_rfc3339();
        let expires_at = (Utc::now() + Duration::hours(1)).to_rfc3339();

        let message = token_message(request_id, operation, environment, &detail_hash, &expires_at);
        let signature = self.signing_key.sign(message.as_bytes());

        ExecutionToken {
            request_id: request_id.to_string(),
            operation: operation.to_string(),
            environment: environment.to_string(),
            detail_hash,
            issued_at,
            expires_at,
            signature: hex::encode(signature.to_bytes()),
        }
    }
}

pub fn hash_detail(detail: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(detail.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn token_message(
    request_id: &str,
    operation: &str,
    environment: &str,
    detail_hash: &str,
    expires_at: &str,
) -> String {
    format!("{request_id}|{operation}|{environment}|{detail_hash}|{expires_at}")
}

/// Verify an execution token using the server's public key.
pub fn verify_token(
    token: &ExecutionToken,
    public_key: &VerifyingKey,
    expected_operation: &str,
    expected_environment: &str,
    expected_detail: &str,
) -> Result<(), String> {
    use ed25519_dalek::Verifier;

    // Check expiry
    let expires = chrono::DateTime::parse_from_rfc3339(&token.expires_at)
        .map_err(|e| format!("invalid expires_at: {e}"))?;
    if Utc::now() > expires {
        return Err("execution token expired".to_string());
    }

    // Check operation/environment match
    if token.operation != expected_operation {
        return Err(format!(
            "operation mismatch: token={}, expected={}",
            token.operation, expected_operation
        ));
    }
    if token.environment != expected_environment {
        return Err(format!(
            "environment mismatch: token={}, expected={}",
            token.environment, expected_environment
        ));
    }

    // Check detail_hash
    let expected_hash = hash_detail(expected_detail);
    if token.detail_hash != expected_hash {
        return Err("detail_hash mismatch: approved content differs from execution content".to_string());
    }

    // Verify Ed25519 signature
    let message = token_message(
        &token.request_id,
        &token.operation,
        &token.environment,
        &token.detail_hash,
        &token.expires_at,
    );
    let sig_bytes = hex::decode(&token.signature).map_err(|e| format!("invalid signature hex: {e}"))?;
    let signature = ed25519_dalek::Signature::from_bytes(
        &sig_bytes
            .try_into()
            .map_err(|_| "invalid signature length")?,
    );
    public_key
        .verify(message.as_bytes(), &signature)
        .map_err(|_| "invalid signature".to_string())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_and_verify() {
        let signer = TokenSigner::generate();
        let token = signer.issue("req_1", "migrate_up", "production", "20260501_create_users.sql");

        let result = verify_token(
            &token,
            &signer.verifying_key(),
            "migrate_up",
            "production",
            "20260501_create_users.sql",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_wrong_detail() {
        let signer = TokenSigner::generate();
        let token = signer.issue("req_1", "execute_query", "staging", "SELECT 1");

        let result = verify_token(
            &token,
            &signer.verifying_key(),
            "execute_query",
            "staging",
            "DELETE FROM users",
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("detail_hash mismatch"));
    }

    #[test]
    fn rejects_wrong_environment() {
        let signer = TokenSigner::generate();
        let token = signer.issue("req_1", "migrate_up", "staging", "test.sql");

        let result = verify_token(
            &token,
            &signer.verifying_key(),
            "migrate_up",
            "production",
            "test.sql",
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("environment mismatch"));
    }

    #[test]
    fn rejects_tampered_signature() {
        let signer = TokenSigner::generate();
        let mut token = signer.issue("req_1", "migrate_up", "production", "test.sql");
        // Tamper with the operation after signing
        token.operation = "execute_query".to_string();

        let result = verify_token(
            &token,
            &signer.verifying_key(),
            "execute_query",
            "production",
            "test.sql",
        );
        assert!(result.is_err());
    }
}
