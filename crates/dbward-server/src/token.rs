use std::path::Path;
use chrono::{Duration, Utc};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use tracing::info;

pub use dbward_core::token::{ExecutionToken, hash_detail, token_message, verify_token};

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
            let key_bytes = key.to_bytes();
            #[cfg(unix)]
            {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&key_path)
                    .map_err(|e| e.to_string())?
                    .write_all(&key_bytes)
                    .map_err(|e| e.to_string())?;
            }
            #[cfg(not(unix))]
            {
                std::fs::write(&key_path, &key_bytes).map_err(|e| e.to_string())?;
            }
            std::fs::write(&pub_path, key.verifying_key().to_bytes()).map_err(|e| e.to_string())?;
            info!(path = %pub_path.display(), "generated signing keypair");
            key
        };

        Ok(Self { signing_key })
    }

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
        database: &str,
        detail: &str,
    ) -> ExecutionToken {
        let detail_hash = hash_detail(detail);
        let issued_at = Utc::now().to_rfc3339();
        let expires_at = (Utc::now() + Duration::hours(1)).to_rfc3339();

        let message = token_message(
            request_id,
            operation,
            environment,
            database,
            &detail_hash,
            &expires_at,
        );
        let signature = self.signing_key.sign(message.as_bytes());

        ExecutionToken {
            request_id: request_id.to_string(),
            operation: operation.to_string(),
            environment: environment.to_string(),
            database: database.to_string(),
            detail_hash,
            issued_at,
            expires_at,
            signature: hex::encode(signature.to_bytes()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_and_verify() {
        let signer = TokenSigner::generate();
        let token = signer.issue(
            "req_1",
            "migrate_up",
            "production",
            "default",
            "20260501_create_users.sql",
        );

        let result = verify_token(
            &token,
            &signer.verifying_key(),
            "migrate_up",
            "production",
            "default",
            "20260501_create_users.sql",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_wrong_detail() {
        let signer = TokenSigner::generate();
        let token = signer.issue("req_1", "execute_query", "staging", "default", "SELECT 1");

        let result = verify_token(
            &token,
            &signer.verifying_key(),
            "execute_query",
            "staging",
            "default",
            "DELETE FROM users",
        );
        assert!(result.is_err());
    }

    #[test]
    fn rejects_wrong_environment() {
        let signer = TokenSigner::generate();
        let token = signer.issue("req_1", "migrate_up", "staging", "default", "test.sql");

        let result = verify_token(
            &token,
            &signer.verifying_key(),
            "migrate_up",
            "production",
            "default",
            "test.sql",
        );
        assert!(result.is_err());
    }

    #[test]
    fn rejects_tampered_signature() {
        let signer = TokenSigner::generate();
        let mut token = signer.issue("req_1", "migrate_up", "production", "default", "test.sql");
        token.operation = "execute_query".to_string();

        let result = verify_token(
            &token,
            &signer.verifying_key(),
            "execute_query",
            "production",
            "default",
            "test.sql",
        );
        assert!(result.is_err());
    }
}
