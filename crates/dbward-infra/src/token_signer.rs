use std::path::Path;

use dbward_app::ports::{ExecutionTokenClaims, TokenSigner};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

pub struct Ed25519TokenSigner {
    signing_key: SigningKey,
}

impl Ed25519TokenSigner {
    pub fn load_or_generate(data_dir: &Path) -> std::io::Result<Self> {
        let key_path = data_dir.join("signing.key");
        let signing_key = if key_path.exists() {
            let bytes = std::fs::read(&key_path)?;
            if bytes.len() != 32 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid key length"));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            SigningKey::from_bytes(&arr)
        } else {
            let key = SigningKey::generate(&mut rand::rngs::OsRng);
            std::fs::create_dir_all(data_dir)?;
            #[cfg(unix)]
            {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&key_path)?
                    .write_all(&key.to_bytes())?;
            }
            #[cfg(not(unix))]
            {
                std::fs::write(&key_path, key.to_bytes())?;
            }
            key
        };
        Ok(Self { signing_key })
    }

    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }
}

impl TokenSigner for Ed25519TokenSigner {
    fn sign(&self, claims: &ExecutionTokenClaims) -> String {
        // detail_hash is already computed by the caller (use_case layer)
        // Do NOT re-hash — use as-is to match agent verification
        let detail_hash = &claims.detail_hash;
        let issued_at = chrono::Utc::now().to_rfc3339();
        let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339();

        // Use token_message_v2 format: req|op|env|db|hash|expires|role|subject
        let message = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            claims.request_id, claims.operation, claims.environment,
            claims.database, detail_hash, expires_at,
            claims.requester_role, claims.requester,
        );
        let signature = self.signing_key.sign(message.as_bytes());

        // Output matches ExecutionToken struct expected by agent (dbward-core/token.rs)
        serde_json::json!({
            "request_id": claims.request_id,
            "operation": claims.operation,
            "environment": claims.environment,
            "database": claims.database,
            "detail_hash": detail_hash,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "signature": hex::encode(signature.to_bytes()),
            "requester_role": claims.requester_role,
            "requester_subject_id": claims.requester,
        }).to_string()
    }

    fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }
}
