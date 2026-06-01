use std::path::Path;

use dbward_app::ports::{ExecutionTokenClaims, TokenSigner};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

pub struct Ed25519TokenSigner {
    signing_key: SigningKey,
}

impl Ed25519TokenSigner {
    pub fn load_or_generate(data_dir: &Path) -> std::io::Result<Self> {
        let key_path = data_dir.join("signing.key");
        let signing_key = if key_path.exists() {
            let bytes = std::fs::read(&key_path)?;
            if bytes.len() != 32 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid key length",
                ));
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
                // O_EXCL: fail if file already exists (race protection)
                match std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&key_path)
                {
                    Ok(mut f) => f.write_all(&key.to_bytes())?,
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        // Another process created it first — load theirs
                        return Self::load_or_generate(data_dir);
                    }
                    Err(e) => return Err(e),
                }
            }
            #[cfg(not(unix))]
            {
                std::fs::write(&key_path, key.to_bytes())?;
                tracing::warn!(
                    path = %key_path.display(),
                    "Signing key written without restrictive permissions. \
                     On Windows, manually restrict access to this file."
                );
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
            claims.request_id,
            claims.operation,
            claims.environment,
            claims.database,
            detail_hash,
            expires_at,
            claims.requester_role,
            claims.requester,
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
        })
        .to_string()
    }

    fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn generate_and_sign() {
        let dir = tempdir().unwrap();
        let signer = Ed25519TokenSigner::load_or_generate(dir.path()).unwrap();
        let hex = signer.public_key_hex();
        assert_eq!(hex.len(), 64);

        let claims = ExecutionTokenClaims {
            request_id: "req-1".into(),
            operation: "execute_dml".into(),
            environment: "production".into(),
            database: "app".into(),
            detail_hash: "abc123".into(),
            requester_role: "developer".into(),
            requester: "alice".into(),
        };
        let token_json = signer.sign(&claims);
        let v: serde_json::Value = serde_json::from_str(&token_json).unwrap();
        assert_eq!(v["request_id"], "req-1");
        assert_eq!(v["database"], "app");
        assert!(!v["signature"].as_str().unwrap().is_empty());
    }

    #[test]
    fn load_existing_key_is_stable() {
        let dir = tempdir().unwrap();
        let s1 = Ed25519TokenSigner::load_or_generate(dir.path()).unwrap();
        let s2 = Ed25519TokenSigner::load_or_generate(dir.path()).unwrap();
        assert_eq!(s1.public_key_hex(), s2.public_key_hex());
    }

    #[test]
    fn invalid_key_file_returns_error() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("signing.key"), [0u8; 16]).unwrap();
        let result = Ed25519TokenSigner::load_or_generate(dir.path());
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn sign_produces_valid_ed25519_signature() {
        let dir = tempdir().unwrap();
        let signer = Ed25519TokenSigner::load_or_generate(dir.path()).unwrap();
        let claims = ExecutionTokenClaims {
            request_id: "req-2".into(),
            operation: "migrate_up".into(),
            environment: "staging".into(),
            database: "mydb".into(),
            detail_hash: "deadbeef".into(),
            requester_role: "admin".into(),
            requester: "bob".into(),
        };
        let token_json = signer.sign(&claims);
        let v: serde_json::Value = serde_json::from_str(&token_json).unwrap();

        // Verify signature with public key
        use ed25519_dalek::Verifier;
        let sig_hex = v["signature"].as_str().unwrap();
        let sig_bytes = hex::decode(sig_hex).unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes.try_into().unwrap());
        let message = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            v["request_id"].as_str().unwrap(),
            v["operation"].as_str().unwrap(),
            v["environment"].as_str().unwrap(),
            v["database"].as_str().unwrap(),
            v["detail_hash"].as_str().unwrap(),
            v["expires_at"].as_str().unwrap(),
            v["requester_role"].as_str().unwrap(),
            v["requester_subject_id"].as_str().unwrap(),
        );
        assert!(
            signer
                .public_key()
                .verify(message.as_bytes(), &signature)
                .is_ok()
        );
    }

    #[test]
    fn tampered_request_id_fails_verification() {
        let dir = tempdir().unwrap();
        let signer = Ed25519TokenSigner::load_or_generate(dir.path()).unwrap();
        let claims = ExecutionTokenClaims {
            request_id: "req-original".into(),
            operation: "execute_dml".into(),
            environment: "production".into(),
            database: "app".into(),
            detail_hash: "hash123".into(),
            requester_role: "developer".into(),
            requester: "alice".into(),
        };
        let token_json = signer.sign(&claims);
        let v: serde_json::Value = serde_json::from_str(&token_json).unwrap();

        use ed25519_dalek::Verifier;
        let sig_bytes = hex::decode(v["signature"].as_str().unwrap()).unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes.try_into().unwrap());

        // Tamper: change request_id
        let message = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            "req-TAMPERED",
            v["operation"].as_str().unwrap(),
            v["environment"].as_str().unwrap(),
            v["database"].as_str().unwrap(),
            v["detail_hash"].as_str().unwrap(),
            v["expires_at"].as_str().unwrap(),
            v["requester_role"].as_str().unwrap(),
            v["requester_subject_id"].as_str().unwrap(),
        );
        assert!(
            signer
                .public_key()
                .verify(message.as_bytes(), &signature)
                .is_err()
        );
    }

    #[test]
    fn tampered_detail_hash_fails_verification() {
        let dir = tempdir().unwrap();
        let signer = Ed25519TokenSigner::load_or_generate(dir.path()).unwrap();
        let claims = ExecutionTokenClaims {
            request_id: "req-3".into(),
            operation: "execute_dml".into(),
            environment: "production".into(),
            database: "app".into(),
            detail_hash: "correct_hash".into(),
            requester_role: "developer".into(),
            requester: "alice".into(),
        };
        let token_json = signer.sign(&claims);
        let v: serde_json::Value = serde_json::from_str(&token_json).unwrap();

        use ed25519_dalek::Verifier;
        let sig_bytes = hex::decode(v["signature"].as_str().unwrap()).unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes.try_into().unwrap());

        // Tamper: change detail_hash (attacker tries different SQL)
        let message = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            v["request_id"].as_str().unwrap(),
            v["operation"].as_str().unwrap(),
            v["environment"].as_str().unwrap(),
            v["database"].as_str().unwrap(),
            "TAMPERED_HASH",
            v["expires_at"].as_str().unwrap(),
            v["requester_role"].as_str().unwrap(),
            v["requester_subject_id"].as_str().unwrap(),
        );
        assert!(
            signer
                .public_key()
                .verify(message.as_bytes(), &signature)
                .is_err()
        );
    }

    #[test]
    fn tampered_database_field_fails_verification() {
        let dir = tempdir().unwrap();
        let signer = Ed25519TokenSigner::load_or_generate(dir.path()).unwrap();
        let claims = ExecutionTokenClaims {
            request_id: "req-4".into(),
            operation: "execute_dml".into(),
            environment: "staging".into(),
            database: "app".into(),
            detail_hash: "hash456".into(),
            requester_role: "developer".into(),
            requester: "alice".into(),
        };
        let token_json = signer.sign(&claims);
        let v: serde_json::Value = serde_json::from_str(&token_json).unwrap();

        use ed25519_dalek::Verifier;
        let sig_bytes = hex::decode(v["signature"].as_str().unwrap()).unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes.try_into().unwrap());

        // Tamper: change database (attacker targets different DB)
        let message = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            v["request_id"].as_str().unwrap(),
            v["operation"].as_str().unwrap(),
            v["environment"].as_str().unwrap(),
            "EVIL_DB",
            v["detail_hash"].as_str().unwrap(),
            v["expires_at"].as_str().unwrap(),
            v["requester_role"].as_str().unwrap(),
            v["requester_subject_id"].as_str().unwrap(),
        );
        assert!(
            signer
                .public_key()
                .verify(message.as_bytes(), &signature)
                .is_err()
        );
    }

    #[test]
    fn tampered_environment_fails_verification() {
        let dir = tempdir().unwrap();
        let signer = Ed25519TokenSigner::load_or_generate(dir.path()).unwrap();
        let claims = ExecutionTokenClaims {
            request_id: "req-5".into(),
            operation: "execute_dml".into(),
            environment: "staging".into(),
            database: "app".into(),
            detail_hash: "hash789".into(),
            requester_role: "developer".into(),
            requester: "alice".into(),
        };
        let token_json = signer.sign(&claims);
        let v: serde_json::Value = serde_json::from_str(&token_json).unwrap();

        use ed25519_dalek::Verifier;
        let sig_bytes = hex::decode(v["signature"].as_str().unwrap()).unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes.try_into().unwrap());

        // Tamper: escalate to production
        let message = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            v["request_id"].as_str().unwrap(),
            v["operation"].as_str().unwrap(),
            "production",
            v["database"].as_str().unwrap(),
            v["detail_hash"].as_str().unwrap(),
            v["expires_at"].as_str().unwrap(),
            v["requester_role"].as_str().unwrap(),
            v["requester_subject_id"].as_str().unwrap(),
        );
        assert!(
            signer
                .public_key()
                .verify(message.as_bytes(), &signature)
                .is_err()
        );
    }

    #[test]
    fn different_signer_key_fails_verification() {
        let dir1 = tempdir().unwrap();
        let dir2 = tempdir().unwrap();
        let signer1 = Ed25519TokenSigner::load_or_generate(dir1.path()).unwrap();
        let signer2 = Ed25519TokenSigner::load_or_generate(dir2.path()).unwrap();

        let claims = ExecutionTokenClaims {
            request_id: "req-6".into(),
            operation: "execute_dml".into(),
            environment: "production".into(),
            database: "app".into(),
            detail_hash: "hashXYZ".into(),
            requester_role: "admin".into(),
            requester: "bob".into(),
        };
        let token_json = signer1.sign(&claims);
        let v: serde_json::Value = serde_json::from_str(&token_json).unwrap();

        use ed25519_dalek::Verifier;
        let sig_bytes = hex::decode(v["signature"].as_str().unwrap()).unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes.try_into().unwrap());

        let message = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            v["request_id"].as_str().unwrap(),
            v["operation"].as_str().unwrap(),
            v["environment"].as_str().unwrap(),
            v["database"].as_str().unwrap(),
            v["detail_hash"].as_str().unwrap(),
            v["expires_at"].as_str().unwrap(),
            v["requester_role"].as_str().unwrap(),
            v["requester_subject_id"].as_str().unwrap(),
        );
        // Verify with different key should fail (rogue server)
        assert!(
            signer2
                .public_key()
                .verify(message.as_bytes(), &signature)
                .is_err()
        );
    }
}
