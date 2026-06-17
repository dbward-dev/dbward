use std::collections::HashMap;
use std::path::Path;

use dbward_app::ports::crypto::{AuditSigner, AuditVerifier};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Key ring entry: key_id → public key bytes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct KeyRingFile {
    current: String,
    keys: HashMap<String, String>, // key_id → base64-encoded public key
}

/// Ed25519 audit signer with key ring support for historical verification.
pub struct Ed25519AuditCrypto {
    key_id: String,
    signing_key: SigningKey,
    key_ring: HashMap<String, VerifyingKey>,
}

impl Ed25519AuditCrypto {
    /// Load or generate an audit signing key. Maintains a key ring file for verification.
    pub fn load_or_generate(data_dir: &Path) -> std::io::Result<Self> {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;

        let key_path = data_dir.join("audit-signing.key");
        let ring_path = data_dir.join("audit-keys.json");

        let signing_key = if key_path.exists() {
            let bytes = std::fs::read(&key_path)?;
            if bytes.len() != 32 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid audit key length",
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
                match std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&key_path)
                {
                    Ok(mut f) => f.write_all(&key.to_bytes())?,
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        return Self::load_or_generate(data_dir);
                    }
                    Err(e) => return Err(e),
                }
            }
            #[cfg(not(unix))]
            {
                std::fs::write(&key_path, key.to_bytes())?;
            }
            key
        };

        let verifying_key = signing_key.verifying_key();
        let pub_b64 = engine.encode(verifying_key.as_bytes());

        // Load or create key ring
        let mut ring_file = if ring_path.exists() {
            let content = std::fs::read_to_string(&ring_path)?;
            serde_json::from_str::<KeyRingFile>(&content).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, format!("key ring: {e}"))
            })?
        } else {
            KeyRingFile {
                current: String::new(),
                keys: HashMap::new(),
            }
        };

        // Ensure current key is in the ring
        let key_id = if let Some((id, _)) = ring_file.keys.iter().find(|(_, v)| *v == &pub_b64) {
            id.clone()
        } else {
            let id = format!("k-{}", chrono::Utc::now().format("%Y%m%d%H%M%S"));
            ring_file.keys.insert(id.clone(), pub_b64);
            id
        };
        ring_file.current = key_id.clone();

        let ring_json = serde_json::to_string_pretty(&ring_file)
            .map_err(|e| std::io::Error::other(format!("serialize ring: {e}")))?;
        std::fs::write(&ring_path, ring_json)?;

        // Build verifying key map
        let mut key_ring = HashMap::new();
        for (id, b64) in &ring_file.keys {
            if let Ok(bytes) = engine.decode(b64)
                && let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice())
                && let Ok(vk) = VerifyingKey::from_bytes(&arr)
            {
                key_ring.insert(id.clone(), vk);
            } else {
                tracing::warn!(key_id = %id, "skipping corrupt key ring entry");
            }
        }

        Ok(Self {
            key_id,
            signing_key,
            key_ring,
        })
    }
}

impl AuditSigner for Ed25519AuditCrypto {
    fn current_key_id(&self) -> &str {
        &self.key_id
    }

    fn sign(&self, payload: &[u8]) -> Vec<u8> {
        self.signing_key.sign(payload).to_bytes().to_vec()
    }
}

impl AuditVerifier for Ed25519AuditCrypto {
    fn verify(&self, payload: &[u8], signature: &[u8]) -> bool {
        self.verify_with_key(&self.key_id, payload, signature)
    }

    fn verify_with_key(&self, key_id: &str, payload: &[u8], signature: &[u8]) -> bool {
        let Some(vk) = self.key_ring.get(key_id) else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(signature) else {
            return false;
        };
        vk.verify(payload, &sig).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn sign_and_verify_roundtrip() {
        let dir = TempDir::new().unwrap();
        let crypto = Ed25519AuditCrypto::load_or_generate(dir.path()).unwrap();

        let payload = b"audit-checkpoint:v1|abc123|50|2025-01-01T00:00:00Z";
        let sig = crypto.sign(payload);

        assert!(crypto.verify(payload, &sig));
        assert!(!crypto.verify(b"tampered", &sig));
    }

    #[test]
    fn key_ring_persists_across_loads() {
        let dir = TempDir::new().unwrap();
        let crypto1 = Ed25519AuditCrypto::load_or_generate(dir.path()).unwrap();
        let key_id = crypto1.current_key_id().to_string();
        let sig = crypto1.sign(b"hello");

        // Reload
        let crypto2 = Ed25519AuditCrypto::load_or_generate(dir.path()).unwrap();
        assert_eq!(crypto2.current_key_id(), key_id);
        assert!(crypto2.verify_with_key(&key_id, b"hello", &sig));
    }

    #[test]
    fn invalid_signature_rejected() {
        let dir = TempDir::new().unwrap();
        let crypto = Ed25519AuditCrypto::load_or_generate(dir.path()).unwrap();

        assert!(!crypto.verify(b"payload", &[0u8; 64]));
        assert!(!crypto.verify(b"payload", &[0u8; 10])); // wrong length
    }

    #[test]
    fn unknown_key_id_rejected() {
        let dir = TempDir::new().unwrap();
        let crypto = Ed25519AuditCrypto::load_or_generate(dir.path()).unwrap();
        let sig = crypto.sign(b"payload");

        assert!(!crypto.verify_with_key("k-nonexistent", b"payload", &sig));
    }
}
