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
        &token.detail_hash,
        &token.expires_at,
    );
    let sig_bytes =
        hex::decode(&token.signature).map_err(|e| Error::Token(format!("invalid signature: {e}")))?;
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

/// Load a public key from file.
pub fn load_public_key(path: &std::path::Path) -> Result<VerifyingKey, Error> {
    let bytes = std::fs::read(path).map_err(Error::Io)?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::Token("invalid public key file".into()))?;
    VerifyingKey::from_bytes(&key_bytes).map_err(|e| Error::Token(format!("invalid public key: {e}")))
}
