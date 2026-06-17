//! Cryptographic ports for audit signing and verification.
//!
//! Separate from `TokenSigner` which handles execution token claims only.
//! These sign/verify arbitrary byte payloads for checkpoints and purge operations.

/// Signs audit payloads (checkpoints, purge tombstones).
pub trait AuditSigner: Send + Sync {
    /// Returns the current key_id.
    fn current_key_id(&self) -> &str;

    /// Sign raw bytes, returning signature bytes.
    fn sign(&self, payload: &[u8]) -> Vec<u8>;
}

/// Verifies audit signatures. Supports historical keys via key ring.
pub trait AuditVerifier: Send + Sync {
    /// Verify with the current key.
    fn verify(&self, payload: &[u8], signature: &[u8]) -> bool;

    /// Verify with a specific historical key_id.
    fn verify_with_key(&self, key_id: &str, payload: &[u8], signature: &[u8]) -> bool;
}
