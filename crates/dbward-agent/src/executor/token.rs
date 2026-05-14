use dbward_api_types::agent::ClaimResponse;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::AgentError;

/// Typed execution token. Fields are private; only `verify()` is the public API.
/// `issued_at` is intentionally omitted (not used in verification, serde ignores unknown fields).
#[derive(Debug, Deserialize)]
pub(crate) struct ExecutionToken {
    request_id: String,
    operation: String,
    environment: String,
    database: String,
    detail_hash: String,
    expires_at: String,
    signature: String,
    #[serde(default)]
    requester_role: String,
    // ADR-008: server currently sets both slots to `claims.requester`.
    // v0.2.0 will separate requester_role and requester_subject_id.
    #[serde(default)]
    requester_subject_id: String,
}

impl ExecutionToken {
    pub fn parse(raw: &str) -> Result<Self, AgentError> {
        serde_json::from_str(raw)
            .map_err(|e| AgentError::TokenVerification(format!("invalid token JSON: {e}")))
    }

    pub fn verify(
        &self,
        claim: &ClaimResponse,
        public_key: &VerifyingKey,
    ) -> Result<(), AgentError> {
        let exp = chrono::DateTime::parse_from_rfc3339(&self.expires_at)
            .map_err(|e| AgentError::TokenVerification(format!("invalid expires_at: {e}")))?;
        if chrono::Utc::now() > exp {
            return Err(AgentError::TokenVerification("token expired".into()));
        }

        if self.request_id != claim.request_id {
            return Err(AgentError::TokenVerification("request_id mismatch".into()));
        }
        if self.operation != claim.operation {
            return Err(AgentError::TokenVerification("operation mismatch".into()));
        }
        if self.database != claim.database {
            return Err(AgentError::TokenVerification("database mismatch".into()));
        }
        if self.environment != claim.environment {
            return Err(AgentError::TokenVerification("environment mismatch".into()));
        }

        let actual_hash = hex::encode(Sha256::digest(claim.detail.as_bytes()));
        if actual_hash != self.detail_hash {
            return Err(AgentError::TokenVerification("detail_hash mismatch".into()));
        }

        let message = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            claim.request_id,
            claim.operation,
            claim.environment,
            claim.database,
            self.detail_hash,
            self.expires_at,
            self.requester_role,
            self.requester_subject_id,
        );
        let sig_bytes = hex::decode(&self.signature)
            .map_err(|e| AgentError::TokenVerification(format!("invalid signature hex: {e}")))?;
        let signature = Signature::from_slice(&sig_bytes)
            .map_err(|e| AgentError::TokenVerification(format!("invalid signature: {e}")))?;
        public_key
            .verify(message.as_bytes(), &signature)
            .map_err(|e| AgentError::TokenVerification(format!("signature invalid: {e}")))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn make_signing_key() -> SigningKey {
        let mut csprng = rand::rngs::OsRng;
        SigningKey::generate(&mut csprng)
    }

    fn make_claim() -> ClaimResponse {
        ClaimResponse {
            execution_id: "exec-1".into(),
            request_id: "req-1".into(),
            operation: "execute_select".into(),
            environment: "production".into(),
            database: "mydb".into(),
            detail: "SELECT 1".into(),
            execution_token: String::new(),
            statement_timeout_secs: None,
            lease_expires_at: None,
        }
    }

    fn sign_token(claim: &ClaimResponse, signing_key: &SigningKey) -> String {
        let detail_hash = hex::encode(Sha256::digest(claim.detail.as_bytes()));
        let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(5))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let message = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            claim.request_id,
            claim.operation,
            claim.environment,
            claim.database,
            detail_hash,
            expires_at,
            "",
            "",
        );
        let sig = signing_key.sign(message.as_bytes());
        serde_json::json!({
            "request_id": claim.request_id,
            "operation": claim.operation,
            "environment": claim.environment,
            "database": claim.database,
            "detail_hash": detail_hash,
            "expires_at": expires_at,
            "signature": hex::encode(sig.to_bytes()),
            "issued_at": chrono::Utc::now().to_rfc3339(),
        })
        .to_string()
    }

    #[test]
    fn parse_valid() {
        let sk = make_signing_key();
        let claim = make_claim();
        let raw = sign_token(&claim, &sk);
        let token = ExecutionToken::parse(&raw).unwrap();
        assert_eq!(token.request_id, "req-1");
    }

    #[test]
    fn parse_invalid_json() {
        assert!(ExecutionToken::parse("not json").is_err());
    }

    #[test]
    fn parse_missing_field() {
        let raw = r#"{"request_id":"r"}"#;
        assert!(ExecutionToken::parse(raw).is_err());
    }

    #[test]
    fn verify_valid() {
        let sk = make_signing_key();
        let pk = sk.verifying_key();
        let claim = make_claim();
        let raw = sign_token(&claim, &sk);
        let token = ExecutionToken::parse(&raw).unwrap();
        assert!(token.verify(&claim, &pk).is_ok());
    }

    #[test]
    fn verify_expired() {
        let sk = make_signing_key();
        let pk = sk.verifying_key();
        let claim = make_claim();
        let detail_hash = hex::encode(Sha256::digest(claim.detail.as_bytes()));
        let expires_at = (chrono::Utc::now() - chrono::Duration::minutes(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let message = format!(
            "{}|{}|{}|{}|{}|{}||",
            claim.request_id,
            claim.operation,
            claim.environment,
            claim.database,
            detail_hash,
            expires_at,
        );
        let sig = sk.sign(message.as_bytes());
        let raw = serde_json::json!({
            "request_id": claim.request_id,
            "operation": claim.operation,
            "environment": claim.environment,
            "database": claim.database,
            "detail_hash": detail_hash,
            "expires_at": expires_at,
            "signature": hex::encode(sig.to_bytes()),
        })
        .to_string();
        let token = ExecutionToken::parse(&raw).unwrap();
        let err = token.verify(&claim, &pk).unwrap_err();
        assert!(err.to_string().contains("expired"));
    }

    #[test]
    fn verify_request_id_mismatch() {
        let sk = make_signing_key();
        let pk = sk.verifying_key();
        let claim = make_claim();
        let raw = sign_token(&claim, &sk);
        let token = ExecutionToken::parse(&raw).unwrap();
        let mut bad_claim = claim;
        bad_claim.request_id = "wrong".into();
        let err = token.verify(&bad_claim, &pk).unwrap_err();
        assert!(err.to_string().contains("request_id mismatch"));
    }

    #[test]
    fn verify_detail_hash_mismatch() {
        let sk = make_signing_key();
        let pk = sk.verifying_key();
        let claim = make_claim();
        let raw = sign_token(&claim, &sk);
        let token = ExecutionToken::parse(&raw).unwrap();
        let mut bad_claim = claim;
        bad_claim.detail = "TAMPERED".into();
        let err = token.verify(&bad_claim, &pk).unwrap_err();
        assert!(err.to_string().contains("detail_hash mismatch"));
    }

    #[test]
    fn verify_signature_invalid() {
        let sk = make_signing_key();
        let other_sk = make_signing_key();
        let pk = other_sk.verifying_key();
        let claim = make_claim();
        let raw = sign_token(&claim, &sk);
        let token = ExecutionToken::parse(&raw).unwrap();
        let err = token.verify(&claim, &pk).unwrap_err();
        assert!(err.to_string().contains("signature invalid"));
    }
}
