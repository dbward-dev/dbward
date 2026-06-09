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

        // SAFE-3: when execution_plan_json is present, hash the raw JSON string directly.
        // This avoids re-serialization and guarantees hash consistency with the server.
        let canonical_detail = if let Some(ref plan_json) = claim.execution_plan_json {
            plan_json.clone()
        } else if claim.operation == "migrate_up"
            || claim.operation == "migrate_down"
            || claim.operation == "migrate_repair"
        {
            serde_json::from_str::<serde_json::Value>(&claim.detail)
                .and_then(|v| serde_json::to_string(&v))
                .unwrap_or_else(|_| claim.detail.clone())
        } else {
            claim.detail.clone()
        };
        let actual_hash = hex::encode(Sha256::digest(canonical_detail.as_bytes()));
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
            max_rows: None,
            lease_expires_at: None,
            execution_plan: None,
            execution_plan_json: None,
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

    #[test]
    fn verify_operation_mismatch() {
        let sk = make_signing_key();
        let pk = sk.verifying_key();
        let claim = make_claim();
        let raw = sign_token(&claim, &sk);
        let token = ExecutionToken::parse(&raw).unwrap();
        let mut bad_claim = claim;
        bad_claim.operation = "execute_dml".into();
        let err = token.verify(&bad_claim, &pk).unwrap_err();
        assert!(err.to_string().contains("operation mismatch"));
    }

    #[test]
    fn verify_database_mismatch() {
        let sk = make_signing_key();
        let pk = sk.verifying_key();
        let claim = make_claim();
        let raw = sign_token(&claim, &sk);
        let token = ExecutionToken::parse(&raw).unwrap();
        let mut bad_claim = claim;
        bad_claim.database = "evil_db".into();
        let err = token.verify(&bad_claim, &pk).unwrap_err();
        assert!(err.to_string().contains("database mismatch"));
    }

    #[test]
    fn verify_environment_mismatch() {
        let sk = make_signing_key();
        let pk = sk.verifying_key();
        let claim = make_claim();
        let raw = sign_token(&claim, &sk);
        let token = ExecutionToken::parse(&raw).unwrap();
        let mut bad_claim = claim;
        bad_claim.environment = "staging".into();
        let err = token.verify(&bad_claim, &pk).unwrap_err();
        assert!(err.to_string().contains("environment mismatch"));
    }

    #[test]
    fn verify_with_execution_plan_json() {
        let sk = make_signing_key();
        let pk = sk.verifying_key();
        let plan_json = r#"["SELECT id, name FROM users"]"#.to_string();
        let mut claim = make_claim();
        claim.execution_plan_json = Some(plan_json.clone());
        claim.execution_plan = Some(vec!["SELECT id, name FROM users".into()]);

        // Sign with plan_json hash
        let detail_hash = hex::encode(Sha256::digest(plan_json.as_bytes()));
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
        assert!(token.verify(&claim, &pk).is_ok());
    }

    #[test]
    fn verify_execution_plan_json_tampered() {
        let sk = make_signing_key();
        let pk = sk.verifying_key();
        let plan_json = r#"["SELECT id FROM users"]"#.to_string();
        let mut claim = make_claim();
        claim.execution_plan_json = Some(plan_json.clone());

        let raw = sign_token(&claim, &sk); // signs with claim.detail hash
        let token = ExecutionToken::parse(&raw).unwrap();
        // Token was signed against detail, but verify uses execution_plan_json → mismatch
        let err = token.verify(&claim, &pk).unwrap_err();
        assert!(err.to_string().contains("detail_hash mismatch"));
    }

    #[test]
    fn verify_falls_back_to_detail_when_execution_plan_json_none() {
        // execution_plan_json = None → token verification uses claim.detail
        let sk = make_signing_key();
        let pk = sk.verifying_key();
        let claim = make_claim(); // execution_plan_json = None
        let raw = sign_token(&claim, &sk); // signs with detail hash
        let token = ExecutionToken::parse(&raw).unwrap();
        assert!(token.verify(&claim, &pk).is_ok());
    }

    #[test]
    fn verify_execution_plan_json_takes_precedence_over_detail() {
        // When both exist but disagree, hash must use execution_plan_json
        let sk = make_signing_key();
        let pk = sk.verifying_key();
        let plan_json = r#"["SELECT 42"]"#.to_string();
        let mut claim = make_claim();
        claim.detail = "SELECT 999".into(); // different from plan
        claim.execution_plan_json = Some(plan_json.clone());

        // Sign with plan_json hash (what server does)
        let detail_hash = hex::encode(Sha256::digest(plan_json.as_bytes()));
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
        // Passes because verify uses execution_plan_json, not detail
        assert!(token.verify(&claim, &pk).is_ok());
    }

    #[test]
    fn verify_migration_canonicalizes_json_field_order() {
        // Server canonicalizes migration JSON before hashing (alphabetical keys).
        // Agent must do the same — different field order must still verify.
        let sk = make_signing_key();
        let pk = sk.verifying_key();

        let mut claim = make_claim();
        claim.operation = "migrate_up".into();
        // Detail with non-alphabetical field order
        claim.detail = r#"{"version":"001","sql":"CREATE TABLE t (id INT)"}"#.into();
        claim.execution_plan_json = None; // migrations don't have execution_plan

        // Server canonicalizes: keys sorted alphabetically
        let canonical = serde_json::to_string(
            &serde_json::from_str::<serde_json::Value>(&claim.detail).unwrap(),
        )
        .unwrap();
        let detail_hash = hex::encode(Sha256::digest(canonical.as_bytes()));
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
        assert!(token.verify(&claim, &pk).is_ok());
    }
}
