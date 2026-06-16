use base64::Engine;
use dbward_domain::license::{License, LicensePayload};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

const LICENSE_PREFIX: &str = "dbward_lic_v1.";

const DEFAULT_PUBLIC_KEY: [u8; 32] = [
    0xc4, 0x1b, 0xf5, 0x0b, 0x87, 0x49, 0xb6, 0x93, 0x73, 0x6a, 0x0c, 0x02, 0xff, 0x15, 0x6f, 0x76,
    0xfe, 0xf4, 0x66, 0xae, 0xb1, 0xd3, 0x87, 0x42, 0xfe, 0xbe, 0x99, 0x78, 0x67, 0xe2, 0x47, 0xe8,
];

#[derive(Debug, thiserror::Error)]
pub enum LicenseKeyError {
    #[error("invalid format: expected dbward_lic_v1.<payload>.<signature>")]
    InvalidFormat,
    #[error("invalid base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid payload: {0}")]
    InvalidPayload(String),
}

/// Verify a license key using the public key from env var or the default.
pub fn verify_license_key(key: &str) -> Result<License, LicenseKeyError> {
    let public_key_bytes: [u8; 32] = std::env::var("DBWARD_LICENSE_PUBLIC_KEY")
        .ok()
        .and_then(|h| {
            #[cfg(not(debug_assertions))]
            tracing::warn!(
                "DBWARD_LICENSE_PUBLIC_KEY override active — \
                 this bypasses production license verification"
            );
            hex::decode(&h).ok()
        })
        .and_then(|bytes| bytes.try_into().ok())
        .unwrap_or(DEFAULT_PUBLIC_KEY);

    verify_with_key(key, &public_key_bytes)
}

/// Verify a license key with an explicit public key (for testability).
pub fn verify_with_key(key: &str, public_key: &[u8; 32]) -> Result<License, LicenseKeyError> {
    let key = key.trim();
    let body = key
        .strip_prefix(LICENSE_PREFIX)
        .ok_or(LicenseKeyError::InvalidFormat)?;
    let (payload_b64, sig_b64) = body
        .rsplit_once('.')
        .ok_or(LicenseKeyError::InvalidFormat)?;

    let payload_bytes = base64::engine::general_purpose::STANDARD.decode(payload_b64)?;
    let sig_bytes = base64::engine::general_purpose::STANDARD.decode(sig_b64)?;

    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| LicenseKeyError::InvalidSignature)?;
    let signature = Signature::from_bytes(
        sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| LicenseKeyError::InvalidSignature)?,
    );

    verifying_key
        .verify(&payload_bytes, &signature)
        .map_err(|_| LicenseKeyError::InvalidSignature)?;

    let payload: LicensePayload = serde_json::from_slice(&payload_bytes)
        .map_err(|e| LicenseKeyError::InvalidPayload(e.to_string()))?;

    Ok(License::from(payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use chrono::Utc;
    use dbward_domain::license::Plan;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn generate_test_key(payload: &LicensePayload, signing_key: &SigningKey) -> String {
        let payload_bytes = serde_json::to_vec(payload).unwrap();
        let signature = signing_key.sign(&payload_bytes);
        let payload_b64 = STANDARD.encode(&payload_bytes);
        let sig_b64 = STANDARD.encode(signature.to_bytes());
        format!("dbward_lic_v1.{payload_b64}.{sig_b64}")
    }

    fn test_payload() -> LicensePayload {
        LicensePayload {
            key_id: "key-test-001".into(),
            plan: Plan::Pro,
            issued_to: "test-org".into(),
            issued_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::days(365),
        }
    }

    #[test]
    fn valid_key_verifies_successfully() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let pub_key = signing_key.verifying_key().to_bytes();
        let payload = test_payload();
        let key = generate_test_key(&payload, &signing_key);

        let license = verify_with_key(&key, &pub_key).unwrap();
        assert_eq!(license.plan, Plan::Pro);
        assert_eq!(license.issued_to.as_deref(), Some("test-org"));
        assert!(license.expires_at.is_some());
    }

    #[test]
    fn tampered_payload_fails_signature() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let pub_key = signing_key.verifying_key().to_bytes();
        let payload = test_payload();
        let key = generate_test_key(&payload, &signing_key);

        // Tamper: replace payload with different content but keep original signature
        let parts: Vec<&str> = key
            .strip_prefix("dbward_lic_v1.")
            .unwrap()
            .rsplitn(2, '.')
            .collect();
        let sig_b64 = parts[0];
        let tampered_payload = serde_json::to_vec(&LicensePayload {
            key_id: "tampered".into(),
            ..payload
        })
        .unwrap();
        let tampered_b64 = STANDARD.encode(&tampered_payload);
        let tampered_key = format!("dbward_lic_v1.{tampered_b64}.{sig_b64}");

        assert!(matches!(
            verify_with_key(&tampered_key, &pub_key),
            Err(LicenseKeyError::InvalidSignature)
        ));
    }

    #[test]
    fn missing_prefix_fails() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let pub_key = signing_key.verifying_key().to_bytes();
        assert!(matches!(
            verify_with_key("no_prefix.payload.sig", &pub_key),
            Err(LicenseKeyError::InvalidFormat)
        ));
    }

    #[test]
    fn empty_string_fails() {
        let pub_key = [0u8; 32];
        assert!(matches!(
            verify_with_key("", &pub_key),
            Err(LicenseKeyError::InvalidFormat)
        ));
    }

    #[test]
    fn missing_signature_part_fails() {
        let pub_key = [0u8; 32];
        assert!(matches!(
            verify_with_key("dbward_lic_v1.payloadonly", &pub_key),
            Err(LicenseKeyError::InvalidFormat)
        ));
    }

    #[test]
    fn invalid_base64_fails() {
        let pub_key = [0u8; 32];
        // Use invalid base64 characters
        let result = verify_with_key("dbward_lic_v1.!!!invalid!!!.!!!bad!!!", &pub_key);
        assert!(matches!(result, Err(LicenseKeyError::Base64(_))));
    }

    #[test]
    fn key_id_present_in_payload() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let pub_key = signing_key.verifying_key().to_bytes();
        let payload = LicensePayload {
            key_id: "unique-key-id-42".into(),
            plan: Plan::Enterprise,
            issued_to: "enterprise-corp".into(),
            issued_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::days(30),
        };
        let key = generate_test_key(&payload, &signing_key);

        let license = verify_with_key(&key, &pub_key).unwrap();
        assert_eq!(license.plan, Plan::Enterprise);
        assert_eq!(license.issued_to.as_deref(), Some("enterprise-corp"));
    }
}
