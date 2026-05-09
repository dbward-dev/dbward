use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;

/// Embedded public key for license verification.
/// Dev/test builds use the test key; release builds use the production key.
#[cfg(feature = "dev")]
const LICENSE_PUBLIC_KEY: &[u8; 32] = include_bytes!("../../../fixtures/license/test-public.key");

#[cfg(not(feature = "dev"))]
const LICENSE_PUBLIC_KEY: &[u8; 32] = include_bytes!("../../../fixtures/license/test-public.key");
// TODO: replace with production public key before v0.1.0 release

#[derive(Debug, Clone, PartialEq)]
pub enum Plan {
    Free,
    Pro,
}

#[derive(Debug, Clone)]
pub struct License {
    pub plan: Plan,
}

#[derive(Deserialize)]
struct LicenseClaims {
    plan: String,
    #[allow(dead_code)]
    org: String,
    expires_at: String,
}

impl License {
    /// Load license from DBWARD_LICENSE_KEY env var or return Free.
    pub fn load() -> Self {
        let key = match std::env::var("DBWARD_LICENSE_KEY") {
            Ok(k) if !k.is_empty() => k,
            _ => return Self { plan: Plan::Free },
        };

        match verify_license_key(&key) {
            Ok(plan) => {
                tracing::info!(plan = ?plan, "License verified");
                Self { plan }
            }
            Err(e) => {
                tracing::warn!(error = %e, "license key invalid, falling back to Free");
                Self { plan: Plan::Free }
            }
        }
    }

    pub fn is_pro(&self) -> bool {
        self.plan == Plan::Pro
    }
}

impl Default for License {
    fn default() -> Self {
        Self::load()
    }
}

fn verify_license_key(raw: &str) -> Result<Plan, String> {
    let (payload_b64, sig_b64) = raw
        .trim()
        .split_once('.')
        .ok_or_else(|| "invalid format: missing '.' separator".to_string())?;

    // Verify signature
    let vk = VerifyingKey::from_bytes(LICENSE_PUBLIC_KEY)
        .map_err(|e| format!("invalid public key: {e}"))?;

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|e| format!("invalid signature encoding: {e}"))?;

    let sig = Signature::from_bytes(
        &sig_bytes
            .try_into()
            .map_err(|_| "invalid signature length".to_string())?,
    );

    vk.verify(payload_b64.as_bytes(), &sig)
        .map_err(|_| "signature verification failed".to_string())?;

    // Decode and parse claims
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| format!("invalid payload encoding: {e}"))?;

    let claims: LicenseClaims =
        serde_json::from_slice(&payload_bytes).map_err(|e| format!("invalid payload: {e}"))?;

    // Check expiration
    let expires = chrono::DateTime::parse_from_rfc3339(&claims.expires_at)
        .map_err(|e| format!("invalid expires_at: {e}"))?;

    if chrono::Utc::now() > expires {
        return Err("license expired".to_string());
    }

    match claims.plan.as_str() {
        "pro" => Ok(Plan::Pro),
        _ => Ok(Plan::Free),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_license_key() -> String {
        std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/license/pro.license"
        ))
        .unwrap()
    }

    #[test]
    fn valid_license_returns_pro() {
        let key = test_license_key();
        assert_eq!(verify_license_key(&key).unwrap(), Plan::Pro);
    }

    #[test]
    fn tampered_payload_rejected() {
        let key = test_license_key();
        let (_, sig) = key.split_once('.').unwrap();
        let fake_payload = URL_SAFE_NO_PAD.encode(b"{\"plan\":\"pro\",\"org\":\"evil\",\"issued_at\":\"2026-01-01T00:00:00Z\",\"expires_at\":\"2099-12-31T23:59:59Z\"}");
        let tampered = format!("{fake_payload}.{sig}");
        assert!(verify_license_key(&tampered).is_err());
    }

    #[test]
    fn invalid_signature_rejected() {
        let key = test_license_key();
        let (payload, _) = key.split_once('.').unwrap();
        let fake_sig = URL_SAFE_NO_PAD.encode([0u8; 64]);
        let tampered = format!("{payload}.{fake_sig}");
        assert!(verify_license_key(&tampered).is_err());
    }

    #[test]
    fn empty_key_returns_free() {
        assert_eq!(
            verify_license_key("").unwrap_err().contains("missing"),
            true
        );
    }

    #[test]
    fn expired_license_rejected() {
        use ed25519_dalek::{Signer, SigningKey};
        let sk_bytes: [u8; 32] = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/license/test-private.key"
        ))
        .unwrap()
        .try_into()
        .unwrap();
        let sk = SigningKey::from_bytes(&sk_bytes);

        let payload = r#"{"plan":"pro","org":"test","issued_at":"2020-01-01T00:00:00Z","expires_at":"2020-12-31T23:59:59Z"}"#;
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let sig = sk.sign(payload_b64.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        let key = format!("{payload_b64}.{sig_b64}");

        assert!(verify_license_key(&key).unwrap_err().contains("expired"));
    }
}
