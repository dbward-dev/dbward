// Copyright (c) 2026 dbward-dev.
// Licensed under the dbward Commercial License.
// Production use requires a valid Team or Enterprise subscription.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::RwLock;

use dbward_app::error::AuthError;
use dbward_app::ports::TokenVerifier;
use dbward_domain::auth::AuthUser;

pub struct OidcVerifier {
    issuer: String,
    client_id: String,
    groups_claim: String,
    jwks_uri: String,
    keys: Arc<RwLock<CachedKeys>>,
}

struct CachedKeys {
    keys: Vec<jsonwebtoken::DecodingKey>,
    fetched_at: Option<Instant>,
}

impl CachedKeys {
    fn is_stale(&self) -> bool {
        self.fetched_at
            .is_none_or(|t| t.elapsed() > Duration::from_secs(3600))
    }
}

impl OidcVerifier {
    pub fn new(
        issuer: String,
        client_id: String,
        groups_claim: String,
        jwks_uri: Option<String>,
    ) -> Self {
        let jwks_uri = jwks_uri
            .unwrap_or_else(|| format!("{}/.well-known/jwks.json", issuer.trim_end_matches('/')));
        Self {
            issuer,
            client_id,
            groups_claim,
            jwks_uri,
            keys: Arc::new(RwLock::new(CachedKeys {
                keys: Vec::new(),
                fetched_at: None,
            })),
        }
    }

    async fn ensure_keys(&self) -> Result<(), AuthError> {
        let needs_refresh = self.keys.read().await.is_stale();
        if needs_refresh {
            self.refresh_keys().await?;
        }
        Ok(())
    }

    async fn refresh_keys(&self) -> Result<(), AuthError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| AuthError::Internal(format!("HTTP client build failed: {e}")))?;
        let resp = client
            .get(&self.jwks_uri)
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("JWKS fetch failed: {e}")))?;
        let jwks: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AuthError::Internal(format!("JWKS parse failed: {e}")))?;

        let keys_arr = jwks
            .get("keys")
            .and_then(|k| k.as_array())
            .ok_or_else(|| AuthError::Internal("JWKS missing keys array".into()))?;

        let mut decoding_keys = Vec::new();
        for key in keys_arr {
            // RSA keys
            if let (Some(n), Some(e)) = (
                key.get("n").and_then(|v| v.as_str()),
                key.get("e").and_then(|v| v.as_str()),
            ) && let Ok(dk) = jsonwebtoken::DecodingKey::from_rsa_components(n, e)
            {
                decoding_keys.push(dk);
            }
            // EC keys (ES256/ES384)
            else if key.get("kty").and_then(|v| v.as_str()) == Some("EC")
                && let Ok(jwk_value) = serde_json::from_value::<jsonwebtoken::jwk::Jwk>(key.clone())
                && let Ok(dk) = jsonwebtoken::DecodingKey::from_jwk(&jwk_value)
            {
                decoding_keys.push(dk);
            }
        }

        if decoding_keys.is_empty() {
            return Err(AuthError::Internal("no usable keys in JWKS".into()));
        }

        let mut cached = self.keys.write().await;
        cached.keys = decoding_keys;
        cached.fetched_at = Some(Instant::now());
        Ok(())
    }

    async fn try_verify(&self, token: &str) -> Result<(String, Vec<String>), AuthError> {
        let keys = self.keys.read().await;
        if keys.keys.is_empty() {
            return Err(AuthError::OidcVerificationFailed(
                "JWKS not loaded (fail-closed)".into(),
            ));
        }

        let algorithms = vec![
            jsonwebtoken::Algorithm::RS256,
            jsonwebtoken::Algorithm::RS384,
            jsonwebtoken::Algorithm::RS512,
            jsonwebtoken::Algorithm::ES256,
            jsonwebtoken::Algorithm::ES384,
        ];

        let mut last_err = String::new();
        let mut had_non_signature_error = false;
        for key in keys.keys.iter() {
            for &alg in &algorithms {
                let mut validation = jsonwebtoken::Validation::new(alg);
                validation.set_audience(&[&self.client_id]);
                validation.set_issuer(&[&self.issuer]);
                validation.leeway = 30;

                match jsonwebtoken::decode::<serde_json::Value>(token, key, &validation) {
                    Ok(token_data) => {
                        let claims = token_data.claims;
                        let subject = claims
                            .get("sub")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| {
                                AuthError::OidcVerificationFailed("missing sub claim".into())
                            })?
                            .to_string();
                        let groups: Vec<String> = claims
                            .get(&self.groups_claim)
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default();
                        return Ok((subject, groups));
                    }
                    Err(e) => {
                        let msg = e.to_string();
                        if !is_key_mismatch(&msg) {
                            had_non_signature_error = true;
                        }
                        last_err = msg;
                        continue;
                    }
                }
            }
        }
        // If any key gave a non-signature error (exp/aud/iss), report that
        // to prevent JWKS refresh on claims validation failures
        if had_non_signature_error {
            last_err = format!("claims_error:{last_err}");
        }
        Err(AuthError::OidcVerificationFailed(last_err))
    }
}

#[async_trait]
impl TokenVerifier for OidcVerifier {
    async fn verify_api_token(&self, _token: &str) -> Result<AuthUser, AuthError> {
        Err(AuthError::InvalidToken)
    }

    async fn verify_oidc_token(&self, token: &str) -> Result<(String, Vec<String>), AuthError> {
        // Ensure keys are loaded (auto-refresh if stale)
        self.ensure_keys().await?;

        // Try verification
        match self.try_verify(token).await {
            Ok(result) => Ok(result),
            Err(AuthError::OidcVerificationFailed(ref msg)) if is_key_mismatch(msg) => {
                // Only refresh on signature/key errors (unknown kid scenario)
                // Do NOT refresh on exp/aud/iss failures (prevents DoS via invalid tokens)
                self.refresh_keys().await?;
                self.try_verify(token).await
            }
            Err(e) => Err(e),
        }
    }
}

#[async_trait]
impl dbward_app::ports::OidcTokenVerifier for OidcVerifier {
    async fn verify_oidc_token(&self, token: &str) -> Result<(String, Vec<String>), AuthError> {
        <Self as TokenVerifier>::verify_oidc_token(self, token).await
    }
}

/// Returns true if the error indicates a key mismatch (unknown kid / signature failure).
/// Other errors (expired, wrong audience, wrong issuer) should NOT trigger JWKS refresh.
fn is_key_mismatch(msg: &str) -> bool {
    if msg.starts_with("claims_error:") {
        return false;
    }
    let lower = msg.to_lowercase();
    // "ExpiredSignature" / "ImmatureSignature" are claims errors that happen to
    // contain "signature" — exclude them to prevent JWKS refresh on expired tokens.
    if lower.contains("expired") || lower.contains("immature") {
        return false;
    }
    lower.contains("signature")
        || lower.contains("key")
        || lower.contains("kid")
        || lower.contains("algorithm")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test RSA key pair (2048-bit, generated for tests only — not a real secret)
    const TEST_RSA_PRIVATE_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDVbwVz9HgLjQVg
px0m1FVmiz6IDXp2CoXRUe9Jmgiktd8+7sZoauVrmSzx9l1yOdYNspBG9i0BjnF2
ZJxrmdCUMHkJoo5exc4CPzFEXGtt/ZT6kVhloZNIRjzdfBf/yONt6nRWkblxkGUv
masaglo9nQMeFxD55CHdP6HFgoCyYUUlZclMeXs6+2DH0uMjcfUxvvUek67YOjIq
NONvaPXaZLcVQRUNktlD4Us7LjCg9LFmNRG/E2s9C8pdKSxbcUexTiKhYocDIZJ9
0Q7vCTNkEO/xXwgdGERFlezFx61d7aS8ybmIcbWMP+f5cGmz8S7C9r9X1DR4yAei
5b5uHC21AgMBAAECggEAM6mZeM1ip20dsZ0R5d28xEMNQlJ844i9hoLeOIMj93ac
kLesaAcD/G0J35HCYc1VHmCsIrkhAMDxfvZwlG0Ze11WVvo1mwQnTwzryH/Ucz3P
62z2KDeZloOF5RjOGFiQkIERYwkICdCpZYG9VH/cBxDz+bscnVhWyB7Ici4aJ9MJ
Rc0vsrCmCP3q3odMk5ggSFisWLcr4sDUvFRKHuzcCpM8O74iTrAkdQZv/kT4PzDV
7bL0g0y5qlmwSUJMKHae9FPYSYXMLRsksPSCGuScdwoXEMSOtArC/ytJCJ76uALC
dRA6WuekRt4CYiJshziZo4ovAuLKRFzC61r0x9aw6wKBgQD6EIVWcpq9UI6aWOda
CSqZywXzcmqIJ07xNMiAmP/PJ0y3qGvLfPeCFhvme9TW8N8yiHeo57veL8y88o9W
DSLiYrSeh7FWg6ddAiZO7SQDzl96sCVQ7awGi6vPbfCd4Tkql4uGuQIi5qUX9BpF
bVv6ch28Mi1UdBnzby5dZ/7C/wKBgQDaf+sp/+B09o2Z9W7UebKR1YZQosz0eMv0
dJiOQrPzKCsJBPLyle7b1fnK0q68CUqs4+gGlTS5+EDn8hE5mMbv+pkmrGX8E4b+
RDTnWDZSAQQSun+C8BtyfU4PXpG8UmBPxVNhZ9sxKsjK96m1QRX8OiD0BmNot9Lo
mq07+Z/zSwKBgQCYM5AEovKeAbcaKLx/p46fVtwDZgODZXF+DGNxKi6hFklyi3c4
vpIjQnOu4HYWcTtYlYlHa+yD+tIBux0VAh/WbL+EshB1GOK4EIPijCHckzK4CRhd
XpvSzBZBxaerYJcb3mtVD6xGM94Oa0vGMB7Im8aPcnb2rUfSTDyLK637XwKBgQCg
PCD8Ku6zN8A+QLPnU9v1gK5AYjOFsTR48CyUXyxSTInK0ntMFVIWm4PVDs4fjXza
70PP2AnTu8/1iRrCr1xszs0ThGhCBRwBSYm2goVLe/09stEh9+1Y97WQJd0gSxTg
SyhLjXs8QlEAL8Gf77wsvYA/FJRATlZ4SD50diqrowKBgQCsenl59ZV18iCrBdSq
aQSFA3uMqpOeR4sfthHgqDKu9Xb1P9oPZMjW9JErV/RF14ru0VtboX06ad2KNmdF
hTfJs+J5og6UXAf66XdG5wqu/djm1K/2iGpTHofM1d0y26R/sV4BEIoMiFbfo9kd
hfJb36Tg7pLvyt3/+C7x1kz+sA==
-----END PRIVATE KEY-----";

    // Pre-computed base64url-encoded RSA public key components for the key above
    const TEST_RSA_N: &str = "1W8Fc_R4C40FYKcdJtRVZos-iA16dgqF0VHvSZoIpLXfPu7GaGrla5ks8fZdcjnWDbKQRvYtAY5xdmSca5nQlDB5CaKOXsXOAj8xRFxrbf2U-pFYZaGTSEY83XwX_8jjbep0VpG5cZBlL5mrGoJaPZ0DHhcQ-eQh3T-hxYKAsmFFJWXJTHl7Ovtgx9LjI3H1Mb71HpOu2DoyKjTjb2j12mS3FUEVDZLZQ-FLOy4woPSxZjURvxNrPQvKXSksW3FHsU4ioWKHAyGSfdEO7wkzZBDv8V8IHRhERZXsxcetXe2kvMm5iHG1jD_n-XBps_Euwva_V9Q0eMgHouW-bhwttQ";
    const TEST_RSA_E: &str = "AQAB";

    fn test_encoding_key() -> jsonwebtoken::EncodingKey {
        jsonwebtoken::EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_PEM).unwrap()
    }

    fn test_decoding_key() -> jsonwebtoken::DecodingKey {
        jsonwebtoken::DecodingKey::from_rsa_components(TEST_RSA_N, TEST_RSA_E).unwrap()
    }

    fn make_jwt(
        encoding_key: &jsonwebtoken::EncodingKey,
        sub: &str,
        iss: &str,
        aud: &str,
        groups: &[&str],
        exp_offset_secs: i64,
    ) -> String {
        use serde_json::json;
        let now = chrono::Utc::now().timestamp();
        let claims = json!({
            "sub": sub,
            "iss": iss,
            "aud": aud,
            "exp": now + exp_offset_secs,
            "iat": now - 10,
            "groups": groups,
        });
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        jsonwebtoken::encode(&header, &claims, encoding_key).unwrap()
    }

    async fn verifier_with_key() -> OidcVerifier {
        let v = OidcVerifier::new(
            "https://issuer.example.com".into(),
            "test-client".into(),
            "groups".into(),
            Some("https://example.com/.well-known/jwks.json".into()),
        );
        let dk = test_decoding_key();
        {
            let mut keys = v.keys.write().await;
            keys.keys = vec![dk];
            keys.fetched_at = Some(Instant::now());
        }
        v
    }

    #[test]
    fn is_key_mismatch_detects_signature_errors() {
        assert!(is_key_mismatch("InvalidSignature"));
        assert!(is_key_mismatch("unknown key id"));
        assert!(is_key_mismatch("kid not found"));
    }

    #[test]
    fn is_key_mismatch_ignores_claims_errors() {
        assert!(!is_key_mismatch("claims_error:ExpiredSignature"));
        assert!(!is_key_mismatch("claims_error:InvalidAudience"));
    }

    #[test]
    fn is_key_mismatch_non_key_errors() {
        // jsonwebtoken 9 outputs PascalCase error kinds
        assert!(!is_key_mismatch("ExpiredSignature"));
        assert!(!is_key_mismatch("ImmatureSignature"));
        assert!(!is_key_mismatch("InvalidAudience"));
        assert!(!is_key_mismatch("InvalidIssuer"));
    }

    #[test]
    fn cached_keys_stale_when_empty() {
        let cached = CachedKeys {
            keys: Vec::new(),
            fetched_at: None,
        };
        assert!(cached.is_stale());
    }

    #[test]
    fn cached_keys_fresh_within_hour() {
        // is_stale only checks fetched_at, not key count (empty keys is handled by try_verify)
        let cached = CachedKeys {
            keys: Vec::new(),
            fetched_at: Some(Instant::now()),
        };
        assert!(!cached.is_stale());
    }

    #[test]
    fn cached_keys_stale_after_hour() {
        let cached = CachedKeys {
            keys: Vec::new(),
            fetched_at: Some(Instant::now() - Duration::from_secs(3601)),
        };
        assert!(cached.is_stale());
    }

    #[tokio::test]
    async fn try_verify_fails_with_empty_keys() {
        let verifier = OidcVerifier::new(
            "https://issuer.example.com".into(),
            "test-client".into(),
            "groups".into(),
            Some("https://example.com/.well-known/jwks.json".into()),
        );
        let result = verifier.try_verify("some.jwt.token").await;
        assert!(matches!(result, Err(AuthError::OidcVerificationFailed(_))));
    }

    #[tokio::test]
    async fn try_verify_valid_token() {
        let verifier = verifier_with_key().await;
        let token = make_jwt(
            &test_encoding_key(),
            "alice",
            "https://issuer.example.com",
            "test-client",
            &["admin", "dba-team"],
            3600,
        );

        let (sub, groups) = verifier.try_verify(&token).await.unwrap();
        assert_eq!(sub, "alice");
        assert_eq!(groups, vec!["admin", "dba-team"]);
    }

    #[tokio::test]
    async fn try_verify_expired_token() {
        let verifier = verifier_with_key().await;
        let token = make_jwt(
            &test_encoding_key(),
            "alice",
            "https://issuer.example.com",
            "test-client",
            &[],
            -3600, // expired 1 hour ago
        );

        let result = verifier.try_verify(&token).await;
        // After fix: expired tokens are NOT key mismatches, so had_non_signature_error = true
        // and the error gets "claims_error:" prefix
        assert!(
            matches!(result, Err(AuthError::OidcVerificationFailed(ref msg)) if msg.starts_with("claims_error:"))
        );
    }

    #[tokio::test]
    async fn try_verify_wrong_audience() {
        let verifier = verifier_with_key().await;
        let token = make_jwt(
            &test_encoding_key(),
            "alice",
            "https://issuer.example.com",
            "wrong-audience",
            &[],
            3600,
        );

        let result = verifier.try_verify(&token).await;
        assert!(matches!(result, Err(AuthError::OidcVerificationFailed(_))));
    }

    #[tokio::test]
    async fn try_verify_wrong_issuer() {
        let verifier = verifier_with_key().await;
        let token = make_jwt(
            &test_encoding_key(),
            "alice",
            "https://wrong-issuer.example.com",
            "test-client",
            &[],
            3600,
        );

        let result = verifier.try_verify(&token).await;
        assert!(matches!(result, Err(AuthError::OidcVerificationFailed(_))));
    }

    #[tokio::test]
    async fn try_verify_missing_sub_claim() {
        let verifier = verifier_with_key().await;

        let now = chrono::Utc::now().timestamp();
        let claims = serde_json::json!({
            "iss": "https://issuer.example.com",
            "aud": "test-client",
            "exp": now + 3600,
            "iat": now - 10,
        });
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        let token = jsonwebtoken::encode(&header, &claims, &test_encoding_key()).unwrap();

        let result = verifier.try_verify(&token).await;
        assert!(
            matches!(result, Err(AuthError::OidcVerificationFailed(msg)) if msg.contains("sub"))
        );
    }

    #[tokio::test]
    async fn try_verify_ec_key_es256() {
        let ec_private_pem = b"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghzkWmSjYR3FVevfR
BfBLxMalbODp6OSqxJxEbnLfjumhRANCAAQkU6QMRbb6y2bevL618Jk97Oz6c5rB
a0JIHAMcgZVTSxT2YQKUkGFDYxkc7gOHP57lmREiCc55iPYh8Sa2bo6o
-----END PRIVATE KEY-----";

        let ec_public_pem = b"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJFOkDEW2+stm3ry+tfCZPezs+nOa
wWtCSBwDHIGVU0sU9mEClJBhQ2MZHO4Dhz+e5ZkRIgnOeYj2IfEmtm6OqA==
-----END PUBLIC KEY-----";

        let encoding_key = jsonwebtoken::EncodingKey::from_ec_pem(ec_private_pem).unwrap();
        let decoding_key = jsonwebtoken::DecodingKey::from_ec_pem(ec_public_pem).unwrap();

        let verifier = OidcVerifier::new(
            "https://issuer.example.com".into(),
            "test-client".into(),
            "groups".into(),
            Some("https://example.com/.well-known/jwks.json".into()),
        );
        {
            let mut keys = verifier.keys.write().await;
            keys.keys = vec![decoding_key];
            keys.fetched_at = Some(Instant::now());
        }

        let now = chrono::Utc::now().timestamp();
        let claims = serde_json::json!({
            "sub": "bob",
            "iss": "https://issuer.example.com",
            "aud": "test-client",
            "exp": now + 3600,
            "iat": now - 10,
            "groups": ["ec-users"],
        });
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        let token = jsonwebtoken::encode(&header, &claims, &encoding_key).unwrap();

        let (sub, groups) = verifier.try_verify(&token).await.unwrap();
        assert_eq!(sub, "bob");
        assert_eq!(groups, vec!["ec-users"]);
    }
}
