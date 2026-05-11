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
        self.fetched_at.map_or(true, |t| t.elapsed() > Duration::from_secs(3600))
    }
}

impl OidcVerifier {
    pub fn new(issuer: String, client_id: String, groups_claim: String, jwks_uri: Option<String>) -> Self {
        let jwks_uri = jwks_uri.unwrap_or_else(|| format!("{}/.well-known/jwks.json", issuer.trim_end_matches('/')));
        Self {
            issuer,
            client_id,
            groups_claim,
            jwks_uri,
            keys: Arc::new(RwLock::new(CachedKeys { keys: Vec::new(), fetched_at: None })),
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
        let resp = reqwest::get(&self.jwks_uri).await
            .map_err(|e| AuthError::Internal(format!("JWKS fetch failed: {e}")))?;
        let jwks: serde_json::Value = resp.json().await
            .map_err(|e| AuthError::Internal(format!("JWKS parse failed: {e}")))?;

        let keys_arr = jwks.get("keys").and_then(|k| k.as_array())
            .ok_or_else(|| AuthError::Internal("JWKS missing keys array".into()))?;

        let mut decoding_keys = Vec::new();
        for key in keys_arr {
            if let (Some(n), Some(e)) = (key.get("n").and_then(|v| v.as_str()), key.get("e").and_then(|v| v.as_str())) {
                if let Ok(dk) = jsonwebtoken::DecodingKey::from_rsa_components(n, e) {
                    decoding_keys.push(dk);
                }
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
            return Err(AuthError::OidcVerificationFailed("JWKS not loaded (fail-closed)".into()));
        }

        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_audience(&[&self.client_id]);
        validation.set_issuer(&[&self.issuer]);
        validation.leeway = 30;

        let mut last_err = String::new();
        let mut had_non_signature_error = false;
        for key in keys.keys.iter() {
            match jsonwebtoken::decode::<serde_json::Value>(token, key, &validation) {
                Ok(token_data) => {
                    let claims = token_data.claims;
                    let subject = claims.get("sub")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| AuthError::OidcVerificationFailed("missing sub claim".into()))?
                        .to_string();
                    let groups: Vec<String> = claims.get(&self.groups_claim)
                        .and_then(|v| v.as_array())
                        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
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

/// Returns true if the error indicates a key mismatch (unknown kid / signature failure).
/// Other errors (expired, wrong audience, wrong issuer) should NOT trigger JWKS refresh.
fn is_key_mismatch(msg: &str) -> bool {
    if msg.starts_with("claims_error:") {
        return false;
    }
    let lower = msg.to_lowercase();
    lower.contains("signature") || lower.contains("key") || lower.contains("kid")
}
