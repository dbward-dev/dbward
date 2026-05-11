use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

use dbward_app::error::AuthError;
use dbward_app::ports::TokenVerifier;
use dbward_domain::auth::AuthUser;

/// OIDC verifier with JWKS-based signature validation.
pub struct OidcVerifier {
    issuer: String,
    client_id: String,
    groups_claim: String,
    jwks_uri: String,
    keys: Arc<RwLock<Vec<jsonwebtoken::DecodingKey>>>,
}

impl OidcVerifier {
    pub fn new(issuer: String, client_id: String, groups_claim: String, jwks_uri: Option<String>) -> Self {
        let jwks_uri = jwks_uri.unwrap_or_else(|| format!("{}/.well-known/jwks.json", issuer.trim_end_matches('/')));
        Self {
            issuer,
            client_id,
            groups_claim,
            jwks_uri,
            keys: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Fetch JWKS from the issuer. Must be called before verification.
    pub async fn refresh_keys(&self) -> Result<(), AuthError> {
        let resp = reqwest::get(&self.jwks_uri).await
            .map_err(|e| AuthError::Internal(format!("JWKS fetch failed: {e}")))?;
        let jwks: serde_json::Value = resp.json().await
            .map_err(|e| AuthError::Internal(format!("JWKS parse failed: {e}")))?;

        let keys_arr = jwks.get("keys").and_then(|k| k.as_array())
            .ok_or_else(|| AuthError::Internal("JWKS missing keys array".into()))?;

        let mut decoding_keys = Vec::new();
        for key in keys_arr {
            // Support RSA keys (most common for OIDC)
            if let (Some(n), Some(e)) = (key.get("n").and_then(|v| v.as_str()), key.get("e").and_then(|v| v.as_str())) {
                if let Ok(dk) = jsonwebtoken::DecodingKey::from_rsa_components(n, e) {
                    decoding_keys.push(dk);
                }
            }
        }

        if decoding_keys.is_empty() {
            return Err(AuthError::Internal("no usable keys in JWKS".into()));
        }

        *self.keys.write().await = decoding_keys;
        Ok(())
    }
}

#[async_trait]
impl TokenVerifier for OidcVerifier {
    async fn verify_api_token(&self, _token: &str) -> Result<AuthUser, AuthError> {
        Err(AuthError::InvalidToken)
    }

    async fn verify_oidc_token(&self, token: &str) -> Result<(String, Vec<String>), AuthError> {
        let keys = self.keys.read().await;

        // fail-closed: if no keys loaded, reject all tokens
        if keys.is_empty() {
            return Err(AuthError::OidcVerificationFailed("JWKS not loaded (fail-closed)".into()));
        }

        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_audience(&[&self.client_id]);
        validation.set_issuer(&[&self.issuer]);

        // Try each key until one works
        let mut last_err = String::new();
        for key in keys.iter() {
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
                    last_err = e.to_string();
                    continue;
                }
            }
        }

        Err(AuthError::OidcVerificationFailed(last_err))
    }
}
