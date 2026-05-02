use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use dbward_core::Role;

use crate::server_config::OidcConfig;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Claims {
    pub sub: String,
    pub iss: Option<String>,
    pub aud: Option<serde_json::Value>,
    pub exp: Option<u64>,
    pub iat: Option<u64>,
    pub email: Option<String>,
    pub groups: Option<Vec<String>>,
    // Catch-all for custom claims
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct OidcDiscovery {
    jwks_uri: String,
}

#[derive(Debug, Deserialize)]
struct JwksResponse {
    keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Deserialize)]
struct Jwk {
    kid: Option<String>,
    kty: String,
    alg: Option<String>,
    n: Option<String>,
    e: Option<String>,
    // EC fields
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
}

struct CachedJwks {
    keys: Vec<Jwk>,
    fetched_at: Instant,
}

pub struct OidcVerifier {
    config: OidcConfig,
    jwks: RwLock<Option<CachedJwks>>,
    jwks_uri: RwLock<Option<String>>,
    client: reqwest::Client,
}

impl OidcVerifier {
    pub fn new(config: OidcConfig) -> Self {
        Self {
            config,
            jwks: RwLock::new(None),
            jwks_uri: RwLock::new(None),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Verify a JWT and return (subject, role).
    pub async fn verify(&self, token: &str) -> Result<(String, Role), String> {
        let header = decode_header(token).map_err(|e| format!("invalid JWT header: {e}"))?;
        let kid = header.kid.as_deref().unwrap_or("");

        let key = self.get_decoding_key(kid).await?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[&self.config.client_id]);
        validation.set_issuer(&[&self.config.issuer]);
        validation.leeway = 30;

        // Also try ES256
        let claims = decode::<Claims>(token, &key, &validation)
            .or_else(|_| {
                let mut v = Validation::new(Algorithm::ES256);
                v.set_audience(&[&self.config.client_id]);
                v.set_issuer(&[&self.config.issuer]);
                v.leeway = 30;
                decode::<Claims>(token, &key, &v)
            })
            .map_err(|e| format!("JWT verification failed: {e}"))?
            .claims;

        let identity = claims.email.clone().unwrap_or(claims.sub.clone());
        let role = self.resolve_role(&claims);

        Ok((identity, role))
    }

    fn resolve_role(&self, claims: &Claims) -> Role {
        // Check role mappings in order
        for mapping in &self.config.role_mappings {
            if let Some(ref subject) = mapping.subject {
                let id = claims.email.as_deref().unwrap_or(&claims.sub);
                if id == subject {
                    return parse_role(&mapping.role);
                }
            }
            if let Some(ref claim_name) = mapping.claim {
                if let Some(ref expected_value) = mapping.value {
                    // Check in groups array
                    if claim_name == "groups" {
                        if let Some(ref groups) = claims.groups {
                            if groups.iter().any(|g| g == expected_value) {
                                return parse_role(&mapping.role);
                            }
                        }
                    }
                    // Check in extra claims
                    if let Some(val) = claims.extra.get(claim_name.as_str()) {
                        if val.as_str() == Some(expected_value.as_str())
                            || val
                                .as_array()
                                .map(|a| a.iter().any(|v| v.as_str() == Some(expected_value.as_str())))
                                .unwrap_or(false)
                        {
                            return parse_role(&mapping.role);
                        }
                    }
                }
            }
        }

        parse_role(&self.config.default_role)
    }

    async fn get_decoding_key(&self, kid: &str) -> Result<DecodingKey, String> {
        // Check cache
        {
            let cache = self.jwks.read().await;
            if let Some(ref cached) = *cache {
                if cached.fetched_at.elapsed() < Duration::from_secs(3600) {
                    if let Some(key) = find_key(&cached.keys, kid) {
                        return jwk_to_decoding_key(&key);
                    }
                }
            }
        }

        // Refresh JWKS
        self.refresh_jwks().await?;

        let cache = self.jwks.read().await;
        let cached = cache.as_ref().ok_or("JWKS not available")?;
        let key = find_key(&cached.keys, kid).ok_or(format!("kid '{kid}' not found in JWKS"))?;
        jwk_to_decoding_key(&key)
    }

    async fn refresh_jwks(&self) -> Result<(), String> {
        let uri = self.get_jwks_uri().await?;
        let resp: JwksResponse = self
            .client
            .get(&uri)
            .send()
            .await
            .map_err(|e| format!("JWKS fetch failed: {e}"))?
            .json()
            .await
            .map_err(|e| format!("JWKS parse failed: {e}"))?;

        let mut cache = self.jwks.write().await;
        *cache = Some(CachedJwks {
            keys: resp.keys,
            fetched_at: Instant::now(),
        });
        Ok(())
    }

    async fn get_jwks_uri(&self) -> Result<String, String> {
        // Use override if configured (for Docker environments)
        if let Some(ref uri) = self.config.jwks_uri {
            return Ok(uri.clone());
        }

        {
            let cached = self.jwks_uri.read().await;
            if let Some(ref uri) = *cached {
                return Ok(uri.clone());
            }
        }

        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            self.config.issuer.trim_end_matches('/')
        );
        let discovery: OidcDiscovery = self
            .client
            .get(&discovery_url)
            .send()
            .await
            .map_err(|e| format!("OIDC discovery failed: {e}"))?
            .json()
            .await
            .map_err(|e| format!("OIDC discovery parse failed: {e}"))?;

        let mut cached = self.jwks_uri.write().await;
        *cached = Some(discovery.jwks_uri.clone());
        Ok(discovery.jwks_uri)
    }
}

fn find_key(keys: &[Jwk], kid: &str) -> Option<Jwk> {
    if kid.is_empty() {
        return keys.first().cloned();
    }
    keys.iter()
        .find(|k| k.kid.as_deref() == Some(kid))
        .cloned()
}

fn jwk_to_decoding_key(jwk: &Jwk) -> Result<DecodingKey, String> {
    match jwk.kty.as_str() {
        "RSA" => {
            let n = jwk.n.as_ref().ok_or("missing RSA n")?;
            let e = jwk.e.as_ref().ok_or("missing RSA e")?;
            DecodingKey::from_rsa_components(n, e).map_err(|e| format!("invalid RSA key: {e}"))
        }
        "EC" => {
            let x = jwk.x.as_ref().ok_or("missing EC x")?;
            let y = jwk.y.as_ref().ok_or("missing EC y")?;
            DecodingKey::from_ec_components(x, y).map_err(|e| format!("invalid EC key: {e}"))
        }
        other => Err(format!("unsupported key type: {other}")),
    }
}

fn parse_role(s: &str) -> Role {
    match s {
        "admin" => Role::Admin,
        "developer" => Role::Developer,
        _ => Role::Readonly,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server_config::RoleMapping;

    #[test]
    fn parse_role_variants() {
        assert!(matches!(parse_role("admin"), Role::Admin));
        assert!(matches!(parse_role("developer"), Role::Developer));
        assert!(matches!(parse_role("readonly"), Role::Readonly));
        assert!(matches!(parse_role("unknown"), Role::Readonly));
    }

    #[test]
    fn find_key_by_kid() {
        let keys = vec![
            Jwk { kid: Some("k1".into()), kty: "RSA".into(), alg: None, n: None, e: None, crv: None, x: None, y: None },
            Jwk { kid: Some("k2".into()), kty: "RSA".into(), alg: None, n: None, e: None, crv: None, x: None, y: None },
        ];
        assert_eq!(find_key(&keys, "k2").unwrap().kid.as_deref(), Some("k2"));
        assert!(find_key(&keys, "k3").is_none());
    }

    #[test]
    fn find_key_empty_kid_returns_first() {
        let keys = vec![
            Jwk { kid: Some("k1".into()), kty: "RSA".into(), alg: None, n: None, e: None, crv: None, x: None, y: None },
        ];
        assert!(find_key(&keys, "").is_some());
    }

    fn test_verifier(mappings: Vec<RoleMapping>, default_role: &str) -> OidcVerifier {
        OidcVerifier::new(OidcConfig {
            issuer: "https://example.com".into(),
            client_id: "test".into(),
            client_secret_env: None,
            jwks_uri: None,
            default_role: default_role.into(),
            role_mappings: mappings,
        })
    }

    fn claims(sub: &str, email: Option<&str>, groups: Option<Vec<&str>>) -> Claims {
        Claims {
            sub: sub.into(),
            iss: None,
            aud: None,
            exp: None,
            iat: None,
            email: email.map(Into::into),
            groups: groups.map(|g| g.into_iter().map(Into::into).collect()),
            extra: Default::default(),
        }
    }

    #[test]
    fn resolve_role_default_when_no_mappings() {
        let v = test_verifier(vec![], "readonly");
        assert!(matches!(v.resolve_role(&claims("user1", None, None)), Role::Readonly));
    }

    #[test]
    fn resolve_role_by_subject_email() {
        let v = test_verifier(vec![
            RoleMapping { subject: Some("admin@co.jp".into()), claim: None, value: None, role: "admin".into() },
        ], "readonly");
        assert!(matches!(v.resolve_role(&claims("sub1", Some("admin@co.jp"), None)), Role::Admin));
        assert!(matches!(v.resolve_role(&claims("sub1", Some("other@co.jp"), None)), Role::Readonly));
    }

    #[test]
    fn resolve_role_by_groups_claim() {
        let v = test_verifier(vec![
            RoleMapping { subject: None, claim: Some("groups".into()), value: Some("db-admins".into()), role: "admin".into() },
        ], "readonly");
        assert!(matches!(v.resolve_role(&claims("u", None, Some(vec!["db-admins", "users"]))), Role::Admin));
        assert!(matches!(v.resolve_role(&claims("u", None, Some(vec!["users"]))), Role::Readonly));
    }

    #[test]
    fn resolve_role_first_match_wins() {
        let v = test_verifier(vec![
            RoleMapping { subject: Some("u@x.com".into()), claim: None, value: None, role: "developer".into() },
            RoleMapping { subject: Some("u@x.com".into()), claim: None, value: None, role: "admin".into() },
        ], "readonly");
        assert!(matches!(v.resolve_role(&claims("s", Some("u@x.com"), None)), Role::Developer));
    }
}
