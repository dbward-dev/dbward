use std::time::{Duration, Instant};

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

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

    /// Verify a JWT and return (subject, roles).
    pub async fn verify(&self, token: &str) -> Result<(String, Vec<String>, Vec<String>), String> {
        let header = decode_header(token).map_err(|e| format!("invalid JWT header: {e}"))?;
        let kid = header.kid.as_deref().unwrap_or("");

        let key = self.get_decoding_key(kid).await?;
        let jwk = self.get_jwk(kid).await?;
        let alg = select_algorithm(header.alg, &jwk)?;

        let mut validation = Validation::new(alg);
        validation.set_audience(&[&self.config.client_id]);
        validation.set_issuer(&[&self.config.issuer]);
        validation.leeway = 30;

        let claims = decode::<Claims>(token, &key, &validation)
            .map_err(|e| format!("JWT verification failed: {e}"))?
            .claims;

        let identity = claims.email.clone().unwrap_or(claims.sub.clone());
        let roles = self.resolve_roles(&claims);
        let groups = claims.groups.clone().unwrap_or_default();

        Ok((identity, roles, groups))
    }

    fn resolve_roles(&self, claims: &Claims) -> Vec<String> {
        let mut roles = Vec::new();
        for mapping in &self.config.role_mappings {
            if let Some(ref subject) = mapping.subject {
                let id = claims.email.as_deref().unwrap_or(&claims.sub);
                if id == subject {
                    roles.push(mapping.role.clone());
                    continue;
                }
            }
            if let Some(ref claim_name) = mapping.claim
                && let Some(ref expected_value) = mapping.value {
                    if claim_name == "groups"
                        && let Some(ref groups) = claims.groups
                            && groups.iter().any(|g| g == expected_value) {
                                roles.push(mapping.role.clone());
                                continue;
                            }
                    if let Some(val) = claims.extra.get(claim_name.as_str())
                        && (val.as_str() == Some(expected_value.as_str())
                            || val
                                .as_array()
                                .map(|a| {
                                    a.iter()
                                        .any(|v| v.as_str() == Some(expected_value.as_str()))
                                })
                                .unwrap_or(false))
                        {
                            roles.push(mapping.role.clone());
                            continue;
                        }
                }
        }

        if roles.is_empty() {
            roles.push(self.config.default_role.clone());
        }
        roles
    }

    async fn get_decoding_key(&self, kid: &str) -> Result<DecodingKey, String> {
        let jwk = self.get_jwk(kid).await?;
        jwk_to_decoding_key(&jwk)
    }

    async fn get_jwk(&self, kid: &str) -> Result<Jwk, String> {
        // Check cache
        {
            let cache = self.jwks.read().await;
            if let Some(ref cached) = *cache
                && cached.fetched_at.elapsed() < Duration::from_secs(3600)
                    && let Some(key) = find_key(&cached.keys, kid) {
                        return Ok(key);
                    }
        }

        // Refresh JWKS
        self.refresh_jwks().await?;

        let cache = self.jwks.read().await;
        let cached = cache.as_ref().ok_or("JWKS not available")?;
        find_key(&cached.keys, kid).ok_or(format!("kid '{kid}' not found in JWKS"))
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
        // Only use first key if JWKS has exactly one key (single-key set)
        return if keys.len() == 1 {
            keys.first().cloned()
        } else {
            None
        };
    }
    keys.iter().find(|k| k.kid.as_deref() == Some(kid)).cloned()
}

fn parse_algorithm(alg: &str) -> Option<Algorithm> {
    match alg {
        "RS256" => Some(Algorithm::RS256),
        "RS384" => Some(Algorithm::RS384),
        "RS512" => Some(Algorithm::RS512),
        "ES256" => Some(Algorithm::ES256),
        "ES384" => Some(Algorithm::ES384),
        _ => None,
    }
}

fn algorithm_matches_jwk(alg: Algorithm, jwk: &Jwk) -> bool {
    match jwk.kty.as_str() {
        "RSA" => matches!(alg, Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512),
        "EC" => match jwk.crv.as_deref() {
            Some("P-256") => alg == Algorithm::ES256,
            Some("P-384") => alg == Algorithm::ES384,
            _ => false,
        },
        _ => false,
    }
}

fn select_algorithm(header_alg: Algorithm, jwk: &Jwk) -> Result<Algorithm, String> {
    if let Some(jwk_alg) = jwk.alg.as_deref() {
        let alg =
            parse_algorithm(jwk_alg).ok_or_else(|| format!("unsupported JWK alg: {jwk_alg}"))?;
        if alg != header_alg {
            return Err(format!(
                "JWT header alg {:?} does not match JWK alg {:?}",
                header_alg, alg
            ));
        }
        if !algorithm_matches_jwk(alg, jwk) {
            return Err(format!(
                "JWK alg {:?} is incompatible with key type {} / curve {:?}",
                alg, jwk.kty, jwk.crv
            ));
        }
        return Ok(alg);
    }

    if algorithm_matches_jwk(header_alg, jwk) {
        return Ok(header_alg);
    }

    Err(format!(
        "JWT header alg {:?} is incompatible with key type {} / curve {:?}",
        header_alg, jwk.kty, jwk.crv
    ))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server_config::RoleMapping;

    #[test]
    fn find_key_by_kid() {
        let keys = vec![
            Jwk {
                kid: Some("k1".into()),
                kty: "RSA".into(),
                alg: None,
                n: None,
                e: None,
                crv: None,
                x: None,
                y: None,
            },
            Jwk {
                kid: Some("k2".into()),
                kty: "RSA".into(),
                alg: None,
                n: None,
                e: None,
                crv: None,
                x: None,
                y: None,
            },
        ];
        assert_eq!(find_key(&keys, "k2").unwrap().kid.as_deref(), Some("k2"));
        assert!(find_key(&keys, "k3").is_none());
    }

    #[test]
    fn find_key_empty_kid_returns_first() {
        let keys = vec![Jwk {
            kid: Some("k1".into()),
            kty: "RSA".into(),
            alg: None,
            n: None,
            e: None,
            crv: None,
            x: None,
            y: None,
        }];
        assert!(find_key(&keys, "").is_some());
    }

    #[test]
    fn find_key_empty_kid_rejects_ambiguous_jwks() {
        let keys = vec![
            Jwk {
                kid: Some("k1".into()),
                kty: "RSA".into(),
                alg: None,
                n: None,
                e: None,
                crv: None,
                x: None,
                y: None,
            },
            Jwk {
                kid: Some("k2".into()),
                kty: "RSA".into(),
                alg: None,
                n: None,
                e: None,
                crv: None,
                x: None,
                y: None,
            },
        ];
        assert!(find_key(&keys, "").is_none());
    }

    #[test]
    fn select_algorithm_uses_header_alg_for_rsa_when_jwk_alg_missing() {
        let jwk = Jwk {
            kid: Some("k1".into()),
            kty: "RSA".into(),
            alg: None,
            n: None,
            e: None,
            crv: None,
            x: None,
            y: None,
        };
        assert_eq!(
            select_algorithm(Algorithm::RS512, &jwk).unwrap(),
            Algorithm::RS512
        );
    }

    #[test]
    fn select_algorithm_rejects_header_alg_when_curve_mismatches() {
        let jwk = Jwk {
            kid: Some("k1".into()),
            kty: "EC".into(),
            alg: None,
            n: None,
            e: None,
            crv: Some("P-256".into()),
            x: None,
            y: None,
        };
        assert!(select_algorithm(Algorithm::ES384, &jwk).is_err());
    }

    #[test]
    fn select_algorithm_rejects_header_alg_mismatch_with_jwk_alg() {
        let jwk = Jwk {
            kid: Some("k1".into()),
            kty: "RSA".into(),
            alg: Some("RS256".into()),
            n: None,
            e: None,
            crv: None,
            x: None,
            y: None,
        };
        assert!(select_algorithm(Algorithm::RS512, &jwk).is_err());
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
        assert_eq!(
            v.resolve_roles(&claims("user1", None, None)),
            vec!["readonly"]
        );
    }

    #[test]
    fn resolve_role_by_subject_email() {
        let v = test_verifier(
            vec![RoleMapping {
                subject: Some("admin@co.jp".into()),
                claim: None,
                value: None,
                role: "admin".into(),
            }],
            "readonly",
        );
        assert_eq!(
            v.resolve_roles(&claims("sub1", Some("admin@co.jp"), None)),
            vec!["admin"]
        );
        assert_eq!(
            v.resolve_roles(&claims("sub1", Some("other@co.jp"), None)),
            vec!["readonly"]
        );
    }

    #[test]
    fn resolve_role_by_groups_claim() {
        let v = test_verifier(
            vec![RoleMapping {
                subject: None,
                claim: Some("groups".into()),
                value: Some("db-admins".into()),
                role: "admin".into(),
            }],
            "readonly",
        );
        assert_eq!(
            v.resolve_roles(&claims("u", None, Some(vec!["db-admins", "users"]))),
            vec!["admin"]
        );
        assert_eq!(
            v.resolve_roles(&claims("u", None, Some(vec!["users"]))),
            vec!["readonly"]
        );
    }

    #[test]
    fn resolve_roles_collects_all_matching() {
        let v = test_verifier(
            vec![
                RoleMapping {
                    subject: Some("u@x.com".into()),
                    claim: None,
                    value: None,
                    role: "developer".into(),
                },
                RoleMapping {
                    subject: Some("u@x.com".into()),
                    claim: None,
                    value: None,
                    role: "admin".into(),
                },
            ],
            "readonly",
        );
        assert_eq!(
            v.resolve_roles(&claims("s", Some("u@x.com"), None)),
            vec!["developer", "admin"]
        );
    }
}
