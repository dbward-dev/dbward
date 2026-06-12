use std::net::IpAddr;

/// Errors from transport security checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// Non-local HTTP without allow_insecure.
    InsecureHttp { url: String },
    /// OIDC configured over non-local HTTP (never allowed).
    OidcOverHttp { url: String },
    /// URL is invalid or uses an unsupported scheme.
    InvalidUrl { url: String, reason: String },
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsecureHttp { url } => write!(
                f,
                "server URL uses HTTP ({url}). Tokens are transmitted in cleartext. \
                 Use HTTPS in production or set allow_insecure = true to suppress."
            ),
            Self::OidcOverHttp { url } => write!(
                f,
                "OIDC authentication over HTTP ({url}) is not allowed. \
                 OIDC requires HTTPS for secure token exchange."
            ),
            Self::InvalidUrl { url, reason } => {
                write!(f, "invalid server URL ({url}): {reason}")
            }
        }
    }
}

impl std::error::Error for TransportError {}

/// Check if a server URL points to a local or internal address (heuristic).
///
/// Returns `true` for:
/// - Loopback: localhost, 127.0.0.1, [::1], 0.0.0.0
/// - Private IPs: 10.x, 172.16-31.x, 192.168.x, IPv6 ULA (fc00::/7)
/// - K8s/Compose internal names: *.svc.cluster.local, *.internal, bare hostnames (no dots)
///
/// This is a heuristic for developer convenience, not a strict security guarantee.
pub fn is_local_or_internal(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    is_host_local_or_internal(parsed.host_str())
}

fn is_host_local_or_internal(host: Option<&str>) -> bool {
    match host {
        Some("localhost") | Some("127.0.0.1") | Some("[::1]") | Some("0.0.0.0") => true,
        Some(host) => {
            if let Ok(ip) = host.parse::<IpAddr>() {
                return ip.is_loopback() || is_private_ip(ip);
            }
            host.ends_with(".svc.cluster.local")
                || host.ends_with(".internal")
                || !host.contains('.')
        }
        None => false,
    }
}

/// Validate transport security for a server URL.
///
/// Accepts only `http` and `https` schemes.
/// Returns `Ok(())` if the connection is safe to proceed.
/// Returns `Err(TransportError)` if the URL is insecure and not suppressed.
pub fn check_transport_security(
    url: &str,
    allow_insecure: bool,
    has_oidc: bool,
) -> Result<(), TransportError> {
    let parsed = url::Url::parse(url).map_err(|e| TransportError::InvalidUrl {
        url: url.to_string(),
        reason: e.to_string(),
    })?;

    match parsed.scheme() {
        "https" => return Ok(()),
        "http" => {}
        other => {
            return Err(TransportError::InvalidUrl {
                url: url.to_string(),
                reason: format!("unsupported scheme '{other}', only http and https are allowed"),
            });
        }
    }

    // HTTP — check if local/internal
    if is_host_local_or_internal(parsed.host_str()) {
        return Ok(());
    }

    // External HTTP
    if has_oidc {
        return Err(TransportError::OidcOverHttp {
            url: url.to_string(),
        });
    }
    if !allow_insecure {
        return Err(TransportError::InsecureHttp {
            url: url.to_string(),
        });
    }
    Ok(())
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            octets[0] == 10
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 168)
                || (octets[0] == 169 && octets[1] == 254) // link-local
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            // ULA (fc00::/7) or link-local (fe80::/10)
            (segments[0] & 0xfe00) == 0xfc00 || (segments[0] & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_addresses() {
        assert!(is_local_or_internal("http://localhost:3000"));
        assert!(is_local_or_internal("http://127.0.0.1:3000"));
        assert!(is_local_or_internal("http://[::1]:3000"));
        assert!(is_local_or_internal("http://0.0.0.0:3000"));
    }

    #[test]
    fn private_ips() {
        assert!(is_local_or_internal("http://10.0.1.5:3000"));
        assert!(is_local_or_internal("http://172.16.0.1:3000"));
        assert!(is_local_or_internal("http://172.31.255.1:3000"));
        assert!(is_local_or_internal("http://192.168.1.100:3000"));
        assert!(!is_local_or_internal("http://172.32.0.1:3000"));
        assert!(!is_local_or_internal("http://8.8.8.8:3000"));
    }

    #[test]
    fn ipv6_private() {
        assert!(is_local_or_internal("http://[fc00::1]:3000"));
        assert!(is_local_or_internal("http://[fd12:3456::1]:3000"));
        // Link-local is also internal (same segment only)
        assert!(is_local_or_internal("http://[fe80::1]:3000"));
    }

    #[test]
    fn internal_hostnames() {
        assert!(is_local_or_internal("http://dbward-server:3000"));
        assert!(is_local_or_internal("http://server:3000"));
        assert!(is_local_or_internal(
            "http://dbward-server.default.svc.cluster.local:3000"
        ));
        assert!(is_local_or_internal("http://api.internal:3000"));
    }

    #[test]
    fn external_addresses() {
        assert!(!is_local_or_internal("http://dbward.example.com:3000"));
        assert!(!is_local_or_internal("http://api.company.io:3000"));
        assert!(!is_local_or_internal(
            "http://api.internal.example.com:3000"
        ));
    }

    #[test]
    fn https_always_ok() {
        assert_eq!(
            check_transport_security("https://dbward.example.com:3000", false, false),
            Ok(())
        );
        assert_eq!(
            check_transport_security("https://dbward.example.com:3000", false, true),
            Ok(())
        );
    }

    #[test]
    fn local_http_always_ok() {
        assert_eq!(
            check_transport_security("http://localhost:3000", false, false),
            Ok(())
        );
        assert_eq!(
            check_transport_security("http://localhost:3000", false, true),
            Ok(())
        );
    }

    #[test]
    fn external_http_without_insecure() {
        assert_eq!(
            check_transport_security("http://dbward.example.com:3000", false, false),
            Err(TransportError::InsecureHttp {
                url: "http://dbward.example.com:3000".into()
            })
        );
    }

    #[test]
    fn external_http_with_insecure() {
        assert_eq!(
            check_transport_security("http://dbward.example.com:3000", true, false),
            Ok(())
        );
    }

    #[test]
    fn oidc_over_external_http_always_rejected() {
        assert_eq!(
            check_transport_security("http://dbward.example.com:3000", true, true),
            Err(TransportError::OidcOverHttp {
                url: "http://dbward.example.com:3000".into()
            })
        );
    }

    #[test]
    fn unsupported_scheme_rejected() {
        let result = check_transport_security("ftp://example.com", false, false);
        assert!(matches!(result, Err(TransportError::InvalidUrl { .. })));

        let result = check_transport_security("file:///etc/passwd", false, false);
        assert!(matches!(result, Err(TransportError::InvalidUrl { .. })));
    }

    #[test]
    fn invalid_url_rejected() {
        let result = check_transport_security("not a url", false, false);
        assert!(matches!(result, Err(TransportError::InvalidUrl { .. })));
    }

    #[test]
    fn scheme_case_insensitive() {
        // url::Url::parse normalizes scheme to lowercase
        assert_eq!(
            check_transport_security("HTTPS://example.com", false, false),
            Ok(())
        );
        assert_eq!(
            check_transport_security("HTTP://localhost:3000", false, false),
            Ok(())
        );
    }
}
