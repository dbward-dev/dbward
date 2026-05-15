use std::net::{IpAddr, SocketAddr};

use axum::{
    extract::{ConnectInfo, Request},
    middleware::Next,
    response::Response,
};
use ipnet::IpNet;

/// Resolved client IP inserted as a request extension.
#[derive(Clone, Debug)]
pub struct ClientIp {
    pub ip: IpAddr,
    pub source: ClientIpSource,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientIpSource {
    Peer,
    Xff,
}

impl ClientIpSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Peer => "peer",
            Self::Xff => "xff",
        }
    }
}

/// Parse trusted_proxies config into IpNet list. Plain IPs become /32 or /128.
pub fn parse_trusted_proxies(raw: &[String]) -> Result<Vec<IpNet>, String> {
    raw.iter()
        .map(|s| {
            s.parse::<IpNet>().or_else(|_| {
                s.parse::<IpAddr>()
                    .map(IpNet::from)
                    .map_err(|e| format!("invalid trusted_proxy '{}': {}", s, e))
            })
        })
        .collect()
}

/// Wrapper for sharing parsed trusted proxies via Extension.
#[derive(Clone)]
pub struct TrustedProxies(pub Vec<IpNet>);

/// Middleware that resolves client IP from XFF header using trusted_proxies.
pub async fn resolve_client_ip(
    trusted: std::sync::Arc<Vec<IpNet>>,
    mut req: Request,
    next: Next,
) -> Response {
    let peer_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());

    let client_ip = match peer_ip {
        Some(peer) => resolve(peer, &trusted, &req),
        None => {
            tracing::warn!("ConnectInfo not available, client_ip will be None");
            None
        }
    };

    if let Some(cip) = client_ip {
        req.extensions_mut().insert(cip);
    }

    next.run(req).await
}

fn resolve(peer: IpAddr, trusted: &[IpNet], req: &Request) -> Option<ClientIp> {
    // If no trusted proxies configured or peer is not trusted, use peer directly
    if trusted.is_empty() || !trusted.iter().any(|net| net.contains(&peer)) {
        return Some(ClientIp {
            ip: peer,
            source: ClientIpSource::Peer,
        });
    }

    // Peer is trusted — parse XFF right-to-left
    let xff = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok());

    let Some(xff_value) = xff else {
        return Some(ClientIp {
            ip: peer,
            source: ClientIpSource::Peer,
        });
    };

    let entries: Vec<&str> = xff_value.split(',').map(|s| s.trim()).collect();

    // Walk from right to left, skip trusted IPs
    for entry in entries.iter().rev() {
        let ip = match entry.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => continue, // skip malformed entries
        };
        if !trusted.iter().any(|net| net.contains(&ip)) {
            return Some(ClientIp {
                ip,
                source: ClientIpSource::Xff,
            });
        }
    }

    // All XFF entries are trusted — use leftmost as client
    for entry in &entries {
        if let Ok(ip) = entry.parse::<IpAddr>() {
            return Some(ClientIp {
                ip,
                source: ClientIpSource::Xff,
            });
        }
    }

    // Fallback to peer
    Some(ClientIp {
        ip: peer,
        source: ClientIpSource::Peer,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cidr_and_plain_ip() {
        let raw = vec![
            "10.0.0.0/8".to_string(),
            "192.168.1.1".to_string(),
            "::1".to_string(),
        ];
        let nets = parse_trusted_proxies(&raw).unwrap();
        assert_eq!(nets.len(), 3);
        assert!(nets[1].contains(&"192.168.1.1".parse::<IpAddr>().unwrap()));
        assert!(!nets[1].contains(&"192.168.1.2".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn parse_invalid_returns_error() {
        let raw = vec!["not-an-ip".to_string()];
        assert!(parse_trusted_proxies(&raw).is_err());
    }

    #[test]
    fn resolve_no_trusted_uses_peer() {
        let peer: IpAddr = "1.2.3.4".parse().unwrap();
        let req = Request::builder().body(axum::body::Body::empty()).unwrap();
        let result = resolve(peer, &[], &req).unwrap();
        assert_eq!(result.ip, peer);
        assert_eq!(result.source, ClientIpSource::Peer);
    }

    #[test]
    fn resolve_untrusted_peer_ignores_xff() {
        let peer: IpAddr = "1.2.3.4".parse().unwrap();
        let trusted = vec!["10.0.0.0/8".parse().unwrap()];
        let req = Request::builder()
            .header("x-forwarded-for", "5.6.7.8")
            .body(axum::body::Body::empty())
            .unwrap();
        let result = resolve(peer, &trusted, &req).unwrap();
        assert_eq!(result.ip, peer);
        assert_eq!(result.source, ClientIpSource::Peer);
    }

    #[test]
    fn resolve_trusted_peer_uses_xff() {
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let trusted = vec!["10.0.0.0/8".parse().unwrap()];
        let req = Request::builder()
            .header("x-forwarded-for", "203.0.113.50, 10.0.0.2")
            .body(axum::body::Body::empty())
            .unwrap();
        let result = resolve(peer, &trusted, &req).unwrap();
        assert_eq!(result.ip, "203.0.113.50".parse::<IpAddr>().unwrap());
        assert_eq!(result.source, ClientIpSource::Xff);
    }

    #[test]
    fn resolve_all_xff_trusted_uses_leftmost() {
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let trusted = vec!["10.0.0.0/8".parse().unwrap()];
        let req = Request::builder()
            .header("x-forwarded-for", "10.0.0.5, 10.0.0.6")
            .body(axum::body::Body::empty())
            .unwrap();
        let result = resolve(peer, &trusted, &req).unwrap();
        assert_eq!(result.ip, "10.0.0.5".parse::<IpAddr>().unwrap());
        assert_eq!(result.source, ClientIpSource::Xff);
    }

    #[test]
    fn resolve_malformed_xff_entries_skipped() {
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        let trusted = vec!["10.0.0.0/8".parse().unwrap()];
        let req = Request::builder()
            .header("x-forwarded-for", "bad, 203.0.113.1, 10.0.0.2")
            .body(axum::body::Body::empty())
            .unwrap();
        let result = resolve(peer, &trusted, &req).unwrap();
        assert_eq!(result.ip, "203.0.113.1".parse::<IpAddr>().unwrap());
        assert_eq!(result.source, ClientIpSource::Xff);
    }
}
