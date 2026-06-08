use dbward_app::error::AppError;
use dbward_app::ports::SsrfValidator;
use std::net::IpAddr;
use url::Url;

pub struct SsrfGuard;

/// Permissive guard that skips private IP checks (for development environments).
pub struct PermissiveSsrfGuard;

impl SsrfValidator for PermissiveSsrfGuard {
    fn validate_url(&self, url_str: &str) -> Result<(), AppError> {
        let url = Url::parse(url_str).map_err(|_| AppError::Validation("invalid URL".into()))?;
        match url.scheme() {
            "http" | "https" => {}
            _ => return Err(AppError::Validation("only http/https allowed".into())),
        }
        url.host_str()
            .ok_or_else(|| AppError::Validation("missing host".into()))?;
        Ok(())
    }
}

impl SsrfValidator for SsrfGuard {
    fn validate_url(&self, url_str: &str) -> Result<(), AppError> {
        let url = Url::parse(url_str).map_err(|_| AppError::Validation("invalid URL".into()))?;
        match url.scheme() {
            "http" | "https" => {}
            _ => return Err(AppError::Validation("only http/https allowed".into())),
        }
        let host = url
            .host_str()
            .ok_or_else(|| AppError::Validation("missing host".into()))?;
        let addrs: Vec<IpAddr> = std::net::ToSocketAddrs::to_socket_addrs(&(
            host,
            url.port_or_known_default().unwrap_or(443),
        ))
        .map_err(|_| AppError::Validation(format!("cannot resolve host: {host}")))?
        .map(|a| a.ip())
        .collect();
        if addrs.is_empty() {
            return Err(AppError::Validation(format!(
                "no addresses for host: {host}"
            )));
        }
        for ip in &addrs {
            if is_private(ip) {
                return Err(AppError::Validation(format!(
                    "private IP not allowed: {ip}"
                )));
            }
        }
        Ok(())
    }
}

fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64)
                || (v4.octets()[0] == 169 && v4.octets()[1] == 254)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || matches!(v6.to_ipv4_mapped(), Some(v4) if is_private(&IpAddr::V4(v4)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dbward_app::ports::SsrfValidator;

    #[test]
    fn rejects_non_http_schemes() {
        let g = SsrfGuard;
        assert!(g.validate_url("ftp://example.com").is_err());
        assert!(g.validate_url("file:///etc/passwd").is_err());
        assert!(g.validate_url("gopher://evil.com").is_err());
    }

    #[test]
    fn rejects_invalid_url() {
        let g = SsrfGuard;
        assert!(g.validate_url("not a url").is_err());
    }

    #[test]
    fn rejects_missing_host() {
        let g = SsrfGuard;
        assert!(g.validate_url("http://").is_err());
    }

    #[test]
    fn rejects_loopback() {
        let g = SsrfGuard;
        assert!(g.validate_url("http://127.0.0.1/hook").is_err());
        assert!(g.validate_url("http://[::1]/hook").is_err());
    }

    #[test]
    fn rejects_private_ranges() {
        let g = SsrfGuard;
        assert!(g.validate_url("http://10.0.0.1/hook").is_err());
        assert!(g.validate_url("http://172.16.0.1/hook").is_err());
        assert!(g.validate_url("http://192.168.1.1/hook").is_err());
        assert!(g.validate_url("http://169.254.169.254/metadata").is_err());
    }

    #[test]
    #[ignore] // requires DNS resolution
    fn allows_public_url() {
        let g = SsrfGuard;
        assert!(g.validate_url("https://example.com/webhook").is_ok());
    }

    #[test]
    fn is_private_covers_all_ranges() {
        use std::net::{Ipv4Addr, Ipv6Addr};
        assert!(is_private(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(is_private(&IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(is_private(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_private(&IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))));
        assert!(is_private(&IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
        assert!(is_private(&IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(is_private(&IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(is_private(&IpAddr::V4(Ipv4Addr::BROADCAST)));
        assert!(is_private(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(is_private(&IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        assert!(!is_private(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_private(&IpAddr::V4(Ipv4Addr::new(93, 184, 215, 14))));
    }

    #[test]
    fn is_private_detects_ipv4_mapped_ipv6() {
        // ::ffff:127.0.0.1 — loopback via IPv4-mapped
        let mapped_loopback: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(is_private(&mapped_loopback));
        // ::ffff:10.0.0.1 — private via IPv4-mapped
        let mapped_private: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        assert!(is_private(&mapped_private));
        // ::ffff:192.168.1.1 — private via IPv4-mapped
        let mapped_192: IpAddr = "::ffff:192.168.1.1".parse().unwrap();
        assert!(is_private(&mapped_192));
        // ::ffff:169.254.169.254 — link-local via IPv4-mapped (AWS metadata)
        let mapped_metadata: IpAddr = "::ffff:169.254.169.254".parse().unwrap();
        assert!(is_private(&mapped_metadata));
        // ::ffff:8.8.8.8 — public via IPv4-mapped (should NOT be private)
        let mapped_public: IpAddr = "::ffff:8.8.8.8".parse().unwrap();
        assert!(!is_private(&mapped_public));
    }

    #[test]
    fn is_private_detects_ula_and_link_local_ipv6() {
        // ULA (fc00::/7)
        let ula: IpAddr = "fd00::1".parse().unwrap();
        assert!(is_private(&ula));
        // Link-local (fe80::/10)
        let link_local: IpAddr = "fe80::1".parse().unwrap();
        assert!(is_private(&link_local));
        // Global unicast (not private)
        let global: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(!is_private(&global));
    }
}
