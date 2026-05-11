use dbward_app::error::AppError;
use dbward_app::ports::SsrfValidator;
use std::net::IpAddr;
use url::Url;

pub struct SsrfGuard;

impl SsrfValidator for SsrfGuard {
    fn validate_url(&self, url_str: &str) -> Result<(), AppError> {
        let url = Url::parse(url_str).map_err(|_| AppError::Validation("invalid URL".into()))?;
        match url.scheme() {
            "http" | "https" => {}
            _ => return Err(AppError::Validation("only http/https allowed".into())),
        }
        let host = url.host_str().ok_or_else(|| AppError::Validation("missing host".into()))?;
        let addrs: Vec<IpAddr> = std::net::ToSocketAddrs::to_socket_addrs(&(host, url.port_or_known_default().unwrap_or(443)))
            .map_err(|_| AppError::Validation(format!("cannot resolve host: {host}")))?
            .map(|a| a.ip())
            .collect();
        if addrs.is_empty() {
            return Err(AppError::Validation(format!("no addresses for host: {host}")));
        }
        for ip in &addrs {
            if is_private(ip) {
                return Err(AppError::Validation(format!("private IP not allowed: {ip}")));
            }
        }
        Ok(())
    }
}

fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local()
                || v4.is_broadcast() || v4.is_unspecified()
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64)
                || (v4.octets()[0] == 169 && v4.octets()[1] == 254)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || matches!(v6.to_ipv4_mapped(), Some(v4) if is_private(&IpAddr::V4(v4)))
        }
    }
}
