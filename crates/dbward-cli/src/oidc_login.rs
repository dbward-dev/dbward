use std::io::Write;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize)]
struct OidcDiscovery {
    authorization_endpoint: String,
    token_endpoint: String,
    #[serde(default)]
    revocation_endpoint: Option<String>,
    #[serde(default)]
    device_authorization_endpoint: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    id_token: Option<String>,
    expires_in: Option<u64>,
    token_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct Credentials {
    access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
    expires_at: String,
    issuer: String,
    client_id: String,
}

fn legacy_credentials_path() -> PathBuf {
    let dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".dbward");
    std::fs::create_dir_all(&dir).ok();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    dir.join("credentials.json")
}

fn scoped_credentials_path(issuer: &str, client_id: &str) -> PathBuf {
    dbward_config::scoped_credentials_path(issuer, client_id)
}

/// Resolve best credentials path: scoped if exists, else legacy fallback.
fn resolve_credentials_path(issuer: &str, client_id: &str) -> PathBuf {
    let scoped = scoped_credentials_path(issuer, client_id);
    if scoped.exists() {
        return scoped;
    }
    // Fallback to legacy
    let legacy = legacy_credentials_path();
    if legacy.exists() {
        return legacy;
    }
    // Default to scoped (for new writes)
    scoped
}

/// Authorization Code Flow + PKCE
pub async fn login(
    issuer: &str,
    client_id: &str,
    discovery_url: Option<&str>,
    backchannel_url: Option<&str>,
) -> Result<(), String> {
    let discovery = discover_with_override(issuer, discovery_url, backchannel_url).await?;

    // PKCE
    let verifier = generate_random(43);
    let challenge = base64_url_encode(&Sha256::digest(verifier.as_bytes()));

    let state = generate_random(32);
    let listener = find_listener().await?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("failed to get listener address: {e}"))?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");

    let auth_url = build_authorization_url(
        &discovery.authorization_endpoint,
        client_id,
        &redirect_uri,
        &state,
        &challenge,
    )?;

    eprintln!("Opening browser for authentication...");
    eprintln!("If the browser doesn't open, visit:\n{auth_url}");
    if let Err(err) = open::that(&auth_url) {
        eprintln!("Warning: failed to open browser automatically: {err}");
    }

    // Wait for callback
    let code = wait_for_callback(listener, &state).await?;

    // Exchange code for tokens
    let client = reqwest::Client::new();
    let resp = client
        .post(&discovery.token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", &redirect_uri),
            ("client_id", client_id),
            ("code_verifier", &verifier),
        ])
        .send()
        .await
        .map_err(|e| format!("token exchange failed: {e}"))?;

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("token exchange failed: {text}"));
    }

    let token_resp: TokenResponse = resp
        .json()
        .await
        .map_err(|e| format!("invalid token response: {e}"))?;

    let expires_at = chrono::Utc::now()
        + chrono::Duration::seconds(token_resp.expires_in.unwrap_or(3600) as i64);

    let creds = Credentials {
        access_token: token_resp.access_token,
        refresh_token: token_resp.refresh_token,
        id_token: token_resp.id_token,
        expires_at: expires_at.to_rfc3339(),
        issuer: issuer.to_string(),
        client_id: client_id.to_string(),
    };

    save_credentials(&creds)?;
    eprintln!("Login successful. Credentials saved.");
    Ok(())
}

/// Device Authorization Grant
pub async fn login_device(
    issuer: &str,
    client_id: &str,
    discovery_url: Option<&str>,
    browser_url: Option<&str>,
    backchannel_url: Option<&str>,
) -> Result<(), String> {
    let discovery = discover_with_override(issuer, discovery_url, backchannel_url).await?;
    let device_endpoint = discovery.device_authorization_endpoint.unwrap_or_else(|| {
        discovery
            .authorization_endpoint
            .replace("/authorize", "/device/authorize")
    });
    let token_endpoint = discovery.token_endpoint.clone();

    let client = reqwest::Client::new();
    let resp: serde_json::Value = client
        .post(&device_endpoint)
        .form(&[("client_id", client_id), ("scope", "openid email profile")])
        .send()
        .await
        .map_err(|e| format!("device auth failed: {e}"))?
        .json()
        .await
        .map_err(|e| format!("invalid device response: {e}"))?;

    let user_code = resp["user_code"].as_str().ok_or("missing user_code")?;
    let verification_uri = resp["verification_uri_complete"]
        .as_str()
        .or(resp["verification_uri"].as_str())
        .ok_or("missing verification_uri")?;
    let device_code = resp["device_code"].as_str().ok_or("missing device_code")?;
    let interval = resp["interval"].as_u64().unwrap_or(5);

    let display_uri = display_verification_uri(verification_uri, issuer, browser_url);
    eprintln!("Visit: {display_uri}");
    eprintln!("Enter code: {user_code}");

    // Poll for token
    loop {
        tokio::select! {
            _ = wait_for_cancel_signal() => {
                return Err("login cancelled".into());
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(interval)) => {}
        }

        let resp = client.post(&token_endpoint).form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", device_code),
            ("client_id", client_id),
        ]);
        let resp = tokio::select! {
            _ = wait_for_cancel_signal() => {
                return Err("login cancelled".into());
            }
            resp = resp.send() => resp.map_err(|e| format!("poll failed: {e}"))?
        };

        let body: serde_json::Value = tokio::select! {
            _ = wait_for_cancel_signal() => {
                return Err("login cancelled".into());
            }
            body = resp.json() => body.map_err(|e| format!("invalid poll response: {e}"))?
        };

        if let Some(error) = body["error"].as_str() {
            match error {
                "authorization_pending" | "slow_down" => continue,
                "expired_token" => return Err("device code expired".into()),
                _ => return Err(format!("device auth error: {error}")),
            }
        }

        let token_resp: TokenResponse =
            serde_json::from_value(body).map_err(|e| format!("invalid token: {e}"))?;

        let expires_at = chrono::Utc::now()
            + chrono::Duration::seconds(token_resp.expires_in.unwrap_or(3600) as i64);

        let creds = Credentials {
            access_token: token_resp.access_token,
            refresh_token: token_resp.refresh_token,
            id_token: token_resp.id_token,
            expires_at: expires_at.to_rfc3339(),
            issuer: issuer.to_string(),
            client_id: client_id.to_string(),
        };

        save_credentials(&creds)?;
        eprintln!("Login successful.");
        return Ok(());
    }
}

pub async fn logout() -> Result<(), String> {
    // Try to find credentials in any location
    let legacy = legacy_credentials_path();
    let path = if legacy.exists() {
        legacy.clone()
    } else {
        // Try to find a scoped credential file
        let creds_dir = dbward_config::global_config_dir().join("credentials");
        if creds_dir.exists() {
            match std::fs::read_dir(&creds_dir) {
                Ok(entries) => {
                    let first = entries
                        .filter_map(|e| e.ok())
                        .find(|e| e.path().extension().is_some_and(|ext| ext == "json"));
                    match first {
                        Some(entry) => entry.path(),
                        None => {
                            eprintln!("Not logged in.");
                            return Ok(());
                        }
                    }
                }
                Err(_) => {
                    eprintln!("Not logged in.");
                    return Ok(());
                }
            }
        } else {
            eprintln!("Not logged in.");
            return Ok(());
        }
    };

    if !path.exists() {
        eprintln!("Not logged in.");
        return Ok(());
    }

    let creds: Credentials =
        serde_json::from_str(&std::fs::read_to_string(&path).map_err(|e| e.to_string())?)
            .map_err(|e| format!("invalid credentials: {e}"))?;

    // Try to revoke at IdP
    if let Some(ref refresh) = creds.refresh_token {
        let discovery = discover(&creds.issuer).await.ok();
        if let Some(disc) = discovery
            && let Some(ref revoke_url) = disc.revocation_endpoint
            && let Err(err) = reqwest::Client::new()
                .post(revoke_url)
                .form(&[
                    ("token", refresh.as_str()),
                    ("client_id", creds.client_id.as_str()),
                ])
                .send()
                .await
        {
            eprintln!("Warning: token revocation request failed: {err}");
        }
    }

    std::fs::remove_file(&path).map_err(|e| e.to_string())?;
    eprintln!("Logged out. Credentials deleted.");
    Ok(())
}

pub fn whoami() -> Result<(), String> {
    // Find credentials: try legacy first, then scoped dir
    let legacy = legacy_credentials_path();
    let path = if legacy.exists() {
        legacy
    } else {
        let creds_dir = dbward_config::global_config_dir().join("credentials");
        if let Ok(entries) = std::fs::read_dir(&creds_dir) {
            entries
                .filter_map(|e| e.ok())
                .find(|e| e.path().extension().is_some_and(|ext| ext == "json"))
                .map(|e| e.path())
                .ok_or_else(|| "no OIDC credentials".to_string())?
        } else {
            return Err("no OIDC credentials".into());
        }
    };
    if !path.exists() {
        return Err("no OIDC credentials".into());
    }

    let creds: Credentials =
        serde_json::from_str(&std::fs::read_to_string(&path).map_err(|e| e.to_string())?)
            .map_err(|e| format!("invalid credentials: {e}"))?;

    // Decode JWT to show identity (without verification)
    if let Some(ref id_token) = creds.id_token
        && let Some(payload) = id_token.split('.').nth(1)
    {
        use base64::Engine;
        if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload)
            && let Ok(claims) = serde_json::from_slice::<serde_json::Value>(&bytes)
        {
            let email = claims["email"].as_str().unwrap_or("unknown");
            let sub = claims["sub"].as_str().unwrap_or("unknown");
            println!("Identity: {email} ({sub})");
        }
    }

    println!("Issuer: {}", creds.issuer);
    println!("Expires: {}", creds.expires_at);
    Ok(())
}

/// Load saved access token (auto-refresh if near expiry).
pub async fn load_token(issuer: &str, client_id: &str) -> Result<String, String> {
    let path = resolve_credentials_path(issuer, client_id);
    if !path.exists() {
        return Err("not logged in. Run: dbward login".into());
    }

    let mut creds: Credentials =
        serde_json::from_str(&std::fs::read_to_string(&path).map_err(|e| e.to_string())?)
            .map_err(|e| format!("invalid credentials: {e}"))?;

    // Check expiry
    let expires = chrono::DateTime::parse_from_rfc3339(&creds.expires_at)
        .map_err(|e| format!("invalid expires_at: {e}"))?;

    let now = chrono::Utc::now();
    let needs_refresh = now > expires || expires < now + chrono::Duration::minutes(5);

    // Try refresh if expired or near expiry
    if needs_refresh {
        if let Some(ref refresh_token) = creds.refresh_token
            && let Ok(discovery) = discover(issuer).await
            && let Ok(resp) = reqwest::Client::new()
                .post(&discovery.token_endpoint)
                .form(&[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", refresh_token),
                    ("client_id", client_id),
                ])
                .send()
                .await
            && resp.status().is_success()
            && let Ok(token_resp) = resp.json::<TokenResponse>().await
        {
            let new_expires = chrono::Utc::now()
                + chrono::Duration::seconds(token_resp.expires_in.unwrap_or(3600) as i64);
            creds.access_token = token_resp.access_token;
            if let Some(rt) = token_resp.refresh_token {
                creds.refresh_token = Some(rt);
            }
            creds.expires_at = new_expires.to_rfc3339();
            if let Err(err) = save_credentials(&creds) {
                eprintln!("Warning: failed to persist refreshed credentials: {err}");
            }
        } else if now > expires {
            return Err("token expired. Run: dbward login".into());
        }
    }

    Ok(creds.access_token)
}

async fn discover(issuer: &str) -> Result<OidcDiscovery, String> {
    discover_with_override(issuer, None, None).await
}

async fn discover_with_override(
    issuer: &str,
    discovery_url: Option<&str>,
    backchannel_url: Option<&str>,
) -> Result<OidcDiscovery, String> {
    let url = match discovery_url {
        Some(u) => u.to_string(),
        None => format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        ),
    };
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;
    let mut disc: OidcDiscovery = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("OIDC discovery failed: {e}"))?
        .json()
        .await
        .map_err(|e| format!("invalid discovery response: {e}"))?;
    // Rewrite endpoints for backchannel access
    if let Some(base) = backchannel_url {
        let rewrite = |u: &str| -> String {
            if let Some(stripped) = u.strip_prefix(issuer) {
                format!("{base}{stripped}")
            } else {
                u.to_string()
            }
        };
        disc.token_endpoint = rewrite(&disc.token_endpoint);
        disc.authorization_endpoint = rewrite(&disc.authorization_endpoint);
        if let Some(ref ep) = disc.device_authorization_endpoint {
            disc.device_authorization_endpoint = Some(rewrite(ep));
        }
    }
    Ok(disc)
}

async fn wait_for_callback(
    listener: tokio::net::TcpListener,
    expected_state: &str,
) -> Result<String, String> {
    // Retry accept loop: reject invalid connections until we get a valid callback
    let timeout = tokio::time::timeout(std::time::Duration::from_secs(300), async {
        loop {
            let (stream, _) = listener
                .accept()
                .await
                .map_err(|e| format!("accept failed: {e}"))?;

            // Read until we have the full request line (ends with \r\n or \n)
            let mut buf = Vec::with_capacity(4096);
            let request_line = match read_request_line(&stream, &mut buf).await {
                Some(line) => line,
                None => continue,
            };

            // Parse query params from GET /callback?code=xxx&state=yyy HTTP/1.1
            let query = request_line
                .split('?')
                .nth(1)
                .unwrap_or("")
                .split(' ')
                .next()
                .unwrap_or("");

            let params: std::collections::HashMap<String, String> =
                url::form_urlencoded::parse(query.as_bytes())
                    .into_owned()
                    .collect();

            let Some(code) = params.get("code") else {
                // Not a valid callback — send 400 and try again
                let _ = send_error_response(&stream, "missing code").await;
                continue;
            };
            let Some(recv_state) = params.get("state") else {
                let _ = send_error_response(&stream, "missing state").await;
                continue;
            };

            if recv_state != expected_state {
                let _ = send_error_response(&stream, "state mismatch").await;
                continue;
            }

            // Valid callback — send success response
            let html = "<html><body><h2>Login successful!</h2><p>You can close this tab.</p></body></html>";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
                html.len(),
                html
            );
            let _ = write_all(&stream, response.as_bytes()).await;

            return Ok::<String, String>(code.to_string());
        }
    });

    match timeout.await {
        Ok(result) => result,
        Err(_) => Err("login timed out waiting for callback (300s)".into()),
    }
}

/// Read bytes from the stream until we find the first line (ending with \n).
/// Returns None if the connection closes or errors before we get a full line.
async fn read_request_line(stream: &tokio::net::TcpStream, buf: &mut Vec<u8>) -> Option<String> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if tokio::time::Instant::now() > deadline {
            return None;
        }
        match tokio::time::timeout(std::time::Duration::from_secs(5), stream.readable()).await {
            Ok(Ok(())) => {}
            _ => return None,
        }
        let mut tmp = [0u8; 1024];
        match stream.try_read(&mut tmp) {
            Ok(0) => return None,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                    let line = String::from_utf8_lossy(&buf[..pos]).to_string();
                    return Some(line);
                }
                if buf.len() > 8192 {
                    return None;
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(_) => return None,
        }
    }
}

/// Best-effort write all bytes to the stream.
async fn write_all(stream: &tokio::net::TcpStream, data: &[u8]) -> Result<(), ()> {
    let mut written = 0;
    while written < data.len() {
        if stream.writable().await.is_err() {
            return Err(());
        }
        match stream.try_write(&data[written..]) {
            Ok(n) => written += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(_) => return Err(()),
        }
    }
    Ok(())
}

async fn send_error_response(stream: &tokio::net::TcpStream, msg: &str) -> Result<(), ()> {
    let body = format!("<html><body><h2>Error: {msg}</h2></body></html>");
    let response = format!(
        "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    write_all(stream, response.as_bytes()).await
}

async fn find_listener() -> Result<tokio::net::TcpListener, String> {
    for port in 19836..=19840 {
        if let Ok(listener) = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}")).await {
            return Ok(listener);
        }
    }
    Err("no available port for callback server".into())
}

fn save_credentials(creds: &Credentials) -> Result<(), String> {
    // Write to scoped path based on issuer+client_id
    let path = scoped_credentials_path(&creds.issuer, &creds.client_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    let json = serde_json::to_string_pretty(creds).map_err(|e| e.to_string())?;
    let mut file = std::fs::File::create(&path).map_err(|e| e.to_string())?;
    file.write_all(json.as_bytes()).map_err(|e| e.to_string())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
    }

    // Clean up legacy file if it exists and matches
    let legacy = legacy_credentials_path();
    if legacy.exists() {
        let _ = std::fs::remove_file(&legacy);
    }

    Ok(())
}

fn generate_random(len: usize) -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let chars: Vec<u8> = (0..len)
        .map(|_| {
            let idx = rng.random_range(0..62);
            match idx {
                0..=25 => b'a' + idx,
                26..=51 => b'A' + (idx - 26),
                _ => b'0' + (idx - 52),
            }
        })
        .collect();
    String::from_utf8(chars).unwrap()
}

fn base64_url_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn build_authorization_url(
    authorization_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    code_challenge: &str,
) -> Result<String, String> {
    let mut url = url::Url::parse(authorization_endpoint)
        .map_err(|e| format!("invalid authorization_endpoint: {e}"))?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("scope", "openid email profile")
        .append_pair("state", state)
        .append_pair("code_challenge", code_challenge)
        .append_pair("code_challenge_method", "S256");
    Ok(url.to_string())
}

fn display_verification_uri(
    verification_uri: &str,
    issuer: &str,
    browser_url: Option<&str>,
) -> String {
    let Some(browser_url) = browser_url else {
        return verification_uri.to_string();
    };
    rewrite_url_base(verification_uri, issuer, browser_url)
}

fn rewrite_url_base(source_url: &str, from_base: &str, to_base: &str) -> String {
    let from_base = from_base.trim_end_matches('/');
    let to_base = to_base.trim_end_matches('/');
    match source_url.strip_prefix(from_base) {
        Some(rest) => format!("{to_base}{rest}"),
        None => source_url.to_string(),
    }
}

#[cfg(unix)]
async fn wait_for_cancel_signal() {
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(mut sigterm) => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = sigterm.recv() => {}
            }
        }
        Err(err) => {
            eprintln!("Warning: failed to register SIGTERM handler: {err}");
            if let Err(ctrl_c_err) = tokio::signal::ctrl_c().await {
                eprintln!("Warning: failed while waiting for Ctrl-C: {ctrl_c_err}");
            }
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_cancel_signal() {
    if let Err(err) = tokio::signal::ctrl_c().await {
        eprintln!("Warning: failed while waiting for Ctrl-C: {err}");
    }
}

#[cfg(test)]
mod tests {
    use super::{build_authorization_url, display_verification_uri, rewrite_url_base};

    #[test]
    fn builds_authorization_url_with_correct_encoding() {
        let url = build_authorization_url(
            "https://auth.example.com/authorize",
            "my-client",
            "http://127.0.0.1:19836/callback",
            "random_state_123",
            "challenge_abc-def",
        )
        .unwrap();

        assert!(url.starts_with("https://auth.example.com/authorize?"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=my-client"));
        assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A19836%2Fcallback"));
        assert!(url.contains("scope=openid+email+profile"));
        assert!(url.contains("state=random_state_123"));
        assert!(url.contains("code_challenge=challenge_abc-def"));
        assert!(url.contains("code_challenge_method=S256"));
    }

    #[test]
    fn builds_authorization_url_preserves_existing_query() {
        let url = build_authorization_url(
            "https://auth.example.com/authorize?tenant=foo",
            "client",
            "http://127.0.0.1:19836/callback",
            "state",
            "challenge",
        )
        .unwrap();

        assert!(url.contains("tenant=foo"));
        assert!(url.contains("client_id=client"));
    }

    #[test]
    fn builds_authorization_url_encodes_special_chars() {
        let url = build_authorization_url(
            "https://auth.example.com/authorize",
            "client with spaces & symbols #[]!",
            "http://127.0.0.1:19836/callback",
            "state",
            "challenge",
        )
        .unwrap();

        // Should not contain raw & or # in client_id value
        assert!(!url.contains("client_id=client with"));
        assert!(url.contains("client_id=client+with+spaces"));
    }

    #[test]
    fn builds_authorization_url_rejects_invalid_endpoint() {
        let result = build_authorization_url(
            "not a valid url",
            "client",
            "http://127.0.0.1:19836/callback",
            "state",
            "challenge",
        );
        assert!(result.is_err());
    }

    #[test]
    fn rewrites_matching_url_base() {
        let rewritten = rewrite_url_base(
            "http://keycloak:8080/realms/dbward/device?user_code=abc",
            "http://keycloak:8080/realms/dbward",
            "http://localhost:8080/realms/dbward",
        );
        assert_eq!(
            rewritten,
            "http://localhost:8080/realms/dbward/device?user_code=abc"
        );
    }

    #[test]
    fn does_not_rewrite_non_matching_url_base() {
        let rewritten = rewrite_url_base(
            "http://localhost:8080/realms/dbward/device?user_code=abc",
            "http://keycloak:8080/realms/dbward",
            "http://localhost:8080/realms/dbward",
        );
        assert_eq!(
            rewritten,
            "http://localhost:8080/realms/dbward/device?user_code=abc"
        );
    }

    #[test]
    fn returns_original_verification_uri_without_browser_url() {
        let displayed = display_verification_uri(
            "http://keycloak:8080/realms/dbward/device?user_code=abc",
            "http://keycloak:8080/realms/dbward",
            None,
        );
        assert_eq!(
            displayed,
            "http://keycloak:8080/realms/dbward/device?user_code=abc"
        );
    }
}
