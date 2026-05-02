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

fn credentials_path() -> PathBuf {
    dirs_next().join("credentials.json")
}

fn dirs_next() -> PathBuf {
    let dir = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".dbward");
    std::fs::create_dir_all(&dir).ok();
    dir
}

/// Authorization Code Flow + PKCE
pub async fn login(issuer: &str, client_id: &str) -> Result<(), String> {
    let discovery = discover(issuer).await?;

    // PKCE
    let verifier = generate_random(43);
    let challenge = base64_url_encode(&Sha256::digest(verifier.as_bytes()));

    let state = generate_random(32);
    let port = find_port().await?;
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");

    let auth_url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope=openid+email+profile&state={}&code_challenge={}&code_challenge_method=S256",
        discovery.authorization_endpoint,
        urlencoded(client_id),
        urlencoded(&redirect_uri),
        urlencoded(&state),
        urlencoded(&challenge),
    );

    eprintln!("Opening browser for authentication...");
    eprintln!("If the browser doesn't open, visit:\n{auth_url}");
    let _ = open::that(&auth_url);

    // Wait for callback
    let code = wait_for_callback(port, &state).await?;

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

    let token_resp: TokenResponse = resp.json().await.map_err(|e| format!("invalid token response: {e}"))?;

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
    eprintln!("Login successful. Credentials saved to ~/.dbward/credentials.json");
    Ok(())
}

/// Device Authorization Grant
pub async fn login_device(issuer: &str, client_id: &str) -> Result<(), String> {
    let discovery = discover(issuer).await?;
    let device_endpoint = discovery
        .device_authorization_endpoint
        .unwrap_or_else(|| discovery.authorization_endpoint.replace("/authorize", "/device/authorize"));

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

    eprintln!("Visit: {verification_uri}");
    eprintln!("Enter code: {user_code}");

    // Poll for token
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;

        let resp = client
            .post(&discovery.token_endpoint)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", device_code),
                ("client_id", client_id),
            ])
            .send()
            .await
            .map_err(|e| format!("poll failed: {e}"))?;

        let body: serde_json::Value = resp.json().await.map_err(|e| format!("invalid poll response: {e}"))?;

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
    let path = credentials_path();
    if !path.exists() {
        eprintln!("Not logged in.");
        return Ok(());
    }

    let creds: Credentials = serde_json::from_str(
        &std::fs::read_to_string(&path).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("invalid credentials: {e}"))?;

    // Try to revoke at IdP
    if let Some(ref refresh) = creds.refresh_token {
        let discovery = discover(&creds.issuer).await.ok();
        if let Some(disc) = discovery {
            if let Some(ref revoke_url) = disc.revocation_endpoint {
                let _ = reqwest::Client::new()
                    .post(revoke_url)
                    .form(&[
                        ("token", refresh.as_str()),
                        ("client_id", creds.client_id.as_str()),
                    ])
                    .send()
                    .await;
            }
        }
    }

    std::fs::remove_file(&path).map_err(|e| e.to_string())?;
    eprintln!("Logged out. Credentials deleted.");
    Ok(())
}

pub fn whoami() -> Result<(), String> {
    let path = credentials_path();
    if !path.exists() {
        eprintln!("Not logged in. Run: dbward login");
        return Ok(());
    }

    let creds: Credentials = serde_json::from_str(
        &std::fs::read_to_string(&path).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("invalid credentials: {e}"))?;

    // Decode JWT to show identity (without verification)
    if let Some(ref id_token) = creds.id_token {
        if let Some(payload) = id_token.split('.').nth(1) {
            use base64::Engine;
            if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload) {
                if let Ok(claims) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                    let email = claims["email"].as_str().unwrap_or("unknown");
                    let sub = claims["sub"].as_str().unwrap_or("unknown");
                    println!("Identity: {email} ({sub})");
                }
            }
        }
    }

    println!("Issuer: {}", creds.issuer);
    println!("Expires: {}", creds.expires_at);
    Ok(())
}

/// Load saved access token (auto-refresh if near expiry).
pub async fn load_token(issuer: &str, client_id: &str) -> Result<String, String> {
    let path = credentials_path();
    if !path.exists() {
        return Err("not logged in. Run: dbward login".into());
    }

    let mut creds: Credentials = serde_json::from_str(
        &std::fs::read_to_string(&path).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("invalid credentials: {e}"))?;

    // Check expiry
    let expires = chrono::DateTime::parse_from_rfc3339(&creds.expires_at)
        .map_err(|e| format!("invalid expires_at: {e}"))?;
    let refresh_threshold = chrono::Utc::now() + chrono::Duration::minutes(5);

    if expires < refresh_threshold {
        if let Some(ref refresh_token) = creds.refresh_token {
            let discovery = discover(issuer).await?;
            let resp = reqwest::Client::new()
                .post(&discovery.token_endpoint)
                .form(&[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", refresh_token),
                    ("client_id", client_id),
                ])
                .send()
                .await
                .map_err(|e| format!("refresh failed: {e}"))?;

            if resp.status().is_success() {
                let token_resp: TokenResponse =
                    resp.json().await.map_err(|e| format!("invalid refresh response: {e}"))?;
                let new_expires = chrono::Utc::now()
                    + chrono::Duration::seconds(token_resp.expires_in.unwrap_or(3600) as i64);
                creds.access_token = token_resp.access_token;
                if let Some(rt) = token_resp.refresh_token {
                    creds.refresh_token = Some(rt);
                }
                creds.expires_at = new_expires.to_rfc3339();
                save_credentials(&creds)?;
            }
        }
    }

    Ok(creds.access_token)
}

async fn discover(issuer: &str) -> Result<OidcDiscovery, String> {
    let url = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
    reqwest::get(&url)
        .await
        .map_err(|e| format!("OIDC discovery failed: {e}"))?
        .json()
        .await
        .map_err(|e| format!("invalid discovery response: {e}"))
}

async fn wait_for_callback(port: u16, expected_state: &str) -> Result<String, String> {
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .map_err(|e| format!("callback server failed: {e}"))?;

    let (stream, _) = listener
        .accept()
        .await
        .map_err(|e| format!("accept failed: {e}"))?;

    let mut buf = vec![0u8; 4096];
    stream.readable().await.map_err(|e| format!("read failed: {e}"))?;
    let n = stream.try_read(&mut buf).map_err(|e| format!("read failed: {e}"))?;
    let request = String::from_utf8_lossy(&buf[..n]);

    // Parse query params from GET /callback?code=xxx&state=yyy
    let path = request.lines().next().unwrap_or("");
    let query = path.split('?').nth(1).unwrap_or("").split(' ').next().unwrap_or("");

    let mut code = None;
    let mut state = None;
    for param in query.split('&') {
        let mut kv = param.splitn(2, '=');
        match (kv.next(), kv.next()) {
            (Some("code"), Some(v)) => code = Some(v.to_string()),
            (Some("state"), Some(v)) => state = Some(v.to_string()),
            _ => {}
        }
    }

    // Send response
    let html = "<html><body><h2>Login successful!</h2><p>You can close this tab.</p></body></html>";
    let response = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}", html.len(), html);
    stream.writable().await.map_err(|e| format!("write failed: {e}"))?;
    stream.try_write(response.as_bytes()).map_err(|e| format!("write failed: {e}"))?;

    let code = code.ok_or("missing code in callback")?;
    let recv_state = state.ok_or("missing state in callback")?;
    if recv_state != expected_state {
        return Err("state mismatch — possible CSRF attack".into());
    }

    Ok(code)
}

async fn find_port() -> Result<u16, String> {
    for port in 19836..=19840 {
        if tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
            .await
            .is_ok()
        {
            return Ok(port);
        }
    }
    Err("no available port for callback server".into())
}

fn save_credentials(creds: &Credentials) -> Result<(), String> {
    let path = credentials_path();
    let json = serde_json::to_string_pretty(creds).map_err(|e| e.to_string())?;
    let mut file = std::fs::File::create(&path).map_err(|e| e.to_string())?;
    file.write_all(json.as_bytes()).map_err(|e| e.to_string())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
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

fn urlencoded(s: &str) -> String {
    s.replace(':', "%3A")
        .replace('/', "%2F")
        .replace('?', "%3F")
        .replace('&', "%26")
        .replace('=', "%3D")
        .replace('+', "%2B")
        .replace(' ', "+")
}
