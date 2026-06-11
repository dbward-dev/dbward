use std::time::Duration;

use reqwest::Client;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

/// Re-export reqwest::Error for callers that need to inspect network errors.
pub use reqwest::Error as ReqwestError;

/// HTTP error from the server or network.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("HTTP {status}: {body}")]
    Http { status: u16, body: String },
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("deserialization error: {0}")]
    Deserialize(String),
}

/// Callback invoked after every response to inspect headers (e.g., version check).
pub type ResponseHook = Box<dyn Fn(&reqwest::Response) + Send + Sync>;

/// Thin HTTP transport: auth + URL join + JSON + error normalization.
#[derive(Clone)]
pub struct ApiClient {
    http: Client,
    base_url: String,
    token: String,
    response_hook: Option<std::sync::Arc<ResponseHook>>,
}

impl ApiClient {
    pub fn new(
        base_url: &str,
        token: &str,
        default_timeout: Duration,
        connect_timeout: Duration,
    ) -> Result<Self, reqwest::Error> {
        let http = Client::builder()
            .timeout(default_timeout)
            .connect_timeout(connect_timeout)
            .build()?;
        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            token: token.to_string(),
            response_hook: None,
        })
    }

    /// Set a hook called on every response (for version-mismatch warnings, etc.)
    pub fn with_response_hook(mut self, hook: ResponseHook) -> Self {
        self.response_hook = Some(std::sync::Arc::new(hook));
        self
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    // --- Generic JSON methods ---

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, ApiError> {
        let resp = self
            .http
            .get(self.url(path))
            .bearer_auth(&self.token)
            .send()
            .await?;
        self.parse(resp).await
    }

    pub async fn get_with_timeout<T: DeserializeOwned>(
        &self,
        path: &str,
        timeout: Duration,
    ) -> Result<T, ApiError> {
        let resp = self
            .http
            .get(self.url(path))
            .timeout(timeout)
            .bearer_auth(&self.token)
            .send()
            .await?;
        self.parse(resp).await
    }

    pub async fn post<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, ApiError> {
        let resp = self
            .http
            .post(self.url(path))
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .await?;
        self.parse(resp).await
    }

    pub async fn post_empty<T: DeserializeOwned>(&self, path: &str) -> Result<T, ApiError> {
        let resp = self
            .http
            .post(self.url(path))
            .bearer_auth(&self.token)
            .send()
            .await?;
        self.parse(resp).await
    }

    pub async fn put<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, ApiError> {
        let resp = self
            .http
            .put(self.url(path))
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .await?;
        self.parse(resp).await
    }

    pub async fn patch<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, ApiError> {
        let resp = self
            .http
            .patch(self.url(path))
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .await?;
        self.parse(resp).await
    }

    pub async fn delete(&self, path: &str) -> Result<Value, ApiError> {
        let resp = self
            .http
            .delete(self.url(path))
            .bearer_auth(&self.token)
            .send()
            .await?;
        self.parse(resp).await
    }

    // --- Status-aware methods (for custom status handling) ---

    /// Returns (status_code, body_text) without error on non-2xx.
    pub async fn get_with_status(&self, path: &str) -> Result<(u16, String), ApiError> {
        let resp = self
            .http
            .get(self.url(path))
            .bearer_auth(&self.token)
            .send()
            .await?;
        self.call_hook(&resp);
        let status = resp.status().as_u16();
        let text = resp.text().await.map_err(ApiError::Network)?;
        Ok((status, text))
    }

    /// POST returning (status_code, body_text) without error on non-2xx.
    pub async fn post_with_status<B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<(u16, String), ApiError> {
        let resp = self
            .http
            .post(self.url(path))
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .await?;
        self.call_hook(&resp);
        let status = resp.status().as_u16();
        let text = resp.text().await.map_err(ApiError::Network)?;
        Ok((status, text))
    }

    pub async fn post_empty_with_status(&self, path: &str) -> Result<(u16, String), ApiError> {
        let resp = self
            .http
            .post(self.url(path))
            .bearer_auth(&self.token)
            .send()
            .await?;
        self.call_hook(&resp);
        let status = resp.status().as_u16();
        let text = resp.text().await.map_err(ApiError::Network)?;
        Ok((status, text))
    }

    pub async fn delete_with_status(&self, path: &str) -> Result<(u16, String), ApiError> {
        let resp = self
            .http
            .delete(self.url(path))
            .bearer_auth(&self.token)
            .send()
            .await?;
        self.call_hook(&resp);
        let status = resp.status().as_u16();
        let text = resp.text().await.map_err(ApiError::Network)?;
        Ok((status, text))
    }

    // --- Internal ---

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn call_hook(&self, resp: &reqwest::Response) {
        if let Some(hook) = &self.response_hook {
            hook(resp);
        }
    }

    async fn parse<T: DeserializeOwned>(&self, resp: reqwest::Response) -> Result<T, ApiError> {
        self.call_hook(&resp);
        let status = resp.status();
        let text = resp.text().await.map_err(ApiError::Network)?;
        if !status.is_success() {
            return Err(ApiError::Http {
                status: status.as_u16(),
                body: text,
            });
        }
        serde_json::from_str(&text).map_err(|e| ApiError::Deserialize(e.to_string()))
    }
}
