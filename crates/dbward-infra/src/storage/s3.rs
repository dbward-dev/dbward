use async_trait::async_trait;
use dbward_app::error::AppError;
use dbward_app::ports::{PutOptions, ResultStore, ResultStream};
use futures_util::{StreamExt, TryStreamExt};
use object_store::aws::{AmazonS3, AmazonS3Builder};
use object_store::path::Path;
use object_store::{ObjectStore, PutOptions as ObjPutOptions, TagSet};
use std::sync::Arc;

pub struct S3Config {
    pub bucket: String,
    pub region: String,
    pub endpoint: Option<String>,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub path_style: bool,
    pub prefix: Option<String>,
}

pub struct S3ResultStore {
    store: Arc<AmazonS3>,
    prefix: String,
}

impl S3ResultStore {
    pub fn new(config: S3Config) -> Result<Self, AppError> {
        let mut builder = AmazonS3Builder::from_env()
            .with_bucket_name(&config.bucket)
            .with_region(&config.region);
        if let Some(ep) = &config.endpoint {
            builder = builder.with_endpoint(ep).with_allow_http(true);
        }
        if let Some(key) = &config.access_key_id {
            builder = builder.with_access_key_id(key);
        }
        if let Some(secret) = &config.secret_access_key {
            builder = builder.with_secret_access_key(secret);
        }
        if config.path_style {
            builder = builder.with_virtual_hosted_style_request(false);
        }
        let store = builder
            .build()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let prefix = config
            .prefix
            .map(|p| if p.ends_with('/') { p } else { format!("{p}/") })
            .unwrap_or_default();
        Ok(Self {
            store: Arc::new(store),
            prefix,
        })
    }

    fn resolve_path(&self, key: &str) -> Path {
        Path::from(format!("{}{}", self.prefix, key))
    }
}

#[async_trait]
impl ResultStore for S3ResultStore {
    async fn put(&self, key: &str, data: &[u8], opts: PutOptions) -> Result<(), AppError> {
        let path = self.resolve_path(key);
        let mut put_opts = ObjPutOptions::default();
        if let Some(expires) = opts.expires_at {
            let mut tags = TagSet::default();
            tags.push("dbward-expires", &expires.to_rfc3339());
            put_opts.tags = tags;
        }
        tracing::info!(key, "S3 put");
        self.store
            .put_opts(&path, data.to_vec().into(), put_opts)
            .await
            .map_err(|e| {
                tracing::error!(key, error = %e, "S3 put failed");
                AppError::Internal(e.to_string())
            })?;
        Ok(())
    }

    async fn get_stream(&self, key: &str) -> Result<ResultStream, AppError> {
        let path = self.resolve_path(key);
        tracing::info!(key, "S3 get_stream");
        let result = self.store.get(&path).await.map_err(|e| {
            tracing::error!(key, error = %e, "S3 get failed");
            AppError::Internal(e.to_string())
        })?;
        let content_length = Some(result.meta.size as u64);
        let stream = result
            .into_stream()
            .map_err(|e| AppError::Internal(e.to_string()))
            .boxed();
        Ok(ResultStream {
            content_length,
            stream,
        })
    }

    async fn delete(&self, key: &str) -> Result<(), AppError> {
        let path = self.resolve_path(key);
        tracing::info!(key, "S3 delete");
        self.store.delete(&path).await.map_err(|e| {
            tracing::error!(key, error = %e, "S3 delete failed");
            AppError::Internal(e.to_string())
        })?;
        Ok(())
    }

    async fn health_check(&self) -> Result<(), AppError> {
        // Write probe to verify actual put/delete capability
        let probe = self.resolve_path(".health-probe");
        self.store
            .put(&probe, b"ok".to_vec().into())
            .await
            .map_err(|e| AppError::Internal(format!("S3 health check failed: {e}")))?;
        let _ = self.store.delete(&probe).await;
        Ok(())
    }
}
