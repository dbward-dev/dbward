use async_trait::async_trait;
use dbward_app::error::AppError;
use dbward_app::ports::ResultStore;
use object_store::ObjectStore;
use object_store::aws::AmazonS3Builder;
use object_store::path::Path;
use std::sync::Arc;

pub struct S3ResultStore {
    store: Arc<dyn ObjectStore>,
}

impl S3ResultStore {
    pub fn new(bucket: &str, region: &str, endpoint: Option<&str>) -> Result<Self, AppError> {
        let mut builder = AmazonS3Builder::new()
            .with_bucket_name(bucket)
            .with_region(region);
        if let Some(ep) = endpoint {
            builder = builder.with_endpoint(ep).with_allow_http(true);
        }
        let store = builder
            .build()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(Self {
            store: Arc::new(store),
        })
    }
}

#[async_trait]
impl ResultStore for S3ResultStore {
    async fn put(&self, key: &str, data: &[u8]) -> Result<(), AppError> {
        let path = Path::from(key);
        self.store
            .put(&path, data.to_vec().into())
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, AppError> {
        let path = Path::from(key);
        let result = self
            .store
            .get(&path)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let bytes = result
            .bytes()
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(bytes.to_vec())
    }

    async fn delete(&self, key: &str) -> Result<(), AppError> {
        let path = Path::from(key);
        self.store
            .delete(&path)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(())
    }
}
