use async_trait::async_trait;
use dbward_app::error::AppError;
use dbward_app::ports::{PutOptions, ResultStore, ResultStream};
use futures_util::{StreamExt, TryStreamExt};
use object_store::ObjectStore;
use object_store::local::LocalFileSystem;
use object_store::path::Path;
use std::sync::Arc;

pub struct LocalResultStore {
    store: Arc<LocalFileSystem>,
}

impl LocalResultStore {
    pub fn new(root_dir: &str) -> Result<Self, AppError> {
        std::fs::create_dir_all(root_dir)
            .map_err(|e| AppError::Internal(format!("create result dir: {e}")))?;
        let store = LocalFileSystem::new_with_prefix(root_dir)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(Self {
            store: Arc::new(store),
        })
    }
}

#[async_trait]
impl ResultStore for LocalResultStore {
    async fn put(&self, key: &str, data: &[u8], _opts: PutOptions) -> Result<(), AppError> {
        let path = Path::from(key);
        self.store
            .put(&path, data.to_vec().into())
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(())
    }

    async fn get_stream(&self, key: &str) -> Result<ResultStream, AppError> {
        let path = Path::from(key);
        let result = self
            .store
            .get(&path)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
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
        let path = Path::from(key);
        self.store
            .delete(&path)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(())
    }

    async fn health_check(&self) -> Result<(), AppError> {
        // Verify the store is writable by putting and deleting a probe object
        let probe = Path::from(".health-probe");
        self.store
            .put(&probe, b"ok".to_vec().into())
            .await
            .map_err(|e| AppError::Internal(format!("local store health check failed: {e}")))?;
        let _ = self.store.delete(&probe).await;
        Ok(())
    }
}
