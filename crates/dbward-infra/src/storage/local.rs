use async_trait::async_trait;
use dbward_app::error::AppError;
use dbward_app::ports::ResultStore;
use object_store::local::LocalFileSystem;
use object_store::path::Path;
use object_store::ObjectStore;
use std::sync::Arc;

pub struct LocalResultStore {
    store: Arc<LocalFileSystem>,
}

impl LocalResultStore {
    pub fn new(root_dir: &str) -> Result<Self, AppError> {
        let store = LocalFileSystem::new_with_prefix(root_dir)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(Self { store: Arc::new(store) })
    }
}

#[async_trait]
impl ResultStore for LocalResultStore {
    async fn put(&self, key: &str, data: &[u8]) -> Result<(), AppError> {
        let path = Path::from(key);
        self.store.put(&path, data.to_vec().into()).await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, AppError> {
        let path = Path::from(key);
        let result = self.store.get(&path).await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let bytes = result.bytes().await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(bytes.to_vec())
    }

    async fn delete(&self, key: &str) -> Result<(), AppError> {
        let path = Path::from(key);
        self.store.delete(&path).await
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(())
    }
}
