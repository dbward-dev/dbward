use object_store::path::Path as ObjectPath;
use object_store::{ObjectStore, PutPayload};
use std::sync::Arc;

/// Wraps object_store for result storage operations.
pub struct ResultStore {
    store: Arc<dyn ObjectStore>,
    backend: &'static str,
    prefix: String,
}

impl ResultStore {
    pub fn new_local(root_dir: &str) -> Result<Self, String> {
        std::fs::create_dir_all(root_dir)
            .map_err(|e| format!("create result dir: {e}"))?;
        let store = object_store::local::LocalFileSystem::new_with_prefix(root_dir)
            .map_err(|e| format!("local storage init: {e}"))?;
        Ok(Self {
            store: Arc::new(store),
            backend: "local",
            prefix: String::new(),
        })
    }

    pub fn new_s3(bucket: &str, region: &str, endpoint: Option<&str>) -> Result<Self, String> {
        let mut builder = object_store::aws::AmazonS3Builder::new()
            .with_bucket_name(bucket)
            .with_region(region);
        if let Some(ep) = endpoint {
            builder = builder.with_endpoint(ep).with_allow_http(true);
        }
        let store = builder
            .build()
            .map_err(|e| format!("s3 storage init: {e}"))?;
        Ok(Self {
            store: Arc::new(store),
            backend: "s3",
            prefix: String::new(),
        })
    }

    pub fn with_prefix(mut self, prefix: &str) -> Self {
        self.prefix = prefix.trim_end_matches('/').to_string();
        self
    }

    fn object_path(&self, request_id: &str) -> ObjectPath {
        ObjectPath::from(self.storage_key(request_id))
    }

    pub fn backend(&self) -> &'static str {
        self.backend
    }

    pub fn storage_key(&self, request_id: &str) -> String {
        if self.prefix.is_empty() {
            format!("{request_id}.json")
        } else {
            format!("{}/{request_id}.json", self.prefix)
        }
    }

    pub async fn put(&self, request_id: &str, data: &[u8]) -> Result<(), String> {
        let path = self.object_path(request_id);
        let payload = PutPayload::from(data.to_vec());
        self.store
            .put(&path, payload)
            .await
            .map_err(|e| format!("storage put: {e}"))?;
        Ok(())
    }

    pub async fn get(&self, request_id: &str) -> Result<Vec<u8>, String> {
        let path = self.object_path(request_id);
        let result = self
            .store
            .get(&path)
            .await
            .map_err(|e| format!("storage get: {e}"))?;
        result
            .bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| format!("storage read bytes: {e}"))
    }

    pub async fn delete(&self, request_id: &str) -> Result<(), String> {
        let path = self.object_path(request_id);
        self.store
            .delete(&path)
            .await
            .map_err(|e| format!("storage delete: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn local_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = ResultStore::new_local(dir.path().to_str().unwrap()).unwrap();

        store.put("req-001", b"{\"rows\":[]}").await.unwrap();
        let data = store.get("req-001").await.unwrap();
        assert_eq!(data, b"{\"rows\":[]}");

        store.delete("req-001").await.unwrap();
        assert!(store.get("req-001").await.is_err());
    }

    #[test]
    fn storage_key_includes_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let store = ResultStore::new_local(dir.path().to_str().unwrap())
            .unwrap()
            .with_prefix("shared/results/");

        assert_eq!(store.backend(), "local");
        assert_eq!(store.storage_key("req-001"), "shared/results/req-001.json");
    }
}
