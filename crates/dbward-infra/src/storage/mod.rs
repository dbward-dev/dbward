mod local;
mod s3;

pub use local::LocalResultStore;
pub use s3::{S3Config, S3ResultStore};
