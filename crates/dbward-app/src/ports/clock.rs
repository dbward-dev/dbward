use chrono::{DateTime, Utc};

pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

pub trait IdGenerator: Send + Sync {
    fn generate(&self) -> String;
}

pub trait TokenValueGenerator: Send + Sync {
    fn generate_token_value(&self) -> String;
}
