use dbward_app::ports::IdGenerator;

pub struct UuidGenerator;

impl IdGenerator for UuidGenerator {
    fn generate(&self) -> String {
        uuid::Uuid::new_v4().to_string()
    }
}

pub struct SecureTokenGenerator;

impl dbward_app::ports::TokenValueGenerator for SecureTokenGenerator {
    fn generate_token_value(&self) -> String {
        format!("dbw_{}", uuid::Uuid::new_v4().simple())
    }
}
