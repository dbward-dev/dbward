use dbward_app::ports::IdGenerator;

pub struct UuidGenerator;

impl IdGenerator for UuidGenerator {
    fn generate(&self) -> String {
        uuid::Uuid::new_v4().to_string()
    }
}
