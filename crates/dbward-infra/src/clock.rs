use chrono::{DateTime, Utc};
use dbward_app::ports::Clock;

pub struct UtcClock;

impl Clock for UtcClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}
