/// License state for the running server instance.
/// v0.1.0: always Free. Pro gating via License::is_pro() returning false.
#[derive(Debug, Clone, PartialEq)]
pub enum Plan {
    Free,
    Pro,
}

#[derive(Debug, Clone)]
pub struct License {
    pub plan: Plan,
}

impl License {
    /// Load license from key. v0.1.0: always returns Free.
    /// Phase 2: verify Ed25519 signed license key.
    pub fn load() -> Self {
        Self { plan: Plan::Free }
    }

    pub fn is_pro(&self) -> bool {
        self.plan == Plan::Pro
    }

    /// Test helper: create a Pro license.
    #[cfg(test)]
    pub fn pro() -> Self {
        Self { plan: Plan::Pro }
    }
}

impl Default for License {
    fn default() -> Self {
        Self::load()
    }
}
