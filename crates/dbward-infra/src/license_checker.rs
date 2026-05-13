use dbward_app::ports::LicenseChecker;
use dbward_domain::license::License;

pub struct LicenseCheckerImpl {
    license: License,
}

impl LicenseCheckerImpl {
    pub fn new(license: License) -> Self {
        Self { license }
    }
}

impl LicenseChecker for LicenseCheckerImpl {
    fn max_tokens(&self) -> u32 {
        self.license
            .limits()
            .map_or(u32::MAX, |l| l.max_tokens as u32)
    }

    fn max_workflows(&self) -> u32 {
        self.license
            .limits()
            .map_or(u32::MAX, |l| l.max_workflows as u32)
    }

    fn max_webhooks(&self) -> u32 {
        self.license
            .limits()
            .map_or(u32::MAX, |l| l.max_webhooks as u32)
    }

    fn max_roles(&self) -> u32 {
        self.license
            .limits()
            .map_or(u32::MAX, |l| l.max_roles as u32)
    }

    fn max_agents(&self) -> u32 {
        self.license
            .limits()
            .map_or(u32::MAX, |l| l.max_agents as u32)
    }

    fn is_pro(&self) -> bool {
        self.license.is_pro()
    }
}
