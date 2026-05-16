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
    fn max_databases(&self) -> u32 {
        self.license.limits().map_or(u32::MAX, |l| l.max_databases)
    }
    fn max_workflows(&self) -> u32 {
        self.license.limits().map_or(u32::MAX, |l| l.max_workflows)
    }
    fn max_webhooks(&self) -> u32 {
        self.license.limits().map_or(u32::MAX, |l| l.max_webhooks)
    }
    fn max_tokens(&self) -> u32 {
        self.license.limits().map_or(u32::MAX, |l| l.max_tokens)
    }
    fn max_roles(&self) -> u32 {
        self.license.limits().map_or(u32::MAX, |l| l.max_roles)
    }
    fn is_enterprise(&self) -> bool {
        self.license.is_enterprise()
    }
}
