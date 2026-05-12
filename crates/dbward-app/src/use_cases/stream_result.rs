use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission, ResourceContext};
use dbward_domain::values::ResultSummary;

use crate::error::AppError;
use crate::ports::*;

pub struct StreamResult {
    pub authorizer: Arc<dyn Authorizer>,
    pub request_repo: Arc<dyn RequestRepo>,
    pub result_channel: Arc<dyn ResultChannel>,
}

pub struct StreamResultInput {
    pub request_id: String,
    pub timeout_secs: Option<u64>,
}

pub struct StreamResultOutput {
    pub data: Option<ResultSummary>,
}

impl StreamResult {
    pub async fn execute(&self, input: StreamResultInput, user: &AuthUser) -> Result<StreamResultOutput, AppError> {
        let request = self.request_repo.get(&input.request_id)?
            .ok_or_else(|| AppError::NotFound("request not found".into()))?;

        // Live stream access: only requester + admin + ResultPolicy.access (NOT share_with)
        self.authorizer.authorize_scoped(
            user,
            Permission::ResultView,
            &request.database,
            &request.environment,
            &ResourceContext::Result {
                requester_id: request.requester.clone(),
                access_selectors: vec![], // share_with excluded from live stream
            },
        ).map_err(AppError::Forbidden)?;

        let timeout = input.timeout_secs.unwrap_or(300);
        let data = self.result_channel.subscribe(&input.request_id, timeout).await?;

        Ok(StreamResultOutput { data })
    }
}
