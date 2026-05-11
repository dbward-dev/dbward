use std::sync::Arc;

use dbward_domain::auth::{AuthUser, Permission, ResourceContext};
use dbward_domain::entities::RequestStatus;

use crate::error::AppError;
use crate::ports::*;

pub struct GetResult {
    pub authorizer: Arc<dyn Authorizer>,
    pub request_repo: Arc<dyn RequestRepo>,
    pub result_store: Arc<dyn ResultStore>,
}

pub struct GetResultInput {
    pub request_id: String,
}

pub struct GetResultOutput {
    pub data: Vec<u8>,
}

impl GetResult {
    pub async fn execute(&self, input: GetResultInput, user: &AuthUser) -> Result<GetResultOutput, AppError> {
        let request = self.request_repo.get(&input.request_id)?
            .ok_or_else(|| AppError::NotFound("request not found".into()))?;

        // Must be executed
        if request.status != RequestStatus::Executed {
            return Err(AppError::NotFound("result not available".into()));
        }

        // no_store check
        if request.no_store {
            return Err(AppError::Gone("result was not stored (no_store)".into()));
        }

        // Authorization: scoped to DB+env, resource context for access control
        self.authorizer.authorize_scoped(
            user,
            Permission::ResultView,
            &request.database,
            &request.environment,
            &ResourceContext::Result {
                requester_id: request.requester.clone(),
                access_selectors: request.share_with.clone(),
            },
        ).map_err(AppError::Forbidden)?;

        // Fetch from store
        let key = format!("results/{}.json", input.request_id);
        let data = self.result_store.get(&key).await
            .map_err(|_| AppError::NotFound("result not found in storage".into()))?;

        Ok(GetResultOutput { data })
    }
}
