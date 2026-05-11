mod authorizer;
mod clock;
mod repos;
mod services;

pub use authorizer::{Authorizer, PolicyEvaluator, RoleResolver, TokenVerifier};
pub use clock::{Clock, IdGenerator};
pub use repos::{
    AgentRepo, AuditLogger, DatabaseRegistry, ExecutionTokenClaims, RequestRepo, ResultStore,
    TokenRepo, TokenSigner, UserRepo, WebhookRepo,
};
pub use services::{Notifier, WebhookEvent};

// Re-export EventDispatcher from domain (ADR-004)
pub use dbward_domain::services::status_machine::EventDispatcher;
