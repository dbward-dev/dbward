pub mod middleware;
pub mod routes;
pub mod state;

use axum::Router;
use state::AppState;

pub fn build_app(state: AppState) -> Router {
    routes::build_router(state)
}
