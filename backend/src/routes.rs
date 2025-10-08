use std::sync::Arc;

use axum::{middleware, Extension, Router};
use tower_http::trace::TraceLayer;

use crate::{
    handler::{auth::auth_handler, users::users_handler, health, metrics, ping},
    middleware::auth,
    AppState,
};

pub fn create_router(app_state: Arc<AppState>) -> Router {
    let ping_route = Router::new()
        .route("/ping", axum::routing::get(ping::ping))
        .layer(middleware::from_fn(auth));

    let api_route = Router::new()
        .route("/health", axum::routing::get(health::health_check)) // ✅ Health check endpoint
        .route("/uptime", axum::routing::get(metrics::uptime))
        .nest("/auth", auth_handler())
        .nest(
            "/users",
            users_handler()
                .layer(middleware::from_fn(auth))
        )
        .merge(ping_route)
        .layer(TraceLayer::new_for_http())
        .layer(Extension(app_state));

    Router::new().nest("/api", api_route)
}
