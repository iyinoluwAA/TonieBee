use std::sync::Arc;

use axum::{middleware, Extension, Router};
use tower_http::trace::TraceLayer;

use crate::{
    handler::{
        auth::auth_handler, 
        health, 
        metrics, 
        oauth::oauth_handler, 
        ping, 
        quotes::quotes_handler, 
        sessions::sessions_handler, 
        two_factor::{two_factor_handler, two_factor_auth_handler}, 
        users::users_handler,
        policies::policies_handler,
        appointments::appointments_handler,
        documents::documents_handler,
        payments::payments_handler,
        claims::claims_handler,
        // recovery_warnings::recovery_warnings_handler, // TODO: Axum 0.7 compatibility
    },
    middleware::{auth, audit, ip_extractor, rate_limit_auth_middleware, security_headers},
    AppState,
};

pub fn create_router(app_state: Arc<AppState>) -> Router {
    let ping_route = Router::new()
        .route("/ping", axum::routing::get(ping::ping))
        .layer(middleware::from_fn(auth));

    // TODO: Fix rate limiting middleware - has type issues with Axum 0.7
    // Rate limiting can be added later using tower-http or a different approach
    let auth_routes = auth_handler()
        .merge(two_factor_auth_handler());
    
    let api_route = Router::new()
        .route("/health", axum::routing::get(health::health_check)) // ✅ Health check endpoint
        .route("/uptime", axum::routing::get(metrics::uptime))
        .nest("/auth", auth_routes)
        .nest("/oauth", oauth_handler())
        // 2FA routes with auth (rate limiting applied at handler level if needed)
        .nest("/2fa", two_factor_handler()
            .layer(middleware::from_fn(auth)))
        .nest("/users", users_handler().layer(middleware::from_fn(auth)))
        .nest("/security", crate::handler::security::security_handler().layer(middleware::from_fn(auth)))
        .nest("/sessions", sessions_handler().layer(middleware::from_fn(auth)))
        .nest("/quotes", quotes_handler().layer(middleware::from_fn(auth)))
        .nest("/policies", policies_handler().layer(middleware::from_fn(auth)))
        .nest("/appointments", appointments_handler().layer(middleware::from_fn(auth)))
        .nest("/documents", documents_handler().layer(middleware::from_fn(auth)))
        .nest("/payments", payments_handler().layer(middleware::from_fn(auth)))
        .nest("/claims", claims_handler().layer(middleware::from_fn(auth)))
        // .nest("/recovery-warnings", recovery_warnings_handler()) // TODO: Axum 0.7 compatibility
        .merge(ping_route)
        // Security layers - order matters!
        .layer(middleware::from_fn(ip_extractor::ip_extractor_middleware)) // Extract IP first
        .layer(middleware::from_fn(rate_limit_auth_middleware::rate_limit_auth_middleware)) // Rate limiting
        .layer(middleware::from_fn(security_headers::security_headers_middleware))
        .layer(middleware::from_fn(audit::audit_log_middleware))
        .layer(TraceLayer::new_for_http())
        .layer(Extension(app_state));

    Router::new().nest("/api", api_route)
}
