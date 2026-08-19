use axum::{
    extract::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::{
    error::HttpError,
    middleware::ip_extractor::ClientIp,
    utils::{rate_limit_auth, security_monitor},
};

/// Rate limiting middleware for auth endpoints
/// This runs before handlers and checks rate limits based on IP
pub async fn rate_limit_auth_middleware(
    req: Request,
    next: Next,
) -> Response {
    // Extract IP from extensions (set by ip_extractor middleware)
    let ip = req
        .extensions()
        .get::<ClientIp>()
        .map(|c| c.0.clone())
        .unwrap_or_else(|| "unknown".to_string());

    // Check rate limit based on path
    let path = req.uri().path();
    
    // Only apply rate limiting to auth endpoints
    if !path.starts_with("/api/auth") {
        return next.run(req).await;
    }
    
    let rate_limiter = rate_limit_auth::AuthRateLimiter::new();
    
    let rate_limit_result = if path.contains("/login") {
        rate_limiter.check_login_rate_limit(&ip)
    } else if path.contains("/forgot-password") || path.contains("/reset-password") {
        rate_limiter.check_password_reset_rate_limit(&ip)
    } else if path.contains("/validate-reset-token") {
        rate_limiter.check_token_validation_rate_limit(&ip)
    } else if path.contains("/register") {
        rate_limiter.check_registration_rate_limit(&ip)
    } else {
        Ok(()) // No rate limiting for other endpoints
    };

    if let Err(msg) = rate_limit_result {
        // Log security event (async, don't block)
        let monitor = security_monitor::SecurityMonitor::new();
        monitor.record_rate_limit_exceeded(&ip, path);
        
        // Return rate limit error
        let error_response = HttpError::too_many_requests(msg);
        return error_response.into_response();
    }

    next.run(req).await
}

