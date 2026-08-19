use axum::{
    extract::Request,
    http::HeaderValue,
    middleware::Next,
    response::Response,
};

/// Security headers middleware to protect against common attacks
pub async fn security_headers_middleware(
    req: Request,
    next: Next,
) -> Response {
    let mut response = next.run(req).await;

    let headers = response.headers_mut();

    // Content Security Policy - prevent XSS attacks
    // In production, adjust these policies based on your needs
    let csp = if std::env::var("RUST_ENV").unwrap_or_else(|_| "development".into()) == "production" {
        "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' https://oauth2.googleapis.com https://github.com https://api.github.com; frame-ancestors 'none';"
    } else {
        // More relaxed for development
        "default-src 'self' 'unsafe-inline' 'unsafe-eval'; connect-src 'self' http://localhost:* https://oauth2.googleapis.com https://github.com https://api.github.com;"
    };
    if let Ok(csp_header) = HeaderValue::from_str(csp) {
        headers.insert("Content-Security-Policy", csp_header);
    }

    // Strict Transport Security - force HTTPS in production
    if std::env::var("RUST_ENV").unwrap_or_else(|_| "development".into()) == "production" {
        headers.insert(
            "Strict-Transport-Security",
            HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
        );
    }

    // Prevent clickjacking
    headers.insert(
        "X-Frame-Options",
        HeaderValue::from_static("DENY"),
    );

    // Prevent MIME type sniffing
    headers.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );

    // Enable XSS protection (legacy browsers)
    headers.insert(
        "X-XSS-Protection",
        HeaderValue::from_static("1; mode=block"),
    );

    // Referrer Policy - control referrer information
    headers.insert(
        "Referrer-Policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );

    // Permissions Policy - restrict browser features
    headers.insert(
        "Permissions-Policy",
        HeaderValue::from_static("geolocation=(), microphone=(), camera=()"),
    );

    // Remove server information
    headers.remove("server");
    headers.remove("x-powered-by");

    response
}
