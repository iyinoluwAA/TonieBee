// src/middleware/csrf.rs
use axum::http::HeaderMap;
use axum_extra::extract::cookie::CookieJar;

/// Return true if `X-CSRF-Token` header equals `csrf_token` cookie.
pub fn verify_csrf(headers: &HeaderMap, jar: &CookieJar) -> bool {
    let header_token = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let cookie_token = jar.get("csrf_token").map(|c| c.value().to_string());

    header_token.is_some() && cookie_token.is_some() && header_token == cookie_token
}
