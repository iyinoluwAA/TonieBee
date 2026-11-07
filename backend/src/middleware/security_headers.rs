//! Security headers on every response — different for the API and the website pages.
//!
//! Both: nosniff, no framing, Permissions-Policy, Cross-Origin-Resource-Policy, and
//! HSTS in production (Spectra had no HSTS; port back).
//! - API (`/api/…`): CSP `default-src 'none'` and `Cache-Control: no-store` (answers
//!   can hold personal information: never keep a copy anywhere).
//! - Website pages: a CSP that allows only this site's own scripts, styles, images and
//!   API (the same as index.html's meta tag, plus `frame-ancestors`, which only a header
//!   can set). Hashed files under `/assets/` are cached for a year; the page itself is
//!   always re-checked, so a new version shows at once. A preview says `noindex`.

use axum::{
    extract::{Request, State},
    http::HeaderValue,
    middleware::Next,
    response::Response,
};

use crate::state::AppState;

pub const SITE_CSP: &str =
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'self'; \
object-src 'none'; frame-ancestors 'none'";

pub async fn security_headers(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let path = req.uri().path().to_owned();
    let mut response = next.run(req).await;
    // Only real files are cached for a year (a 404 for a missing one isn't).
    let found = response.status().is_success();
    let headers = response.headers_mut();

    headers.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    headers.insert(
        "Permissions-Policy",
        HeaderValue::from_static("geolocation=(), microphone=(), camera=(), payment=(), usb=()"),
    );
    headers.insert(
        "Cross-Origin-Resource-Policy",
        HeaderValue::from_static("same-site"),
    );
    if state.config.is_production() {
        headers.insert(
            "Strict-Transport-Security",
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }

    if path == "/api" || path.starts_with("/api/") {
        headers.insert("Referrer-Policy", HeaderValue::from_static("no-referrer"));
        headers.insert(
            "Content-Security-Policy",
            HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'; base-uri 'none'"),
        );
        headers.insert("Cache-Control", HeaderValue::from_static("no-store"));
    } else {
        headers.insert(
            "Referrer-Policy",
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        );
        headers.insert(
            "Content-Security-Policy",
            HeaderValue::from_static(SITE_CSP),
        );
        headers.insert(
            "Cross-Origin-Opener-Policy",
            HeaderValue::from_static("same-origin"),
        );
        let cache = if path.starts_with("/assets/") && found {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        };
        headers.insert("Cache-Control", HeaderValue::from_static(cache));
        if state.config.site_preview || path.starts_with("/admin") || path.starts_with("/account") {
            headers.insert(
                "X-Robots-Tag",
                HeaderValue::from_static("noindex, nofollow"),
            );
        }
    }
    response
}
