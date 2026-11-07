//! Cross-site request forgery guard. Any request that changes something
//! (POST/PUT/PATCH/DELETE) must come from the real website. Browsers always send
//! `Origin` on those, and a forged form on another site can't fake it. Works alongside
//! the SameSite cookies and JSON-only bodies (a form post from another site can't send
//! `Content-Type: application/json` without a CORS preflight, which is refused).

use axum::{
    extract::{Request, State},
    http::{header, Method},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::{error::AppError, state::AppState};

pub async fn require_site_origin(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    if matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) {
        return next.run(req).await;
    }
    let allowed = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|origin| state.config.is_site_origin(origin));
    if !allowed {
        return AppError::Forbidden("Request blocked: it didn't come from the website.".into())
            .into_response();
    }
    let json = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
        });
    let has_body = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|len| len != "0")
        || req.headers().contains_key(header::TRANSFER_ENCODING);
    if has_body && !json {
        return AppError::BadRequest("Send JSON (Content-Type: application/json).".into())
            .into_response();
    }
    next.run(req).await
}
