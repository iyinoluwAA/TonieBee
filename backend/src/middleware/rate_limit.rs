use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// Simple in-memory rate limiter for development
// In production, use Redis or similar distributed store
type RateLimitStore = Arc<Mutex<HashMap<String, (u32, Instant)>>>;

// Simple rate limiter for auth endpoints (5 requests per 15 minutes per IP)
// TODO: Fix type issues with Axum 0.7 middleware before enabling
#[allow(dead_code)]
pub async fn rate_limit_auth(
    req: Request,
    next: Next,
) -> Response {
    // Extract IP from headers (simplified for now)
    let headers = req.headers();
    let ip: String = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Simple in-memory rate limiting (5 requests per 15 minutes)
    // In production, use Redis or similar distributed store
    static RATE_LIMIT: std::sync::OnceLock<RateLimitStore> = std::sync::OnceLock::new();
    let store = RATE_LIMIT.get_or_init(|| Arc::new(Mutex::new(HashMap::new())));

    let mut store = store.lock().unwrap();
    let now = Instant::now();
    let window = Duration::from_secs(15 * 60); // 15 minutes

    // Clean up old entries
    store.retain(|_, (_, time)| now.duration_since(*time) < window);

    // Check rate limit
    let should_block = {
        let current = store.get(&ip).cloned();
        match current {
            Some((count, first_request)) => {
                if now.duration_since(first_request) < window {
                    if count >= 5 {
                        true
                    } else {
                        // Increment count
                        store.insert(ip.clone(), (count + 1, first_request));
                        false
                    }
                } else {
                    // Window expired, reset
                    store.insert(ip.clone(), (1, now));
                    false
                }
            }
            None => {
                // First request
                store.insert(ip.clone(), (1, now));
                false
            }
        }
    };

    if should_block {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "status": "fail",
                "message": "Too many requests. Please try again in 15 minutes."
            })),
        ).into_response();
    }

    next.run(req).await
}

