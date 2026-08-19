use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// In-memory rate limiter for 2FA attempts per IP
// In production, use Redis for distributed rate limiting
type RateLimitStore = Arc<Mutex<HashMap<String, (u32, Instant)>>>;

static RATE_LIMIT_2FA: std::sync::OnceLock<RateLimitStore> = std::sync::OnceLock::new();

/// Check if IP is rate limited for 2FA attempts
/// Returns Ok(()) if allowed, Err(message) if rate limited
pub fn check_2fa_rate_limit(ip: &str) -> Result<(), String> {
    let store = RATE_LIMIT_2FA.get_or_init(|| Arc::new(Mutex::new(HashMap::new())));
    let mut store = store.lock().unwrap();
    let now = Instant::now();
    let window = Duration::from_secs(5 * 60); // 5 minutes
    let max_attempts = 3;

    // Clean up old entries
    store.retain(|_, (_, time)| now.duration_since(*time) < window);

    // Check rate limit
    let should_block = {
        let current = store.get(ip).cloned();
        match current {
            Some((count, first_request)) => {
                if now.duration_since(first_request) < window {
                    if count >= max_attempts {
                        true
                    } else {
                        // Increment count
                        store.insert(ip.to_string(), (count + 1, first_request));
                        false
                    }
                } else {
                    // Window expired, reset
                    store.insert(ip.to_string(), (1, now));
                    false
                }
            }
            None => {
                // First request
                store.insert(ip.to_string(), (1, now));
                false
            }
        }
    };

    if should_block {
        Err("Too many 2FA verification attempts. Please try again in 5 minutes.".to_string())
    } else {
        Ok(())
    }
}

/// Extract IP address from request headers
pub fn extract_ip(headers: &axum::http::HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|h| h.to_str().ok())
        .map(|s| {
            // Take first IP if comma-separated (proxy chain)
            s.split(',').next().unwrap_or(s).trim().to_string()
        })
        .unwrap_or_else(|| "unknown".to_string())
}

