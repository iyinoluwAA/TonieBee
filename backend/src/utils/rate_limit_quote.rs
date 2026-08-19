use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

type RateLimitStore = Arc<Mutex<HashMap<String, (u32, Instant)>>>;

/// Rate limiter for quote submissions (3 quotes per hour per user)
pub struct QuoteRateLimiter {
    store: RateLimitStore,
}

impl QuoteRateLimiter {
    pub fn new() -> Self {
        Self {
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Check if user can submit a quote
    /// Returns Ok(()) if allowed, Err(message) if rate limited
    pub fn check_rate_limit(&self, user_id: &uuid::Uuid) -> Result<(), String> {
        let mut store = self.store.lock().unwrap();
        let now = Instant::now();
        let window = Duration::from_secs(60 * 60); // 1 hour
        let max_requests = 3;

        let key = user_id.to_string();
        
        // Clean up old entries
        store.retain(|_, (_, time)| now.duration_since(*time) < window);

        // Check rate limit
        let should_block = {
            let current = store.get(&key).cloned();
            match current {
                Some((count, first_request)) => {
                    if now.duration_since(first_request) < window {
                        count >= max_requests
                    } else {
                        false // Window expired, reset
                    }
                }
                None => false,
            }
        };

        if should_block {
            return Err("Rate limit exceeded. Please wait before submitting another quote request.".to_string());
        }

        // Update or create entry
        let entry = store.entry(key).or_insert_with(|| (0, now));
        entry.0 += 1;
        if entry.0 == 1 {
            entry.1 = now; // Set first request time
        }

        Ok(())
    }
}

impl Default for QuoteRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

