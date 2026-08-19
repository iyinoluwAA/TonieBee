use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

type RateLimitStore = Arc<Mutex<HashMap<String, (u32, Instant, Instant)>>>; // (count, first_request, last_request)

/// Rate limiter for authentication endpoints (IP-based)
pub struct AuthRateLimiter {
    store: RateLimitStore,
}

impl AuthRateLimiter {
    pub fn new() -> Self {
        Self {
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Check rate limit for login attempts
    /// Returns Ok(()) if allowed, Err(message) if rate limited
    /// Limits: 5 attempts per 15 minutes per IP
    pub fn check_login_rate_limit(&self, ip: &str) -> Result<(), String> {
        self.check_rate_limit(ip, 5, Duration::from_secs(15 * 60), "login")
    }

    /// Check rate limit for password reset requests
    /// Limits: 3 requests per hour per IP
    pub fn check_password_reset_rate_limit(&self, ip: &str) -> Result<(), String> {
        self.check_rate_limit(ip, 3, Duration::from_secs(60 * 60), "password reset")
    }

    /// Check rate limit for token validation
    /// Limits: 10 requests per 15 minutes per IP
    pub fn check_token_validation_rate_limit(&self, ip: &str) -> Result<(), String> {
        self.check_rate_limit(ip, 10, Duration::from_secs(15 * 60), "token validation")
    }

    /// Check rate limit for registration
    /// Limits: 3 registrations per hour per IP
    pub fn check_registration_rate_limit(&self, ip: &str) -> Result<(), String> {
        self.check_rate_limit(ip, 3, Duration::from_secs(60 * 60), "registration")
    }

    /// Generic rate limit check
    fn check_rate_limit(
        &self,
        ip: &str,
        max_requests: u32,
        window: Duration,
        action: &str,
    ) -> Result<(), String> {
        let mut store = self.store.lock().unwrap();
        let now = Instant::now();

        // Clean up old entries (older than window)
        store.retain(|_, (_, first_request, _)| {
            now.duration_since(*first_request) < window
        });

        let key = ip.to_string();

        // Check rate limit
        let should_block = {
            let current = store.get(&key).cloned();
            match current {
                Some((count, first_request, _)) => {
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
            let remaining = window
                .as_secs()
                .saturating_sub(now.duration_since(store.get(&key).unwrap().1).as_secs());
            return Err(format!(
                "Rate limit exceeded for {}. Please try again in {} minutes.",
                action,
                (remaining / 60) + 1
            ));
        }

        // Update or create entry
        let entry = store.entry(key).or_insert_with(|| (0, now, now));
        entry.0 += 1;
        entry.2 = now; // Update last request time
        if entry.0 == 1 {
            entry.1 = now; // Set first request time
        }

        Ok(())
    }

    /// Get remaining attempts for an IP (for informational purposes)
    pub fn get_remaining_attempts(&self, ip: &str, max_requests: u32, window: Duration) -> u32 {
        let store = self.store.lock().unwrap();
        let now = Instant::now();

        if let Some((count, first_request, _)) = store.get(ip) {
            if now.duration_since(*first_request) < window {
                max_requests.saturating_sub(*count)
            } else {
                max_requests // Window expired
            }
        } else {
            max_requests
        }
    }
}

impl Default for AuthRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}



