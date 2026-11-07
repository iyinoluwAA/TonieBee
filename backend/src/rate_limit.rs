//! In-memory fixed-window rate limiter (from AJ's stalbet → Spectra).
//!
//! Changes from Spectra (port back):
//! - Expired windows are swept at most every [`SWEEP_EVERY`], not on every call: Spectra
//!   walked the whole map on each request, so a flood of requests from many addresses
//!   made every request slower (the limiter itself became the slow part).
//! - The map has a ceiling ([`MAX_KEYS`]). If it's full even after a sweep, a *new* key is
//!   refused (fail closed) rather than letting memory grow without bound; keys already
//!   being counted keep working.
//!
//! Limits reset when the server restarts. Anything that must survive a restart (the
//! daily cap on sign-in emails, attempts per code, account lockouts) is counted in the
//! database instead.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const SWEEP_EVERY: Duration = Duration::from_secs(30);
const MAX_KEYS: usize = 200_000;

#[derive(Debug, Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<Inner>>,
}

#[derive(Debug)]
struct Inner {
    entries: HashMap<String, RateWindow>,
    last_sweep: Instant,
}

#[derive(Debug, Clone, Copy)]
struct RateWindow {
    count: u32,
    started_at: Instant,
    window: Duration,
}

#[derive(Debug, Clone, Copy)]
pub struct RateLimitExceeded {
    pub retry_after_seconds: u64,
}

pub fn retry_after_text(seconds: u64) -> String {
    let minutes = seconds.div_ceil(60);
    if minutes <= 1 {
        "about 1 minute".to_string()
    } else {
        format!("about {minutes} minutes")
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                entries: HashMap::new(),
                last_sweep: Instant::now(),
            })),
        }
    }

    pub fn check(
        &self,
        key: &str,
        max_requests: u32,
        window: Duration,
    ) -> Result<(), RateLimitExceeded> {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());

        let full = inner.entries.len() >= MAX_KEYS && !inner.entries.contains_key(key);
        if now.duration_since(inner.last_sweep) >= SWEEP_EVERY || full {
            // Each window expires by its OWN length (stalbet used the caller's for all).
            inner
                .entries
                .retain(|_, entry| now.duration_since(entry.started_at) < entry.window);
            inner.last_sweep = now;
        }
        if inner.entries.len() >= MAX_KEYS && !inner.entries.contains_key(key) {
            tracing::warn!("rate limiter is full; refusing new visitors until windows expire");
            return Err(RateLimitExceeded {
                retry_after_seconds: SWEEP_EVERY.as_secs(),
            });
        }

        let entry = inner.entries.entry(key.to_string()).or_insert(RateWindow {
            count: 0,
            started_at: now,
            window,
        });
        if now.duration_since(entry.started_at) >= window {
            entry.count = 0;
            entry.started_at = now;
        }
        entry.window = window;

        if entry.count >= max_requests {
            let retry_after_seconds = window
                .saturating_sub(now.duration_since(entry.started_at))
                .as_secs()
                .max(1);
            return Err(RateLimitExceeded {
                retry_after_seconds,
            });
        }
        entry.count += 1;
        Ok(())
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().unwrap().entries.len()
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_requests_until_limit() {
        let limiter = RateLimiter::new();
        let window = Duration::from_secs(60);
        assert!(limiter.check("login:ip:127.0.0.1", 2, window).is_ok());
        assert!(limiter.check("login:ip:127.0.0.1", 2, window).is_ok());
        assert!(limiter.check("login:ip:127.0.0.1", 2, window).is_err());
    }

    #[test]
    fn a_short_limit_never_resets_a_long_one() {
        let limiter = RateLimiter::new();
        let long = Duration::from_secs(15 * 60);
        assert!(limiter.check("signin:email:a", 1, long).is_ok());
        std::thread::sleep(Duration::from_millis(20));
        assert!(limiter
            .check("other:key", 5, Duration::from_millis(1))
            .is_ok());
        assert!(limiter.check("signin:email:a", 1, long).is_err());
    }

    #[test]
    fn keys_are_isolated() {
        let limiter = RateLimiter::new();
        let window = Duration::from_secs(60);
        assert!(limiter.check("login:ip:one", 1, window).is_ok());
        assert!(limiter.check("login:ip:one", 1, window).is_err());
        assert!(limiter.check("login:ip:two", 1, window).is_ok());
    }

    #[test]
    fn an_expired_window_starts_again() {
        let limiter = RateLimiter::new();
        let tiny = Duration::from_millis(5);
        assert!(limiter.check("k", 1, tiny).is_ok());
        assert!(limiter.check("k", 1, tiny).is_err());
        std::thread::sleep(Duration::from_millis(10));
        assert!(limiter.check("k", 1, tiny).is_ok());
        assert_eq!(limiter.len(), 1);
    }
}
