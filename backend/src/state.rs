use std::{sync::Arc, time::Instant};

use sqlx::PgPool;

use crate::{config::Config, mail::Mailer, rate_limit::RateLimiter};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: PgPool,
    pub mailer: Mailer,
    pub rate_limiter: Arc<RateLimiter>,
    pub started_at: Instant,
}

impl AppState {
    pub fn new(config: Config, db: PgPool, mailer: Mailer) -> Self {
        Self {
            config: Arc::new(config),
            db,
            mailer,
            rate_limiter: Arc::new(RateLimiter::new()),
            started_at: Instant::now(),
        }
    }
}
