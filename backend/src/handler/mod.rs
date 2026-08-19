pub mod auth;
pub mod auth_refresh;
pub mod health;
pub mod metrics;
pub mod oauth;
pub mod ping;
pub mod quotes;
pub mod sessions;
pub mod two_factor;
pub mod users;
pub mod policies;
pub mod appointments;
pub mod documents;
pub mod payments;
pub mod claims;
pub mod security;
// pub mod recovery_warnings; // TODO: Axum 0.7 handler compatibility issue - handler with only Extension doesn't compile
