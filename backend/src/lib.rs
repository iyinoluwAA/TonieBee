//! TonieBee website API.
//!
//! The security design started from AJ's Spectra API (its accounts were reviewed line by
//! line and tested over HTTP) and was tightened further here — see `backend/README.md`
//! → "Security" for what's different and why.

pub mod audit;
pub mod cleanup;
pub mod cli;
pub mod client_ip;
pub mod config;
pub mod crypto;
pub mod db;
pub mod error;
pub mod mail;
pub mod middleware;
pub mod modules;
pub mod rate_limit;
pub mod routes;
pub mod state;

pub use routes::router;

/// Database migrations, embedded at compile time from `backend/migrations`.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
