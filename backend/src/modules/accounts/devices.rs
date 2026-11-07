//! Known devices ("smart lockout", like Microsoft's).
//!
//! After a successful sign-in, the browser gets a long-lived random cookie
//! (`toniebee_device`); the database keeps only its SHA-256, one row per
//! (browser, account). It changes two things:
//! - Admin lockout: wrong guesses from unknown devices lock only unknown
//!   devices, so strangers can't lock the owner out of her own phone. A known
//!   device's own wrong guesses lock only that device.
//! - Client sign-in: the client's own known browser skips the per-address
//!   email caps, so a stranger can't use them up.
//!
//! An attacker can't have someone else's device cookie (256 random bits,
//! HttpOnly). "Sign out everywhere" and `create-admin` forget all of an
//! account's devices.

use axum_extra::extract::cookie::{Cookie, CookieJar};
use sqlx::PgExecutor;
use uuid::Uuid;

use super::session;
use crate::{config::Config, crypto, error::AppResult};

pub const COOKIE: &str = "toniebee_device";
const COOKIE_PATH: &str = "/api";
const COOKIE_DAYS: i64 = 365;
/// Devices unused this long are forgotten by the hourly cleanup.
pub const FORGET_AFTER_DAYS: i64 = 400;

fn token(jar: &CookieJar) -> Option<String> {
    jar.get(COOKIE)
        .map(|c| c.value().to_string())
        .filter(|t| crypto::is_token_shaped(t))
}

/// The device's id if this browser has signed in to `user_id` before.
pub async fn recognise<'e>(
    db: impl PgExecutor<'e>,
    jar: &CookieJar,
    user_id: Uuid,
) -> AppResult<Option<Uuid>> {
    let Some(token) = token(jar) else {
        return Ok(None);
    };
    Ok(
        sqlx::query_scalar("SELECT id FROM known_devices WHERE token_hash = $1 AND user_id = $2")
            .bind(crypto::sha256(token.as_bytes()))
            .bind(user_id)
            .fetch_optional(db)
            .await?,
    )
}

/// Whether this browser has signed in to the account with this email before.
pub async fn recognise_by_email<'e>(
    db: impl PgExecutor<'e>,
    jar: &CookieJar,
    email: &str,
) -> AppResult<bool> {
    let Some(token) = token(jar) else {
        return Ok(false);
    };
    let found: Option<Uuid> = sqlx::query_scalar(
        "SELECT d.id FROM known_devices d JOIN users u ON u.id = d.user_id
         WHERE d.token_hash = $1 AND u.email = $2",
    )
    .bind(crypto::sha256(token.as_bytes()))
    .bind(email)
    .fetch_optional(db)
    .await?;
    Ok(found.is_some())
}

/// Remembers this browser for `user_id` after a successful sign-in (clearing the
/// device's own failure count) and returns the cookie to (re)set.
pub async fn remember<'e>(
    db: impl PgExecutor<'e>,
    config: &Config,
    jar: &CookieJar,
    user_id: Uuid,
) -> AppResult<Cookie<'static>> {
    let token = token(jar).unwrap_or_else(crypto::random_token);
    sqlx::query(
        "INSERT INTO known_devices (user_id, token_hash) VALUES ($1, $2)
         ON CONFLICT (token_hash, user_id) DO UPDATE
             SET last_used_at = now(), failed_sign_ins = 0, locked_until = NULL",
    )
    .bind(user_id)
    .bind(crypto::sha256(token.as_bytes()))
    .execute(db)
    .await?;
    Ok(session::cookie(
        config,
        COOKIE,
        COOKIE_PATH,
        token,
        time::Duration::days(COOKIE_DAYS),
    ))
}

/// Forgets every device of an account (sign out everywhere, admin reset).
pub async fn forget_all<'e>(db: impl PgExecutor<'e>, user_id: Uuid) -> AppResult<u64> {
    Ok(sqlx::query("DELETE FROM known_devices WHERE user_id = $1")
        .bind(user_id)
        .execute(db)
        .await?
        .rows_affected())
}

pub fn clear_cookie(config: &Config) -> Cookie<'static> {
    session::cookie(
        config,
        COOKIE,
        COOKIE_PATH,
        String::new(),
        time::Duration::ZERO,
    )
}
