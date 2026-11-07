//! Signed-in sessions: a random token in an HttpOnly cookie (page scripts can't read
//! it), only its SHA-256 in the database. Replaces the old TonieBee JWTs, which
//! couldn't be revoked and whose cookie outlived the token (60 hours vs 60 minutes).
//!
//! Lifetimes (OWASP ASVS 5.0, V7.3):
//! - clients: 30 days idle, 90 days at most;
//! - admins: [`ADMIN_IDLE_MINUTES`] without activity, and [`ADMIN_HOURS`] at most —
//!   then password + authenticator again. (Spectra had no idle limit for admins: a
//!   phone left unlocked kept the dashboard open for 8 hours. Port back.)

use axum::{async_trait, extract::FromRequestParts, http::request::Parts};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{FromRow, PgExecutor, PgPool};
use uuid::Uuid;

use crate::{
    config::Config,
    crypto,
    error::{AppError, AppResult},
    state::AppState,
};

pub const COOKIE: &str = "toniebee_session";
const COOKIE_PATH: &str = "/api";

const CUSTOMER_IDLE_DAYS: i64 = 30;
const CUSTOMER_MAX_DAYS: i64 = 90;
pub const ADMIN_HOURS: i64 = 8;
pub const ADMIN_IDLE_MINUTES: i64 = 60;

#[derive(Debug, Clone, FromRow)]
pub struct SessionUser {
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub email: String,
    pub role: String,
    pub name: Option<String>,
    pub member_since: DateTime<Utc>,
    pub is_admin_session: bool,
    last_seen_at: DateTime<Utc>,
}

/// Starts a session and returns the cookie to set.
pub async fn start<'e>(
    db: impl PgExecutor<'e>,
    config: &Config,
    user_id: Uuid,
    is_admin: bool,
    device: &DeviceLabel,
) -> AppResult<Cookie<'static>> {
    let token = crypto::random_token();
    let lifetime = if is_admin {
        format!("{ADMIN_HOURS} hours")
    } else {
        format!("{CUSTOMER_IDLE_DAYS} days")
    };
    sqlx::query(
        "INSERT INTO sessions (token_hash, user_id, is_admin, expires_at, device_label)
         VALUES ($1, $2, $3, now() + $4::interval, $5)",
    )
    .bind(crypto::sha256(token.as_bytes()))
    .bind(user_id)
    .bind(is_admin)
    .bind(lifetime)
    .bind(&device.0)
    .execute(db)
    .await?;

    let max_age = if is_admin {
        time::Duration::hours(ADMIN_HOURS)
    } else {
        time::Duration::days(CUSTOMER_MAX_DAYS)
    };
    Ok(cookie(config, COOKIE, COOKIE_PATH, token, max_age))
}

/// Signs out the browser holding `jar`'s session cookie (if any).
pub async fn end<'e>(db: impl PgExecutor<'e>, jar: &CookieJar) -> AppResult<()> {
    if let Some(token) = jar.get(COOKIE).map(|c| c.value().to_string()) {
        sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
            .bind(crypto::sha256(token.as_bytes()))
            .execute(db)
            .await?;
    }
    Ok(())
}

#[derive(Debug, Serialize, FromRow)]
#[serde(rename_all = "camelCase")]
pub struct SessionInfo {
    pub id: Uuid,
    #[sqlx(rename = "device_label")]
    pub device: String,
    pub signed_in_at: DateTime<Utc>,
    pub last_active_at: DateTime<Utc>,
    pub admin: bool,
    pub current: bool,
}

/// "Where you're signed in": every live session of the account, newest activity first.
pub async fn list(db: &PgPool, user_id: Uuid, current: Uuid) -> AppResult<Vec<SessionInfo>> {
    Ok(sqlx::query_as(
        "SELECT id, device_label, created_at AS signed_in_at, last_seen_at AS last_active_at,
                is_admin AS admin, id = $2 AS current
         FROM sessions
         WHERE user_id = $1 AND expires_at > now()
           AND (NOT is_admin OR last_seen_at > now() - make_interval(mins => $3))
         ORDER BY (id = $2) DESC, last_seen_at DESC",
    )
    .bind(user_id)
    .bind(current)
    .bind(ADMIN_IDLE_MINUTES as i32)
    .fetch_all(db)
    .await?)
}

/// Signs out one of the account's sessions. `false` if it isn't theirs (or is gone).
pub async fn end_one(db: &PgPool, user_id: Uuid, session_id: Uuid) -> AppResult<bool> {
    let done = sqlx::query("DELETE FROM sessions WHERE id = $1 AND user_id = $2")
        .bind(session_id)
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(done.rows_affected() == 1)
}

/// Signs out every browser of the account except `keep` (after a password or
/// authenticator change: a lost phone's session ends, this one carries on).
pub async fn end_others<'e>(db: impl PgExecutor<'e>, user_id: Uuid, keep: Uuid) -> AppResult<u64> {
    let done = sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND id <> $2")
        .bind(user_id)
        .bind(keep)
        .execute(db)
        .await?;
    Ok(done.rows_affected())
}

pub async fn end_all(db: &PgPool, user_id: Uuid) -> AppResult<u64> {
    let done = sqlx::query("DELETE FROM sessions WHERE user_id = $1")
        .bind(user_id)
        .execute(db)
        .await?;
    Ok(done.rows_affected())
}

pub fn clear_cookie(config: &Config) -> Cookie<'static> {
    cookie(
        config,
        COOKIE,
        COOKIE_PATH,
        String::new(),
        time::Duration::ZERO,
    )
}

/// Every cookie the API sets: HttpOnly, SameSite=Lax, Secure in production.
pub fn cookie(
    config: &Config,
    name: &'static str,
    path: &'static str,
    value: String,
    max_age: time::Duration,
) -> Cookie<'static> {
    Cookie::build((name, value))
        .path(path)
        .http_only(true)
        .secure(config.is_production())
        .same_site(SameSite::Lax)
        .max_age(max_age)
        .build()
}

/// A signed-in visitor (client or admin). Rejects with 401 otherwise.
pub struct CurrentUser(pub SessionUser);

#[async_trait]
impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AppError> {
        let jar = CookieJar::from_headers(&parts.headers);
        let token = jar
            .get(COOKIE)
            .map(|c| c.value().to_string())
            .filter(|token| crypto::is_token_shaped(token))
            .ok_or_else(not_signed_in)?;

        let user: SessionUser = sqlx::query_as(
            "SELECT s.id AS session_id, s.user_id, u.email, u.role, u.name,
                    u.created_at AS member_since, s.is_admin AS is_admin_session, s.last_seen_at
             FROM sessions s
             JOIN users u ON u.id = s.user_id
             WHERE s.token_hash = $1 AND s.expires_at > now()",
        )
        .bind(crypto::sha256(token.as_bytes()))
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(not_signed_in)?;

        let idle = Utc::now() - user.last_seen_at;
        if user.is_admin_session {
            if idle > chrono::Duration::minutes(ADMIN_IDLE_MINUTES) {
                sqlx::query("DELETE FROM sessions WHERE id = $1")
                    .bind(user.session_id)
                    .execute(&state.db)
                    .await?;
                return Err(AppError::Unauthorized(format!(
                    "You were signed out after {ADMIN_IDLE_MINUTES} minutes without activity. Sign in again."
                )));
            }
            // Keep an active admin's idle clock fresh (at most one write a minute).
            if idle > chrono::Duration::minutes(1) {
                sqlx::query("UPDATE sessions SET last_seen_at = now() WHERE id = $1")
                    .bind(user.session_id)
                    .execute(&state.db)
                    .await?;
            }
        } else if idle > chrono::Duration::hours(1) {
            // Slide a client's idle window forward, at most once an hour.
            sqlx::query(
                "UPDATE sessions
                 SET last_seen_at = now(),
                     expires_at = LEAST(now() + $2::interval, created_at + $3::interval)
                 WHERE id = $1",
            )
            .bind(user.session_id)
            .bind(format!("{CUSTOMER_IDLE_DAYS} days"))
            .bind(format!("{CUSTOMER_MAX_DAYS} days"))
            .execute(&state.db)
            .await?;
        }
        Ok(CurrentUser(user))
    }
}

/// The signed-in visitor if there is one — for pages that work either way (the
/// consultation form links a request to the account when the visitor is signed in).
pub struct MaybeUser(pub Option<SessionUser>);

#[async_trait]
impl FromRequestParts<AppState> for MaybeUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AppError> {
        match CurrentUser::from_request_parts(parts, state).await {
            Ok(CurrentUser(user)) => Ok(MaybeUser(Some(user))),
            Err(AppError::Unauthorized(_)) => Ok(MaybeUser(None)),
            Err(other) => Err(other),
        }
    }
}

/// An admin signed in through the admin sign-in (password + authenticator).
/// A client session never qualifies — even if that person is later made an admin.
pub struct AdminUser(pub SessionUser);

#[async_trait]
impl FromRequestParts<AppState> for AdminUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AppError> {
        let CurrentUser(user) = CurrentUser::from_request_parts(parts, state).await?;
        if user.role != "admin" || !user.is_admin_session {
            return Err(AppError::Forbidden("Admins only.".into()));
        }
        Ok(AdminUser(user))
    }
}

/// A short name for the browser making the request, e.g. "Chrome on Windows",
/// shown in "where you're signed in". Only this summary is ever stored.
pub struct DeviceLabel(pub String);

#[async_trait]
impl<S: Send + Sync> FromRequestParts<S> for DeviceLabel {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let user_agent = parts
            .headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        Ok(DeviceLabel(describe(user_agent)))
    }
}

pub fn describe(user_agent: &str) -> String {
    let has = |needle: &str| user_agent.contains(needle);
    let browser = if has("Edg/") || has("EdgA/") || has("EdgiOS/") {
        "Edge"
    } else if has("OPR/") || has("Opera") {
        "Opera"
    } else if has("SamsungBrowser/") {
        "Samsung Internet"
    } else if has("Firefox/") || has("FxiOS/") {
        "Firefox"
    } else if has("CriOS/") || has("Chrome/") {
        "Chrome"
    } else if has("Safari/") {
        "Safari"
    } else {
        ""
    };
    // Order matters: iPhones say "like Mac OS X", Android says "Linux".
    let system = if has("Windows") {
        "Windows"
    } else if has("iPhone") {
        "iPhone"
    } else if has("iPad") {
        "iPad"
    } else if has("Android") {
        "Android"
    } else if has("CrOS") {
        "Chromebook"
    } else if has("Mac OS X") || has("Macintosh") {
        "Mac"
    } else if has("Linux") {
        "Linux"
    } else {
        ""
    };
    match (browser, system) {
        ("", "") => "Unknown device".into(),
        (browser, "") => browser.into(),
        ("", system) => format!("Browser on {system}"),
        (browser, system) => format!("{browser} on {system}"),
    }
}

fn not_signed_in() -> AppError {
    AppError::Unauthorized("You're not signed in.".into())
}

#[cfg(test)]
mod tests {
    use super::describe;

    #[test]
    fn devices_get_short_readable_names() {
        let cases = [
            ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36", "Chrome on Windows"),
            ("Mozilla/5.0 (Linux; Android 14; SM-F946B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/27.0 Chrome/125.0.0.0 Mobile Safari/537.36", "Samsung Internet on Android"),
            ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1", "Safari on iPhone"),
            ("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15", "Safari on Mac"),
            ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36 Edg/154.0.0.0", "Edge on Windows"),
            ("Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0", "Firefox on Linux"),
            ("", "Unknown device"),
            ("curl/8.5.0", "Unknown device"),
        ];
        for (ua, expected) in cases {
            assert_eq!(describe(ua), expected, "{ua}");
        }
    }
}
