//! Client sign-in — no passwords, like Claude's:
//!
//! 1. `POST /auth/email/start {email}` → emails a "Sign in" link, and gives the asking
//!    browser a cookie that marks it as "the browser that asked".
//! 2. The link opens the website's `/sign-in/link#token` page, which calls
//!    `POST /auth/email/link {token}`:
//!    - same browser → signed in, nothing to type;
//!    - another device → shows the 6-digit code to type where you started, AND which
//!      device asked and when, with a "This wasn't me" button (`/auth/email/deny`).
//! 3. `POST /auth/email/verify {email, code}` → signed in — only in the browser that
//!    asked (it holds the marker cookie).
//!
//! The reply to step 1 is identical whether or not the email has an account, so
//! nobody can probe who is a client. The first successful sign-in creates the account.
//!
//! Tightened over Spectra (port back):
//! - The code only works in the browser that asked. In Spectra anyone who knew the
//!   email could type guesses, burning the real person's 5 tries (or guessing
//!   alongside their genuine request).
//! - Opening the link elsewhere shows who asked ("Chrome on Windows, 10:42") with a way
//!   to cancel — so someone phoned by a scammer ("read me the code we sent you")
//!   can see the request isn't theirs.

use std::time::Duration;

use axum::{extract::State, Json};
use axum_extra::extract::cookie::CookieJar;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use super::{
    devices, emails, limit, normalize_email,
    session::{self, DeviceLabel},
};
use crate::{
    audit,
    client_ip::{rate_key, ClientIp},
    crypto,
    error::{AppError, AppResult},
    state::AppState,
};

pub const BROWSER_COOKIE: &str = "toniebee_signin";
const BROWSER_COOKIE_PATH: &str = "/api/auth";
pub const MAX_TRIES: i32 = 5;
const MAX_EMAILS_PER_DAY: i64 = 10;
const FIFTEEN_MINUTES: Duration = Duration::from_secs(15 * 60);

const WRONG_OR_EXPIRED: &str = "That code is wrong or has expired.";
const TOO_MANY_TRIES: &str = "Too many wrong tries for this code. Request a new one.";
const LINK_EXPIRED: &str = "This sign-in link has expired or was already used. Request a new one.";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartBody {
    email: String,
}

pub async fn start(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    device: DeviceLabel,
    jar: CookieJar,
    Json(body): Json<StartBody>,
) -> AppResult<(CookieJar, Json<Value>)> {
    limit(
        &state,
        &format!("signin-start:ip:{}", rate_key(&ip)),
        10,
        FIFTEEN_MINUTES,
    )?;
    let email = normalize_email(&body.email)
        .ok_or_else(|| AppError::BadRequest("Enter a valid email address.".into()))?;

    // The per-address caps protect an inbox from strangers. The address owner's own
    // known browser skips them, so strangers can't use them up either.
    if !devices::recognise_by_email(&state.db, &jar, &email).await? {
        limit(
            &state,
            &format!("signin-start:email:{email}"),
            3,
            FIFTEEN_MINUTES,
        )?;
        let sent_today: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM sign_in_codes
             WHERE email = $1 AND created_at > now() - interval '1 day'",
        )
        .bind(&email)
        .fetch_one(&state.db)
        .await?;
        if sent_today >= MAX_EMAILS_PER_DAY {
            return Err(AppError::TooManyRequests(
                "Too many sign-in emails for this address today. Try again tomorrow.".into(),
            ));
        }
    }

    let browser_token = crypto::random_token();
    let role: Option<String> = sqlx::query_scalar("SELECT role FROM users WHERE email = $1")
        .bind(&email)
        .fetch_optional(&state.db)
        .await?;
    let is_admin = role.as_deref() == Some("admin");

    // Every address gets a row — admins too, with a code nobody can know — so tries,
    // the 5-try limit and the daily cap behave identically for all of them: nothing
    // here reveals which addresses are admins.
    let id = Uuid::new_v4();
    let link_token = crypto::random_token();
    let stored_code_hash = if is_admin {
        crypto::sha256(crypto::random_token().as_bytes())
    } else {
        code_hash(&state, id, &derive_code(&state, &link_token))
    };

    let mut tx = state.db.begin().await?;
    // Only the newest request works.
    sqlx::query(
        "UPDATE sign_in_codes SET closed_at = now() WHERE email = $1 AND closed_at IS NULL",
    )
    .bind(&email)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO sign_in_codes
             (id, email, code_hash, link_token_hash, browser_hash, device_label, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, now() + $7::interval)",
    )
    .bind(id)
    .bind(&email)
    .bind(stored_code_hash)
    .bind(crypto::sha256(link_token.as_bytes()))
    .bind(crypto::sha256(browser_token.as_bytes()))
    .bind(&device.0)
    .bind(format!("{} minutes", emails::LINK_MINUTES))
    .execute(&mut *tx)
    .await?;
    if is_admin {
        audit::record(
            &mut *tx,
            None,
            "admin.client_sign_in_attempt",
            json!({ "email": email }),
            Some(&ip),
        )
        .await?;
    }
    tx.commit().await?;

    // Admins never get a code-only sign-in: their email says where to sign in instead.
    let email_out = if is_admin {
        emails::admin_redirect(&state.config, &email)
    } else {
        emails::sign_in(&state.config, &email, &link_token)
    };
    state.mailer.send(email_out).await?;

    let marker = session::cookie(
        &state.config,
        BROWSER_COOKIE,
        BROWSER_COOKIE_PATH,
        browser_token,
        time::Duration::minutes(emails::LINK_MINUTES + 5),
    );
    Ok((jar.add(marker), Json(json!({ "status": "sent" }))))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkBody {
    token: String,
}

type OpenRequest = (Uuid, String, Vec<u8>, i32, String, DateTime<Utc>);

async fn find_by_link(state: &AppState, token: &str) -> AppResult<Option<OpenRequest>> {
    if !crypto::is_token_shaped(token) {
        return Ok(None);
    }
    Ok(sqlx::query_as(
        "SELECT id, email, browser_hash, attempts, device_label, created_at FROM sign_in_codes
         WHERE link_token_hash = $1 AND closed_at IS NULL AND expires_at > now()",
    )
    .bind(crypto::sha256(token.as_bytes()))
    .fetch_optional(&state.db)
    .await?)
}

fn is_asking_browser(jar: &CookieJar, browser_hash: &[u8]) -> bool {
    jar.get(BROWSER_COOKIE).is_some_and(|marker| {
        crypto::is_token_shaped(marker.value())
            && crypto::constant_time_eq(&crypto::sha256(marker.value().as_bytes()), browser_hash)
    })
}

pub async fn open_link(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    device: DeviceLabel,
    jar: CookieJar,
    Json(body): Json<LinkBody>,
) -> AppResult<(CookieJar, Json<Value>)> {
    limit(
        &state,
        &format!("signin-link:ip:{}", rate_key(&ip)),
        30,
        FIFTEEN_MINUTES,
    )?;
    let expired = || AppError::BadRequest(LINK_EXPIRED.into());
    let token = body.token.trim();
    let (id, email, browser_hash, attempts, asked_from, asked_at) =
        find_by_link(&state, token).await?.ok_or_else(expired)?;

    if !is_asking_browser(&jar, &browser_hash) {
        if attempts >= MAX_TRIES {
            return Err(AppError::TooManyRequests(TOO_MANY_TRIES.into()));
        }
        let code = derive_code(&state, token);
        return Ok((
            jar,
            Json(json!({
                "status": "showCode",
                "code": code,
                "requestedFrom": asked_from,
                "requestedAt": asked_at,
            })),
        ));
    }

    if !close(&state, id, false).await? {
        return Err(expired());
    }
    finish(&state, jar, &email, &device).await
}

/// "This wasn't me": the link's holder cancels the request, so its code stops working.
pub async fn deny(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Json(body): Json<LinkBody>,
) -> AppResult<Json<Value>> {
    limit(
        &state,
        &format!("signin-link:ip:{}", rate_key(&ip)),
        30,
        FIFTEEN_MINUTES,
    )?;
    if let Some((id, ..)) = find_by_link(&state, body.token.trim()).await? {
        close(&state, id, true).await?;
    }
    // The same answer either way: the link no longer works.
    Ok(Json(json!({ "status": "cancelled" })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyBody {
    email: String,
    code: String,
}

pub async fn verify(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    device: DeviceLabel,
    jar: CookieJar,
    Json(body): Json<VerifyBody>,
) -> AppResult<(CookieJar, Json<Value>)> {
    limit(
        &state,
        &format!("signin-verify:ip:{}", rate_key(&ip)),
        30,
        FIFTEEN_MINUTES,
    )?;
    let wrong = || AppError::BadRequest(WRONG_OR_EXPIRED.into());
    let email = normalize_email(&body.email).ok_or_else(wrong)?;
    let code: String = body.code.chars().filter(|c| !c.is_whitespace()).collect();
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(wrong());
    }

    let row: Option<(Uuid, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT id, code_hash, browser_hash FROM sign_in_codes
         WHERE email = $1 AND closed_at IS NULL AND expires_at > now()
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(&email)
    .fetch_optional(&state.db)
    .await?;
    let (id, stored, browser_hash) = row.ok_or_else(wrong)?;

    // Only where the sign-in started. A stranger's guesses aren't even counted, so
    // they can't use up the real person's tries.
    if !is_asking_browser(&jar, &browser_hash) {
        return Err(AppError::BadRequest(
            "Type the code in the browser where you asked for the email. (Or open the link \
             from the email here to sign in directly.)"
                .into(),
        ));
    }

    // Count the try before checking it, atomically, so parallel guesses can't exceed 5.
    let tries: Option<i32> = sqlx::query_scalar(
        "UPDATE sign_in_codes SET attempts = attempts + 1
         WHERE id = $1 AND attempts < $2
         RETURNING attempts",
    )
    .bind(id)
    .bind(MAX_TRIES)
    .fetch_optional(&state.db)
    .await?;
    let Some(tries) = tries else {
        return Err(AppError::TooManyRequests(TOO_MANY_TRIES.into()));
    };

    if !crypto::constant_time_eq(&code_hash(&state, id, &code), &stored) {
        return Err(if tries >= MAX_TRIES {
            AppError::TooManyRequests(TOO_MANY_TRIES.into())
        } else {
            wrong()
        });
    }
    if !close(&state, id, false).await? {
        return Err(wrong());
    }
    finish(&state, jar, &email, &device).await
}

/// Marks a request used (or denied). `false` if something else closed it first.
async fn close(state: &AppState, id: Uuid, denied: bool) -> AppResult<bool> {
    let done = sqlx::query(
        "UPDATE sign_in_codes SET closed_at = now(), denied = $2
         WHERE id = $1 AND closed_at IS NULL",
    )
    .bind(id)
    .bind(denied)
    .execute(&state.db)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// Creates the account on first sign-in, then the session.
async fn finish(
    state: &AppState,
    jar: CookieJar,
    email: &str,
    device: &DeviceLabel,
) -> AppResult<(CookieJar, Json<Value>)> {
    let user_id: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO users (email, last_sign_in_at) VALUES ($1, now())
         ON CONFLICT (email) DO UPDATE SET last_sign_in_at = now()
             WHERE users.role = 'customer'
         RETURNING id",
    )
    .bind(email)
    .fetch_optional(&state.db)
    .await?;
    let user_id = user_id.ok_or_else(|| AppError::Forbidden("Admins sign in at /admin.".into()))?;

    // Signing in again in the same browser replaces its old session.
    session::end(&state.db, &jar).await?;
    let session_cookie = session::start(&state.db, &state.config, user_id, false, device).await?;
    let device_cookie = devices::remember(&state.db, &state.config, &jar, user_id).await?;
    let used_marker = session::cookie(
        &state.config,
        BROWSER_COOKIE,
        BROWSER_COOKIE_PATH,
        String::new(),
        time::Duration::ZERO,
    );
    Ok((
        jar.add(session_cookie).add(device_cookie).add(used_marker),
        Json(json!({
            "status": "signedIn",
            "user": { "email": email, "role": "customer" },
        })),
    ))
}

/// The 6-digit code is derived from the link token, so only someone holding the
/// email's link can see it — the database stores neither.
fn derive_code(state: &AppState, link_token: &str) -> String {
    let mac = crypto::hmac_sha256(
        state.config.auth_secret.expose(),
        &[b"sign-in-code", link_token.as_bytes()],
    );
    let number = u32::from_be_bytes([mac[0], mac[1], mac[2], mac[3]]) % 1_000_000;
    format!("{number:06}")
}

fn code_hash(state: &AppState, id: Uuid, code: &str) -> Vec<u8> {
    crypto::hmac_sha256(
        state.config.auth_secret.expose(),
        &[b"sign-in-code-hash", id.as_bytes(), code.as_bytes()],
    )
}
